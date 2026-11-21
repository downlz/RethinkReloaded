//go:build oracle

// Copyright (c) 2026 RethinkReloaded contributors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// RethinkReloaded oracle for the DNS gateway (ALG): seeded random sequences of registrations (as dnsgateway.q
// makes them), translate/split toggles, transport stops and X / PTR / RDNSBL / resolv lookups, recorded as
// alg.tsv (op \t args \t result \t err). Address lists are recorded sorted: their order only feeds dialing,
// which shuffles them anyway.
package dnsx

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	x "github.com/celzero/firestack/intra/backend"
)

func pick[T any](g *rand.Rand, xs []T) T { return xs[g.IntN(len(xs))] }

type oracleRdns struct{ RdnsResolver }

func (oracleRdns) IsDnsAddr(netip.Addr) bool { return false }

type oracle64 struct{ NatPt }

func (oracle64) X64(string, netip.Addr) netip.Addr { return netip.Addr{} }

func sortedCsv(ips []netip.Addr) string {
	s := make([]string, 0, len(ips))
	for _, ip := range ips {
		s = append(s, ip.String())
	}
	slices.Sort(s)
	return strings.Join(s, ",")
}

func sortCsvStr(csv string) string {
	if csv == "" {
		return ""
	}
	s := strings.Split(csv, ",")
	slices.Sort(s)
	return strings.Join(s, ",")
}

func TestOracleAlg(t *testing.T) {
	var rec rrec
	// address generation
	for i := range 200 {
		k := fmt.Sprintf("d%d.example.com", i)
		rec.line("gen4", k+key4+"0", strconv.Itoa(i%5), gen4Locked(k+key4+"0", i%5).String(), nil)
		rec.line("gen6", k+key6+"0", strconv.Itoa(i%5), gen6Locked(k+key6+"0", i%5).String(), nil)
	}

	g := rand.New(rand.NewPCG(21, 42))
	fake := []netip.AddrPort{netip.MustParseAddrPort("10.111.222.3:53")}
	gw := NewDNSGateway(context.Background(), fake, oracleRdns{}, oracle64{})
	doms := []string{"a.example", "b.example", "cdn.example", "x.test", "y.test", "z.test"}
	tids := []string{"Preferred", "System", "CachePreferred", "BlockAll"}
	uids := []string{"-1", "10123", "10456", "10789"}
	pool := []netip.Addr{netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("10.111.222.3")}
	randip := func() netip.Addr {
		if g.IntN(3) == 0 {
			b := [16]byte{0x20, 0x01, 0x0d, 0xb8}
			b[15] = byte(g.IntN(8))
			return netip.AddrFrom16(b)
		}
		return netip.AddrFrom4([4]byte{93, 184, 0, byte(g.IntN(8))})
	}
	for range 3000 {
		switch op := g.IntN(10); {
		case op < 3: // register, as dnsgateway.q does after an answer
			d := pick(g, doms)
			tid := pick(g, tids[:3])
			uid := pick(g, uids)
			var real, sec []netip.Addr
			for range 1 + g.IntN(3) {
				real = append(real, randip())
			}
			switch g.IntN(4) {
			case 0:
				sec = append(sec, real...)
			case 1:
				sec = []netip.Addr{anyaddr4, anyaddr6}
			}
			targets := []string{d}
			if g.IntN(2) == 0 {
				targets = append(targets, "edge."+d)
			}
			bl := ""
			if g.IntN(3) == 0 {
				bl = "privacy:" + d
			}
			ttl := time.Duration(g.IntN(600)) * time.Second
			if !gw.split.Load() {
				uid = "-1"
			}
			gw.Lock()
			var a4, a6 netip.Addr
			if len(v4only(real)) > 0 {
				a4, _ = gw.take4Locked(d, 0)
			}
			if len(v6only(real)) > 0 {
				a6, _ = gw.take6Locked(d, 0)
			}
			ok := gw.registerLocked(d, tid, uid, "f", a4, a6, real, ttl, targets, secans{ips: sec, smm: &x.DNSSummary{Blocklists: bl}})
			gw.Unlock()
			pool = append(pool, real...)
			if a4.IsValid() {
				pool = append(pool, a4)
			}
			if a6.IsValid() {
				pool = append(pool, a6)
			}
			args := strings.Join([]string{d, tid, uid, sortedCsv(real), sortedCsv(sec), strconv.Itoa(int(ttl.Seconds())), strings.Join(targets, ","), bl}, "|")
			rec.line("reg", args, "", a4.String()+"|"+a6.String()+"|"+strconv.FormatBool(ok), nil)
		case op == 3:
			if g.IntN(4) == 0 {
				m, f := g.IntN(2) == 0, g.IntN(2) == 0
				gw.translate(m, f)
				rec.line("tr", strconv.FormatBool(m), strconv.FormatBool(f), "", nil)
			} else if g.IntN(8) == 0 {
				gw.splitTunnel()
				rec.line("split", "", "", "", nil)
			} else if g.IntN(6) == 0 {
				tid := pick(g, tids[:3])
				gw.onStopped(tid)
				rec.line("stop", tid, "", "", nil)
			}
		case op < 7:
			ip := pick(g, pool)
			uid := pick(g, uids)
			var ts []string
			if g.IntN(2) == 0 {
				ts = []string{pick(g, tids)}
			}
			ips, undid := gw.X(ip, uid, ts...)
			rec.line("x", ip.String()+"|"+uid, strings.Join(ts, ","), sortedCsv(ips)+"|"+strconv.FormatBool(undid), nil)
		case op < 9:
			ip := pick(g, pool)
			uid := pick(g, uids)
			force := g.IntN(2) == 0
			doms, useptr := gw.PTR(ip, uid, "", force)
			rec.line("ptr", ip.String()+"|"+uid, strconv.FormatBool(force), sortCsvStr(doms)+"|"+strconv.FormatBool(useptr), nil)
			rec.line("bl", ip.String(), "", gw.RDNSBL(ip), nil)
		default:
			d := pick(g, doms)
			typ := iptype(g.IntN(3))
			tid := pick(g, tids[:3])
			uid := pick(g, uids)
			gw.RLock()
			i4, i6, _, _, _ := gw.resolvLocked(d, typ, tid, uid)
			gw.RUnlock()
			rec.line("resolv", d+"|"+tid+"|"+uid, strconv.Itoa(int(typ)), sortedCsv(i4)+"|"+sortedCsv(i6), nil)
		}
	}
	rec.write(t, "alg.tsv")
}
