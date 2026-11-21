//go:build oracle

// Copyright (c) 2026 RethinkReloaded contributors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// RethinkReloaded oracle for DNS64 / NAT64: NAT64 prefixes derived from ipv4only.arpa answers (dns64.add), the two
// ip4to6 variants (x64's, used by X46; xdns's, used to synthesize AAAA records), x64's ip6to4 (X64), and AAAA
// synthesis (xdns.MaybeToQuadA), recorded as x64.tsv (op \t args... \t result).
package x64

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/celzero/firestack/intra/xdns"
	"github.com/miekg/dns"
)

func TestOracleX64(t *testing.T) {
	out := os.Getenv("RR_ORACLE_OUT")
	if out == "" {
		t.Skip("RR_ORACLE_OUT not set")
	}
	g := rand.New(rand.NewPCG(64, 46))
	var lines []string
	w := func(f ...string) { lines = append(lines, strings.Join(f, "\t")) }
	rip6 := func() net.IP {
		b := make(net.IP, 16)
		for i := range b {
			b[i] = byte(g.UintN(256))
		}
		return b
	}
	wkas := []net.IP{net.IPv4(192, 0, 0, 170).To4(), net.IPv4(192, 0, 0, 171).To4()}

	// prefixes from ipv4only.arpa answers, with the well-known address at each RFC 6052 position (and junk)
	d := newDns64(context.Background())
	positions := [][]int{{12, 13, 14, 15}, {9, 10, 11, 12}, {7, 9, 10, 11}, {6, 7, 9, 10}, {5, 6, 7, 9}, {4, 5, 6, 7}}
	for i := 0; i < 120; i++ {
		var ips []net.IP
		var in []string
		for k := 1 + g.IntN(2); k > 0; k-- {
			ip := rip6()
			if g.IntN(8) != 0 {
				pos := positions[g.IntN(len(positions))]
				wka := wkas[g.IntN(2)]
				for j, p := range pos {
					ip[p] = wka[j]
				}
			}
			ips = append(ips, ip)
			in = append(in, ip.String())
		}
		id := fmt.Sprintf("r%d", i)
		d.register(id)
		cp := make([]net.IP, len(ips))
		for j := range ips {
			cp[j] = append(net.IP{}, ips[j]...)
		}
		err := d.add(id, cp)
		var got []string
		for _, n := range d.get(id) {
			got = append(got, n.String())
		}
		w("prefix", strings.Join(in, ","), strings.Join(got, ","), fmt.Sprint(err != nil))
	}

	// address translation for prefix lengths 32..96
	for i := 0; i < 200; i++ {
		bits := []int{32, 40, 48, 56, 64, 96}[g.IntN(6)]
		pip := rip6().Mask(net.CIDRMask(bits, 128))
		pfx := net.IPNet{IP: pip, Mask: net.CIDRMask(bits, 128)}
		ip4 := net.IPv4(byte(g.UintN(256)), byte(g.UintN(256)), byte(g.UintN(256)), byte(g.UintN(256))).To4()
		if g.IntN(20) == 0 {
			ip4 = net.IPv4zero.To4()
		}
		x6 := ip4to6(&pfx, ip4)
		a := &dns.A{Hdr: dns.RR_Header{Name: "x.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: uint32(g.IntN(600))}, A: ip4}
		synth := "nil"
		if q := xdns.MaybeToQuadA(a, pfx); q != nil {
			synth = fmt.Sprintf("%s|%d", q.AAAA.String(), q.Hdr.Ttl)
		}
		w("x46", pfx.String(), ip4.String(), x6.String(), fmt.Sprint(a.Hdr.Ttl), synth)
		ip6 := rip6()
		copy(ip6, pip[:bits/8])
		w("x64", pfx.String(), ip6.String(), ip6to4(&pfx, ip6).String())
	}

	if err := os.WriteFile(filepath.Join(out, "x64.tsv"), []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}
