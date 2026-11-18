//go:build oracle

// Copyright (c) 2026 RethinkReloaded contributors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// RethinkReloaded oracle: injected into a clean celzero/firestack checkout (package backend) by
// engine/tools/go-oracle/run.sh. Records firestack's own results for seeded random operation sequences as TSV
// fixtures (op \t arg1 \t arg2 \t result \t err) that the Rust ports replay in their tests.
package backend

import (
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/celzero/firestack/intra/settings"
)

type rec struct{ b strings.Builder }

func (r *rec) line(op, a1, a2, res string, err error) {
	e := "0"
	if err != nil {
		e = "1"
	}
	for _, s := range []string{op, a1, a2, res} {
		if strings.ContainsAny(s, "\t\n") {
			panic("oracle: field contains tab/newline: " + s)
		}
	}
	fmt.Fprintf(&r.b, "%s\t%s\t%s\t%s\t%s\n", op, a1, a2, res, e)
}

func (r *rec) write(t *testing.T, name string) {
	dir := os.Getenv("RR_ORACLE_OUT")
	if dir == "" {
		t.Skip("RR_ORACLE_OUT not set")
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(r.b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

func pick[T any](g *rand.Rand, xs []T) T { return xs[g.IntN(len(xs))] }

var cidrs = func() []string {
	out := []string{
		"10.0.0.0/8", "10.1.0.0/16", "10.1.2.0/24", "10.1.2.3/32", "10.1.2.3", "10.1.2.3:443", "10.1.2.128/25",
		"10.1.0.0/12", "10.255.255.255", "11.0.0.0/8", "0.0.0.0", "0.0.0.0/0", "0.0.0.0/8", "192.168.1.1",
		"192.168.0.0/16", "172.16.0.0/12", "8.8.8.8:53", "1.1.1.1",
		"2001:db8::/32", "2001:db8:1::/48", "2001:db8:1::1", "[2001:db8:1::1]:443", "2001:db8::", "::", "::/0",
		"::1", "fe80::1%wlan0", "fe80::/10", "2001:db8:0:0:1::1", "64:ff9b::/96", "64:ff9b::808:808",
		"::ffff:10.1.2.3", "::ffff:10.1.2.0/120", "::ffff:0.0.0.0/96", "::1.2.3.4",
		"bogus", "", "10.0.0.1/33", "300.1.1.1", "010.1.1.1", "10.0.0.0/08", "[10.0.0.1]:80", "2001:db8::1:53",
	}
	return out
}()

var vals = []string{"p1", "p2", "p", "x1", "Base", "Exit", "wg0", "wg01", "", "p1,p2"}
var likes = []string{"p", "x", "", "wg0", "Base", "q"}

func TestOracleIpTree(t *testing.T) {
	var r rec
	for seed := uint64(1); seed <= 40; seed++ {
		g := rand.New(rand.NewPCG(seed, 0x5eed))
		tr := NewIpTree()
		r.line("new", fmt.Sprint(seed), "", "", nil)
		for i := 0; i < 250; i++ {
			c, v, l := pick(g, cidrs), pick(g, vals), pick(g, likes)
			k := g.IntN(19)
			sub := g.IntN(20)
			c2 := pick(g, cidrs)
			// firestack (critbitgo) panics on some malformed route mixes; record and continue
			func() {
				defer func() {
					if p := recover(); p != nil {
						r.line("panic", c, fmt.Sprint(k), "", nil)
					}
				}()
				ipop(&r, tr, k, sub, c, c2, v, l)
			}()
		}
	}
	r.write(t, "iptree.tsv")
}

func ipop(r *rec, tr IpTree, k, sub int, c, c2, v, l string) {
	{
		{
			switch k {
			case 0, 1:
				r.line("add", c, v, "", tr.Add(c, v))
			case 2:
				r.line("set", c, v, "", tr.Set(c, v))
			case 3:
				r.line("esc", c, v, fmt.Sprint(tr.Esc(c, v)), nil)
			case 4:
				r.line("del", c, "", fmt.Sprint(tr.Del(c)), nil)
			case 5:
				s, err := tr.Get(c)
				r.line("get", c, "", s, err)
			case 6:
				b, err := tr.Has(c)
				r.line("has", c, "", fmt.Sprint(b), err)
			case 7:
				r.line("routes", c, "", tr.Routes(c), nil)
			case 8:
				r.line("values", c, "", tr.Values(c), nil)
			case 9:
				s, err := tr.GetAny(c)
				r.line("getAny", c, "", s, err)
			case 10:
				b, err := tr.HasAny(c)
				r.line("hasAny", c, "", fmt.Sprint(b), err)
			case 11:
				r.line("escLike", c, l, fmt.Sprint(tr.EscLike(c, l)), nil)
			case 12:
				r.line("routesLike", c, l, tr.RoutesLike(c, l), nil)
			case 13:
				r.line("valuesLike", c, l, tr.ValuesLike(c, l), nil)
			case 14:
				r.line("getLike", c, l, tr.GetLike(c, l), nil)
			case 15:
				s, err := tr.GetAll(c)
				r.line("getAll", c, "", s, err)
			case 16:
				if sub%4 == 0 {
					r.line("delAll", c, "", fmt.Sprint(tr.DelAll(c)), nil)
				} else {
					r.line("len", "", "", fmt.Sprint(tr.Len()), nil)
				}
			case 17:
				if sub == 0 {
					tr.Clear()
					r.line("clear", "", "", "", nil)
				} else {
					r.line("len", "", "", fmt.Sprint(tr.Len()), nil)
				}
			case 18:
				r.line("routes", c2, "", tr.Routes(c2), nil)
			}
		}
	}
}

var domains = []string{
	"example.com", ".example.com", "a.example.com", "b.a.example.com", "ample.com", "xample.com", "com", ".com",
	"", "example.org", ".org", "sub.example.org", "例え.jp", ".jp", "xn--bcher-kva.example", "a", ".a", "b.a",
}

func TestOracleRadixTree(t *testing.T) {
	var r rec
	for seed := uint64(1); seed <= 40; seed++ {
		g := rand.New(rand.NewPCG(seed, 0xd0d0))
		tr := NewRadixTree()
		r.line("new", fmt.Sprint(seed), "", "", nil)
		for i := 0; i < 200; i++ {
			d, v := pick(g, domains), pick(g, vals)
			switch g.IntN(10) {
			case 0:
				r.line("add", d, "", fmt.Sprint(tr.Add(d)), nil)
			case 1:
				tr.Set(d, v)
				r.line("set", d, v, "", nil)
			case 2:
				r.line("del", d, "", fmt.Sprint(tr.Del(d)), nil)
			case 3:
				r.line("get", d, "", tr.Get(d), nil)
			case 4:
				r.line("has", d, "", fmt.Sprint(tr.Has(d)), nil)
			case 5, 6:
				// Go panics (index -1) when only the empty key matches; skip those queries (see engine/PARITY.md)
				func() {
					defer func() {
						if recover() != nil {
							r.line("getAnyPanics", d, "", "", nil)
						}
					}()
					r.line("getAny", d, "", tr.GetAny(d), nil)
				}()
			case 7:
				func() {
					defer func() {
						if recover() != nil {
							r.line("hasAnyPanics", d, "", "", nil)
						}
					}()
					r.line("hasAny", d, "", fmt.Sprint(tr.HasAny(d)), nil)
				}()
			case 8:
				r.line("delAll", d, "", fmt.Sprint(tr.DelAll(d)), nil)
			case 9:
				r.line("len", "", "", fmt.Sprint(tr.Len()), nil)
			}
		}
	}
	r.write(t, "radixtree.tsv")
}

func TestOracleWgKey(t *testing.T) {
	var r rec
	g := rand.New(rand.NewPCG(7, 7))
	inputs := []string{"", "AAAA", "not base64!", "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=",
		"dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo", "dwdtCnMYpX08Fs\nFyUbJmRd9ML4frwJkqsXf7pR25LCo="}
	for i := 0; i < 64; i++ {
		var b [32]byte
		for j := range b {
			b[j] = byte(g.IntN(256))
		}
		k := (*eckey)(&b)
		inputs = append(inputs, k.Base64())
	}
	for _, in := range inputs {
		k, err := NewWgPrivateKeyOf(in)
		esc := strings.ReplaceAll(in, "\n", "\\n")
		if err != nil {
			r.line("of", esc, "", "", err)
			continue
		}
		r.line("of", esc, "", k.Hex()+"|"+k.Base64()+"|"+fmt.Sprint(k.IsZero())+"|"+k.Mult().Hex(), nil)
	}
	r.write(t, "wgkey.tsv")
}

func TestOracleSettings(t *testing.T) {
	var r rec
	for _, typ := range []string{"dns", "block", "pt", "DNS", "x"} {
		for m := int32(-1); m <= 5; m++ {
			r.line("mode2String", typ, fmt.Sprint(m), settings.Mode2String(typ, m), nil)
		}
	}
	for _, e := range []int{0, 2, 4, 6, 7} {
		r.line("l3", fmt.Sprint(e), "", settings.L3(e), nil)
	}
	for _, l := range []string{"4", "6", "46", "", "x"} {
		r.line("engine", l, "", fmt.Sprint(settings.Engine(l)), nil)
	}
	for _, c := range [][5]int32{{0, 0, 4096, 10, 1}, {3, 2, 1 << 30, -1, 0}, {9, 9, 0, 0, 1}, {4, 1, 65536, 30, 0}} {
		ok := settings.SetDialerOpts(c[0], c[1], c[2], c[3], c[4] == 1)
		r.line("setDialerOpts", fmt.Sprintf("%d,%d,%d,%d,%d", c[0], c[1], c[2], c[3], c[4]), "",
			fmt.Sprint(ok)+"|"+settings.GetDialerOpts().String(), nil)
	}
	for _, m := range []int32{-5, 0, 1, 2, 3} {
		prev := settings.SetAutoMode(m)
		r.line("setAutoMode", fmt.Sprint(m), "", fmt.Sprintf("%d|%s|%t|%t", prev, settings.AutoModeStr(),
			settings.AutoActive(), settings.AutoAlwaysRemote()), nil)
	}
	r.write(t, "settings.tsv")
}
