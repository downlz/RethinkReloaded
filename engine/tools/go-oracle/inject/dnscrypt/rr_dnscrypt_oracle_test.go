//go:build oracle

// Copyright (c) 2026 RethinkReloaded contributors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// RethinkReloaded oracle for DNSCrypt: seeded random vectors for both crypto constructions (shared-key derivation,
// seal), padding, TXT unescaping (packTxtString), certificate selection (as fetchCurrentDNSCryptCert picks among
// TXT records) and DNS stamps (go-dnsstamps), recorded as dnscrypt.tsv (op \t args... \t result).
package dnscrypt

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/celzero/firestack/intra/xdns"
	"github.com/jedisct1/xsecretbox"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/secretbox"

	stamps "github.com/jedisct1/go-dnsstamps"
)

func rbytes(g *rand.Rand, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(g.UintN(256))
	}
	return b
}

func h(b []byte) string { return hex.EncodeToString(b) }

// certBytes builds a DNSCrypt v2 certificate: magic, es-version, minor, signature, server pk, client magic,
// serial, ts-start, ts-end (the layout fetchCurrentDNSCryptCert parses).
func certBytes(sk ed25519.PrivateKey, es uint16, serverPk, magic []byte, serial, begin, end uint32) []byte {
	signed := append(append([]byte{}, serverPk...), magic...)
	var t [12]byte
	binary.BigEndian.PutUint32(t[0:4], serial)
	binary.BigEndian.PutUint32(t[4:8], begin)
	binary.BigEndian.PutUint32(t[8:12], end)
	signed = append(signed, t[:]...)
	sig := ed25519.Sign(sk, signed)
	var head [8]byte
	copy(head[0:4], xdns.CertMagic[:4])
	binary.BigEndian.PutUint16(head[4:6], es)
	return append(append(head[:], sig...), signed...)
}

// escapeTxt renders bytes the way miekg/dns presents TXT strings (\DDD for non-printables, \" and \\ escaped).
func escapeTxt(b []byte) string {
	var s strings.Builder
	for _, c := range b {
		switch {
		case c == '"' || c == '\\':
			s.WriteByte('\\')
			s.WriteByte(c)
		case c <= 0x20 || c > 0x7e:
			fmt.Fprintf(&s, "\\%03d", c)
		default:
			s.WriteByte(c)
		}
	}
	return s.String()
}

func TestOracleDNSCrypt(t *testing.T) {
	out := os.Getenv("RR_ORACLE_OUT")
	if out == "" {
		t.Skip("RR_ORACLE_OUT not set")
	}
	g := rand.New(rand.NewPCG(7, 13))
	var lines []string
	w := func(f ...string) { lines = append(lines, strings.Join(f, "\t")) }

	// shared keys and seals
	for i := 0; i < 64; i++ {
		var sk, pk [32]byte
		copy(sk[:], rbytes(g, 32))
		other := rbytes(g, 32)
		curve25519.ScalarBaseMult(&pk, (*[32]byte)(other))
		name := "p"
		xs := computeSharedKey(xdns.XSalsa20Poly1305, &sk, &pk, &name)
		xc := computeSharedKey(xdns.XChacha20Poly1305, &sk, &pk, &name)
		w("shared", h(sk[:]), h(pk[:]), h(xs[:]), h(xc[:]))

		nonce := rbytes(g, 24)
		msg := rbytes(g, g.IntN(300))
		var n24 [24]byte
		copy(n24[:], nonce)
		w("seal_xsalsa", h(xs[:]), h(nonce), h(msg), h(secretbox.Seal(nil, msg, &n24, &xs)))
		w("seal_xchacha", h(xc[:]), h(nonce), h(msg), h(xsecretbox.Seal(nil, nonce, msg, xc[:])))
	}

	// padding
	for i := 0; i < 32; i++ {
		msg := rbytes(g, g.IntN(64))
		min := len(msg) + 1 + g.IntN(80)
		w("pad", h(msg), strconv.Itoa(min), h(pad(append([]byte{}, msg...), min)))
		up, err := unpad(rbytes(g, g.IntN(8)+1))
		w("unpad_random", "-", h(up), fmt.Sprint(err != nil))
	}

	// TXT unescaping
	for i := 0; i < 32; i++ {
		b := rbytes(g, g.IntN(140))
		s := escapeTxt(b)
		w("txt", s, h(packTxtString(s)))
	}

	// certificate selection: a few certs per server, some expired, superseded or mis-signed
	// keys from seeds of the seeded generator, so the fixture is reproducible
	sk := ed25519.NewKeyFromSeed(rbytes(g, ed25519.SeedSize))
	otherSk := ed25519.NewKeyFromSeed(rbytes(g, ed25519.SeedSize))
	pub := sk.Public().(ed25519.PublicKey)
	now := uint32(1795000000)
	for i := 0; i < 48; i++ {
		var txts []string
		n := 1 + g.IntN(4)
		for j := 0; j < n; j++ {
			es := uint16(1 + g.IntN(2))
			if g.IntN(10) == 0 {
				es = 3 // unsupported
			}
			begin := now - uint32(g.IntN(86400*3))
			end := begin + uint32(1+g.IntN(86400*10))
			if g.IntN(6) == 0 {
				end = now - 1 // expired
			}
			key := sk
			if g.IntN(8) == 0 {
				key = otherSk // bad signature
			}
			c := certBytes(key, es, rbytes(g, 32), rbytes(g, 8), uint32(g.IntN(4)), begin, end)
			txts = append(txts, escapeTxt(c))
		}
		ignore := g.IntN(5) == 0
		w("certs", h(pub), strconv.FormatUint(uint64(now), 10), fmt.Sprint(ignore), strings.Join(txts, " "), pickCert(pub, txts, now, ignore))
	}

	// stamps: random ServerStamps through String() and back, plus malformed ones
	protos := []stamps.StampProtoType{stamps.StampProtoTypeDNSCrypt, stamps.StampProtoTypeDoH, stamps.StampProtoTypeDNSCryptRelay}
	addrs := []string{"", "1.2.3.4", "1.2.3.4:5353", "[2001:db8::1]", "[2001:db8::1]:8443", "2001:db8::2", "host.example", "::ffff:9.9.9.9"}
	for i := 0; i < 300; i++ {
		st := stamps.ServerStamp{
			Proto:         protos[g.IntN(len(protos))],
			Props:         stamps.ServerInformalProperties(g.Uint64N(8)),
			ServerAddrStr: addrs[g.IntN(len(addrs))],
			ProviderName:  []string{"2.dnscrypt-cert.example", "doh.example", "", "x.y"}[g.IntN(4)],
			Path:          []string{"/dns-query", "", "/q"}[g.IntN(3)],
		}
		if st.Proto == stamps.StampProtoTypeDNSCrypt {
			st.ServerPk = rbytes(g, 32)
		}
		for k := g.IntN(3); k > 0; k-- {
			st.Hashes = append(st.Hashes, rbytes(g, 32))
		}
		s := st.String()
		if g.IntN(10) == 0 { // corrupt
			b := []byte(s)
			b[5+g.IntN(len(b)-5)] = "Ab_-0"[g.IntN(5)]
			s = string(b)
		}
		w("stamp", s, stampResult(s))
	}
	for _, s := range []string{"sdns:", "sdns://", "dns://AQ", "sdns://AA", "sdns://gQ", "sdns://AQcAAAAAAAAA"} {
		w("stamp", s, stampResult(s))
	}

	if err := os.WriteFile(filepath.Join(out, "dnscrypt.tsv"), []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func stampResult(s string) string {
	st, err := stamps.NewServerStampFromString(s)
	if err != nil {
		return "err"
	}
	var hs []string
	for _, x := range st.Hashes {
		hs = append(hs, h(x))
	}
	return fmt.Sprintf("%d|%d|%s|%s|%s|%s|%s", st.Proto, st.Props, st.ServerAddrStr, h(st.ServerPk), st.ProviderName, st.Path, strings.Join(hs, ","))
}

// pickCert mirrors the selection loop of fetchCurrentDNSCryptCert over TXT strings (without the network
// exchange): the result is "construction|serverPk|magic", or "none".
func pickCert(pk ed25519.PublicKey, txts []string, now uint32, ignoreTs bool) string {
	cc := xdns.UndefinedConstruction
	var serverPk [32]byte
	var magic [8]byte
	highest := uint32(0)
	for _, txt := range txts {
		b := packTxtString(txt)
		if len(b) < 124 || string(b[:4]) != string(xdns.CertMagic[:4]) {
			continue
		}
		var c xdns.CryptoConstruction
		switch binary.BigEndian.Uint16(b[4:6]) {
		case 1:
			c = xdns.XSalsa20Poly1305
		case 2:
			c = xdns.XChacha20Poly1305
		default:
			continue
		}
		if !ed25519.Verify(pk, b[72:], b[8:72]) {
			continue
		}
		serial := binary.BigEndian.Uint32(b[112:116])
		begin := binary.BigEndian.Uint32(b[116:120])
		end := binary.BigEndian.Uint32(b[120:124])
		if begin >= end {
			continue
		}
		if !ignoreTs && (now > end || now < begin) {
			continue
		}
		if serial < highest {
			continue
		}
		if serial == highest && c < cc {
			continue
		}
		copy(serverPk[:], b[72:104])
		copy(magic[:], b[104:112])
		highest = serial
		cc = c
	}
	if cc == xdns.UndefinedConstruction {
		return "none"
	}
	return fmt.Sprintf("%d|%s|%s", cc, h(serverPk[:]), h(magic[:]))
}

var _ = net.ParseIP
