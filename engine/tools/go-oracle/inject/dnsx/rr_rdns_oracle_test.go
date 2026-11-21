//go:build oracle

// Copyright (c) 2026 RethinkReloaded contributors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// RethinkReloaded oracle for RethinkDNS blocklists: injected into a clean celzero/firestack checkout (package dnsx)
// by engine/tools/go-oracle/run.sh. Records firestack's own results as TSV (op \t arg1 \t arg2 \t result \t err),
// err = 0 | 1 | p (firestack panicked; the Rust replay skips those).
//
//   rdns.tsv       blockstamp encode/decode against filetag.json (RR_BLOCKLIST_DIR/filetag.json)
//   rdnstrie.tsv   trie lookups + blockQuery/blockAnswer against the full on-device trie in RR_BLOCKLIST_DIR
//                  (td.txt, rd.txt, basicconfig.json, filetag.json); first line records the trie's md5.
package dnsx

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

type rrec struct{ b strings.Builder }

func (r *rrec) line(op, a1, a2, res string, err any) {
	e := "0"
	switch v := err.(type) {
	case nil:
	case string:
		e = v
	case error:
		if v != nil {
			e = "1"
		}
	}
	for _, s := range []string{op, a1, a2, res} {
		if strings.ContainsAny(s, "\t\n") {
			panic("oracle: field contains tab/newline: " + s)
		}
	}
	fmt.Fprintf(&r.b, "%s\t%s\t%s\t%s\t%s\n", op, a1, a2, res, e)
}

func (r *rrec) write(t *testing.T, name string) {
	dir := os.Getenv("RR_ORACLE_OUT")
	if dir == "" {
		t.Skip("RR_ORACLE_OUT not set")
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(r.b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

// try runs f, reporting a panic as err "p".
func try(f func() (string, error)) (res string, e any) {
	defer func() {
		if p := recover(); p != nil {
			res, e = "", "p"
		}
	}()
	s, err := f()
	if err != nil {
		return s, err
	}
	return s, nil
}

func blDir(t *testing.T) string {
	d := os.Getenv("RR_BLOCKLIST_DIR")
	if d == "" {
		t.Skip("RR_BLOCKLIST_DIR not set")
	}
	return d
}

func TestOracleRdnsStamps(t *testing.T) {
	dir := blDir(t)
	flags, tags, err := load(filepath.Join(dir, "filetag.json"))
	if err != nil {
		t.Fatal(err)
	}
	r := &rethinkdns{flags: flags, tags: tags, mode: localBlock}
	n := len(flags)
	g := rand.New(rand.NewPCG(7, 11))
	var rec rrec

	csvs := []string{"", ",", "0", "1", "15", "16", "17", "0,1,2", "2,1,0", "5,5,5", "1,,2", ",1", "-1", "65535",
		"65536", "abc", " 5", "+5", "4096", "255,256,257", strconv.Itoa(n - 1), strconv.Itoa(n), strconv.Itoa(n + 3)}
	for range 300 {
		k := 1 + g.IntN(24)
		var xs []string
		for range k {
			xs = append(xs, strconv.Itoa(g.IntN(n+8)))
		}
		csvs = append(csvs, strings.Join(xs, ","))
	}
	all := make([]string, n)
	for i := range n {
		all[i] = strconv.Itoa(i)
	}
	csvs = append(csvs, strings.Join(all, ","))

	var stamps []string
	for _, c := range csvs {
		for _, enc := range []int{EB32, EB64} {
			s, e := try(func() (string, error) { return r.flagsToStamp(c, enc) })
			rec.line("flagsToStamp", c, strconv.Itoa(enc), s, e)
			if e == nil {
				stamps = append(stamps, s)
			}
		}
	}
	// variants of valid stamps
	var more []string
	for i, s := range stamps {
		if i%3 != 0 {
			continue
		}
		more = append(more, strings.TrimRight(s, "="), strings.ToUpper(s), s[:len(s)-1], s+"A",
			strings.Replace(s, "1", "0", 1), strings.Replace(s, "1", "2", 1),
			strings.ReplaceAll(strings.ReplaceAll(s, "-", "+"), "_", "/"))
	}
	stamps = append(stamps, more...)
	stamps = append(stamps, "", "1:", "1-", ":", "-", "1", "0:", "garbage", "1:!!!!", "1-0000", "1:AAAA", "1:AA==",
		"1-aaaa", "1-AE", "1:-AcHAL6d_5-Yxf7zMQAKAAAI", "1-7adqoaf6tx7z7ggf73ztcaakaaaaq", "1:IHD_D___APzAPw==",
		"1:4P___________________________-D_", "1:AIAAwA==", "6IeA6ICA4oCAxIAE", "0:6IeA6ICA4oCAxIAE",
		"77%2Bg77%2B%2F77%2B%2F77%2B%2F77%2B%2F77%2B%2F77%2B%2F77%2B%2F77%2B%2F77%2B%2F77%2B%2F77%2Bg", "w4DEgAQ=",
		"0:w4DEgAQ%3D", "0:%zz", "1:YAYBACABEDAgAA==", "1:YAYBACABEDAgAA", "1-madacabaaeidaiaa", "1-MADACABAAEIDAIAA",
		"1-madacabaaeidaiaa====", "1:a-b", "1-a:b", "2-abc", "1:AAA=", "1:gAA=", "1:gACAAA==")

	for _, s := range stamps {
		f, e := try(func() (string, error) { return r.stampToFlags(s) })
		rec.line("stampToFlags", s, "", f, e)
		nm, e := try(func() (string, error) { return r.stampToNames(s) })
		rec.line("stampToNames", s, "", nm, e)
		ns, e := try(func() (string, error) {
			if err := r.setStamp(s); err != nil {
				return "", err
			}
			return r.getStamp()
		})
		rec.line("setStamp", s, "", ns, e)
	}
	rec.write(t, "rdns.tsv")
}

var rdnsDomains = []string{
	"google.com", "www.google.com", "doubleclick.net", "ad.doubleclick.net", "googleads.g.doubleclick.net",
	"googlesyndication.com", "pagead2.googlesyndication.com", "googleadservices.com", "www.googleadservices.com",
	"google-analytics.com", "www.google-analytics.com", "ssl.google-analytics.com", "googletagmanager.com",
	"www.googletagmanager.com", "googletagservices.com", "adservice.google.com", "app-measurement.com",
	"facebook.com", "www.facebook.com", "graph.facebook.com", "connect.facebook.net", "fbcdn.net", "instagram.com",
	"whatsapp.com", "whatsapp.net", "messenger.com", "twitter.com", "x.com", "t.co", "twimg.com", "ads-twitter.com",
	"analytics.twitter.com", "tiktok.com", "tiktokv.com", "byteoverseas.com", "snapchat.com", "sc-analytics.appspot.com",
	"reddit.com", "redditmedia.com", "linkedin.com", "ads.linkedin.com", "pinterest.com", "tumblr.com", "twitch.tv",
	"rubbish.twitch.tv", "youtube.com", "www.youtube.com", "youtubei.googleapis.com", "ytimg.com", "googlevideo.com",
	"netflix.com", "amazon.com", "www.amazon.com", "www.aws.amazon.com", "amazon-adsystem.com", "aax.amazon-adsystem.com",
	"s.amazon-adsystem.com", "adsystem.amazon.com", "device-metrics-us.amazon.com", "microsoft.com", "bing.com",
	"bat.bing.com", "msn.com", "ads.msn.com", "live.com", "vortex.data.microsoft.com", "telemetry.microsoft.com",
	"settings-win.data.microsoft.com", "apple.com", "icloud.com", "metrics.apple.com", "iadsdk.apple.com",
	"xp.apple.com", "scorecardresearch.com", "sb.scorecardresearch.com", "quantserve.com", "pixel.quantserve.com",
	"criteo.com", "static.criteo.net", "bidder.criteo.com", "taboola.com", "cdn.taboola.com", "outbrain.com",
	"widgets.outbrain.com", "adnxs.com", "ib.adnxs.com", "rubiconproject.com", "fastlane.rubiconproject.com",
	"pubmatic.com", "ads.pubmatic.com", "openx.net", "us-u.openx.net", "casalemedia.com", "indexww.com",
	"advertising.com", "adsrvr.org", "match.adsrvr.org", "moatads.com", "z.moatads.com", "chartbeat.com",
	"static.chartbeat.com", "hotjar.com", "static.hotjar.com", "mixpanel.com", "api.mixpanel.com", "segment.io",
	"api.segment.io", "segment.com", "amplitude.com", "api.amplitude.com", "branch.io", "app.link", "appsflyer.com",
	"t.appsflyer.com", "adjust.com", "app.adjust.com", "kochava.com", "flurry.com", "data.flurry.com", "crashlytics.com",
	"settings.crashlytics.com", "firebaseinstallations.googleapis.com", "firebase-settings.crashlytics.com",
	"unityads.unity3d.com", "config.unityads.unity3d.com", "applovin.com", "a.applovin.com", "vungle.com",
	"api.vungle.com", "chartboost.com", "inmobi.com", "ironsrc.com", "supersonicads.com", "mopub.com", "ads.mopub.com",
	"startappservice.com", "admob.com", "media.net", "contextual.media.net", "yieldmo.com", "smartadserver.com",
	"teads.tv", "sharethrough.com", "33across.com", "gumgum.com", "bluekai.com", "tags.bluekai.com", "krxd.net",
	"cdn.krxd.net", "demdex.net", "dpm.demdex.net", "omtrdc.net", "2o7.net", "everesttech.net", "tapad.com",
	"agkn.com", "rlcdn.com", "exelator.com", "eyeota.net", "lijit.com", "sovrn.com", "yandex.ru", "mc.yandex.ru",
	"an.yandex.ru", "yandex.net", "baidu.com", "hm.baidu.com", "pos.baidu.com", "qq.com", "wechat.com", "weibo.com",
	"alibaba.com", "aliexpress.com", "mmstat.com", "umeng.com", "alog.umeng.com", "xiaomi.com", "tracking.miui.com",
	"data.mistat.xiaomi.com", "samsung.com", "samsungads.com", "config.samsungads.com", "huawei.com", "hicloud.com",
	"metrics.data.hicloud.com", "oppo.com", "vivo.com.cn", "onesignal.com", "pushwoosh.com", "newrelic.com",
	"bam.nr-data.net", "nr-data.net", "sentry.io", "o1.ingest.sentry.io", "bugsnag.com", "sessions.bugsnag.com",
	"optimizely.com", "cdn.optimizely.com", "doubleverify.com", "cdn.doubleverify.com", "integralads.com",
	"pixel.adsafeprotected.com", "adsafeprotected.com", "zedo.com", "popads.net", "propellerads.com", "popcash.net",
	"exoclick.com", "juicyads.com", "trafficjunky.net", "pornhub.com", "xvideos.com", "xhamster.com", "onlyfans.com",
	"bet365.com", "pokerstars.com", "draftkings.com", "1xbet.com", "thepiratebay.org", "1337x.to", "rarbg.to",
	"coinhive.com", "coin-hive.com", "cryptoloot.pro", "malware.wicar.org", "testsafebrowsing.appspot.com",
	"wikipedia.org", "en.wikipedia.org", "github.com", "raw.githubusercontent.com", "stackoverflow.com",
	"cloudflare.com", "one.one.one.one", "rethinkdns.com", "dl.rethinkdns.com", "sky.rethinkdns.com", "example.com",
	"example.org", "localhost", "local", "lan", "home.arpa", "in-addr.arpa", "1.1.1.1.in-addr.arpa", "com", "net", "org",
	"tv", "io", "xyz", "top", "click", "zip", "ru", "cn", "invalid", ".", "", "a", "-", "a..b", "WWW.DoubleClick.NET",
	"doubleclick.net.", "Ads.LinkedIn.com", "  doubleclick.net  ", "xn--80ak6aa92e.com", "日本.jp", "ünicode.de",
	"a-very-long-label-that-goes-on-and-on-and-on-and-on-forever-and-ever.doubleclick.net",
	"tracker.example.doubleclick.net", "x.y.z.googlesyndication.com", "deep.sub.domain.of.criteo.com",
	"notblocked-really-random-zz9q.com", "qwertyuiopasdfghjkl.net", "zzzzzzzzzzzzzzzz.org", "aaaaaaaaa.aaaaaaaa",
	"0.0.0.0", "127.0.0.1", "::1", "10.0.0.1", "192.168.1.1", "_dmarc.example.com", "_443._tcp.example.com",
}

func rdnsCorpus() []string {
	g := rand.New(rand.NewPCG(3, 5))
	out := append([]string{}, rdnsDomains...)
	labels := []string{"www", "ads", "ad", "cdn", "api", "m", "static", "img", "track", "pixel", "metrics", "t", "s",
		"x", "eu", "us", "a1", "z9", "beacon", "telemetry"}
	for _, d := range rdnsDomains {
		if len(d) < 3 || !strings.Contains(d, ".") {
			continue
		}
		out = append(out, labels[g.IntN(len(labels))]+"."+d)
		if g.IntN(3) == 0 {
			out = append(out, fmt.Sprintf("r%d.%s.%s", g.IntN(1000), labels[g.IntN(len(labels))], d))
		}
		if g.IntN(4) == 0 {
			out = append(out, strings.ToUpper(d[:1])+d[1:]+".")
		}
	}
	return out
}

func TestOracleRdnsTrie(t *testing.T) {
	dir := blDir(t)
	j := func(n string) string { return filepath.Join(dir, n) }
	rl, err := newRDNSLocal(j("td.txt"), j("rd.txt"), j("basicconfig.json"), j("filetag.json"))
	if err != nil {
		t.Fatal(err)
	}
	bc, _ := os.ReadFile(j("basicconfig.json"))
	var conf map[string]any
	_ = json.Unmarshal(bc, &conf)

	var rec rrec
	rec.line("trie", fmt.Sprint(conf["tdmd5"]), fmt.Sprint(conf["rdmd5"]), fmt.Sprint(conf["nodecount"]), nil)

	corpus := rdnsCorpus()
	for _, d := range corpus {
		w := []byte(d)
		for a, b := 0, len(w)-1; a < b; a, b = a+1, b-1 {
			w[a], w[b] = w[b], w[a]
		}
		res, e := try(func() (string, error) {
			ok, v := rl.ftrie.Lookup(w)
			var xs []string
			for _, x := range v {
				xs = append(xs, strconv.FormatUint(uint64(x), 10))
			}
			return fmt.Sprintf("%t:%s", ok, strings.Join(xs, ",")), nil
		})
		rec.line("lookup", d, "", res, e)
	}

	n := len(rl.flags)
	all := make([]string, n)
	for i := range n {
		all[i] = strconv.Itoa(i)
	}
	allb64, _ := rl.flagsToStamp(strings.Join(all, ","), EB64)
	allb32, _ := rl.flagsToStamp(strings.Join(all, ","), EB32)
	g := rand.New(rand.NewPCG(13, 17))
	stamps := []string{allb64, allb32, "1:IHD_D___APzAPw==", "1:AIAAwA==",
		"77%2Bg77%2B%2F77%2B%2F77%2B%2F77%2B%2F77%2B%2F77%2B%2F77%2B%2F77%2B%2F77%2B%2F77%2B%2F77%2Bg"}
	for range 4 {
		var xs []string
		for range 1 + g.IntN(40) {
			xs = append(xs, strconv.Itoa(g.IntN(n)))
		}
		s, _ := rl.flagsToStamp(strings.Join(xs, ","), EB32)
		stamps = append(stamps, s)
	}

	for si, s := range stamps {
		_, e := try(func() (string, error) { return "", rl.setStamp(s) })
		rec.line("stamp", s, "", strconv.Itoa(si), e)
		if e != nil {
			continue
		}
		for _, d := range corpus {
			for _, qt := range []uint16{dns.TypeA, dns.TypeHTTPS, dns.TypeTXT} {
				res, e := try(func() (string, error) {
					q := new(dns.Msg)
					q.SetQuestion(dns.Fqdn(d), qt)
					return rl.blockQuery(q)
				})
				rec.line("blockQuery", d, strconv.Itoa(int(qt)), res, e)
				if qt != dns.TypeA {
					continue // answers: one record type is enough
				}
				res, e = try(func() (string, error) {
					q := new(dns.Msg)
					q.SetQuestion("cloak.example.", dns.TypeA)
					a := new(dns.Msg)
					a.SetReply(q)
					a.Answer = append(a.Answer, &dns.CNAME{
						Hdr:    dns.RR_Header{Name: "cloak.example.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
						Target: dns.Fqdn(d),
					})
					bt, bl, err := rl.blockAnswer(a)
					return bt + "|" + bl, err
				})
				rec.line("blockAnswer", d, "", res, e)
			}
		}
	}
	rec.write(t, "rdnstrie.tsv")
}
