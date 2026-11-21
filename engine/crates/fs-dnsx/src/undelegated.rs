// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/core/undelegated.go

//! Undelegated and special-use domains (firestack `core.UndelegatedDomains`): names the public DNS never
//! answers, such as private-range reverse zones, `.lan`, `.internal` and `.home.arpa`.

/// The domains, as firestack lists them (148 entries).
pub const UNDELEGATED_DOMAINS: &[&str] = &[
    "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
    "0.in-addr.arpa",
    "1",
    "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
    "10.in-addr.arpa",
    "100.100.in-addr.arpa",
    "100.51.198.in-addr.arpa",
    "101.100.in-addr.arpa",
    "102.100.in-addr.arpa",
    "103.100.in-addr.arpa",
    "104.100.in-addr.arpa",
    "105.100.in-addr.arpa",
    "106.100.in-addr.arpa",
    "107.100.in-addr.arpa",
    "108.100.in-addr.arpa",
    "109.100.in-addr.arpa",
    "110.100.in-addr.arpa",
    "111.100.in-addr.arpa",
    "112.100.in-addr.arpa",
    "113.0.203.in-addr.arpa",
    "113.100.in-addr.arpa",
    "114.100.in-addr.arpa",
    "115.100.in-addr.arpa",
    "116.100.in-addr.arpa",
    "117.100.in-addr.arpa",
    "118.100.in-addr.arpa",
    "119.100.in-addr.arpa",
    "120.100.in-addr.arpa",
    "121.100.in-addr.arpa",
    "122.100.in-addr.arpa",
    "123.100.in-addr.arpa",
    "124.100.in-addr.arpa",
    "125.100.in-addr.arpa",
    "126.100.in-addr.arpa",
    "127.100.in-addr.arpa",
    "127.in-addr.arpa",
    "16.172.in-addr.arpa",
    "168.192.in-addr.arpa",
    "17.172.in-addr.arpa",
    "18.172.in-addr.arpa",
    "19.172.in-addr.arpa",
    "2.0.192.in-addr.arpa",
    "20.172.in-addr.arpa",
    "21.172.in-addr.arpa",
    "22.172.in-addr.arpa",
    "23.172.in-addr.arpa",
    "24.172.in-addr.arpa",
    "25.172.in-addr.arpa",
    "254.169.in-addr.arpa",
    "255.255.255.255.in-addr.arpa",
    "26.172.in-addr.arpa",
    "27.172.in-addr.arpa",
    "28.172.in-addr.arpa",
    "29.172.in-addr.arpa",
    "30.172.in-addr.arpa",
    "31.172.in-addr.arpa",
    "64.100.in-addr.arpa",
    "65.100.in-addr.arpa",
    "66.100.in-addr.arpa",
    "67.100.in-addr.arpa",
    "68.100.in-addr.arpa",
    "69.100.in-addr.arpa",
    "70.100.in-addr.arpa",
    "71.100.in-addr.arpa",
    "72.100.in-addr.arpa",
    "73.100.in-addr.arpa",
    "74.100.in-addr.arpa",
    "75.100.in-addr.arpa",
    "76.100.in-addr.arpa",
    "77.100.in-addr.arpa",
    "78.100.in-addr.arpa",
    "79.100.in-addr.arpa",
    "8.b.d.0.1.0.0.2.ip6.arpa",
    "8.e.f.ip6.arpa",
    "80.100.in-addr.arpa",
    "81.100.in-addr.arpa",
    "82.100.in-addr.arpa",
    "83.100.in-addr.arpa",
    "84.100.in-addr.arpa",
    "85.100.in-addr.arpa",
    "86.100.in-addr.arpa",
    "87.100.in-addr.arpa",
    "88.100.in-addr.arpa",
    "89.100.in-addr.arpa",
    "9.e.f.ip6.arpa",
    "90.100.in-addr.arpa",
    "91.100.in-addr.arpa",
    "92.100.in-addr.arpa",
    "93.100.in-addr.arpa",
    "94.100.in-addr.arpa",
    "95.100.in-addr.arpa",
    "96.100.in-addr.arpa",
    "97.100.in-addr.arpa",
    "98.100.in-addr.arpa",
    "99.100.in-addr.arpa",
    "a.e.f.ip6.arpa",
    ".airdream",
    ".api",
    "b.e.f.ip6.arpa",
    ".bbrouter",
    ".belkin",
    ".bind",
    ".blinkap",
    ".corp",
    "d.f.ip6.arpa",
    ".davolink",
    ".dearmyrouter",
    ".dhcp",
    ".dlink",
    ".domain",
    ".envoy",
    ".example",
    "fritz.box",
    "f.f.ip6.arpa",
    ".fritz.box",
    ".grp",
    ".gw==",
    ".home",
    ".home.arpa",
    ".hub",
    ".internal",
    ".intra",
    ".intranet",
    ".invalid",
    ".ksyun",
    ".lan",
    ".loc",
    ".local",
    ".localdomain",
    ".localhost",
    ".localnet",
    ".mail",
    ".modem",
    ".mynet",
    ".myrouter",
    ".novalocal",
    ".onion",
    ".openstacklocal",
    ".priv",
    ".private",
    ".prv",
    ".router",
    ".telus",
    ".test",
    ".totolink",
    ".wlan_ap",
    ".workgroup",
    ".zghjccbob3n0",
];

static TRIE: std::sync::LazyLock<fs_iptree::RadixTree> = std::sync::LazyLock::new(|| {
    let t = fs_iptree::RadixTree::new();
    for d in UNDELEGATED_DOMAINS {
        t.add(d);
    }
    t
});

/// firestack `isUndelegatedDomain` (`qname` normalized: no trailing dot, lowercase).
pub fn is_undelegated(qname: &str) -> bool {
    !qname.is_empty() && TRIE.has_any(qname)
}

const ARPA4: &str = "254.169.in-addr.arpa";
const ARPA6: &str = "e.f.ip6.arpa";
const LOCAL: &str = "local";

/// firestack `IsMDNSQuery`: `<svc>.local`, link-local reverse names (`…254.169.in-addr.arpa`, `…e.f.ip6.arpa`).
pub fn is_mdns_query(qname: &str) -> bool {
    if let Some(i) = qname.rfind(LOCAL)
        && i > 0
        && i == qname.len() - LOCAL.len()
    {
        return i > 1; // svc = qname[..i-1]
    }
    if let Some(i) = qname.rfind(ARPA4)
        && i > 0
    {
        return i > 1;
    }
    if let Some(i) = qname.rfind(ARPA6)
        && i > 0
    {
        return i > 3; // firestack slices qname[..i-3] (and panics below that)
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn special_use_names() {
        assert!(is_undelegated("router.lan"));
        // entries without a leading dot match only themselves (firestack RadixTree semantics)
        assert!(is_undelegated("168.192.in-addr.arpa"));
        assert!(!is_undelegated("1.168.192.in-addr.arpa"));
        assert!(is_undelegated("printer.home.arpa"));
        assert!(!is_undelegated("example.com"));
        assert!(!is_undelegated(""));
        assert!(is_mdns_query("printer.local"));
        assert!(is_mdns_query("4.3.254.169.in-addr.arpa"));
        assert!(is_mdns_query("1.0.0.0.a.e.f.ip6.arpa"));
        assert!(!is_mdns_query("local"));
        assert!(!is_mdns_query("example.com"));
    }
}
