// Copyright (c) 2026 RethinkReloaded contributors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Replays testdata/oracle/<pin>/x64.tsv (firestack's dns64.add, x64 ip4to6 / ip6to4, xdns.MaybeToQuadA).

use fs_dnsx::x64::{self, Prefix};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Go prints IPv4-mapped IPv6 addresses as dotted IPv4; compare by value.
fn same(go: &str, ip: Option<IpAddr>) -> bool {
    match (go, ip) {
        ("<nil>", None) => true,
        (s, Some(ip)) => s
            .parse::<IpAddr>()
            .map(|g| g.to_canonical() == ip.to_canonical())
            .unwrap_or(false),
        _ => false,
    }
}

#[test]
#[allow(clippy::unnecessary_min_or_max)] // ANS_TTL is 0 in this build
fn replays_firestack() {
    let pin = include_str!("../../../api/PIN").trim();
    let path = format!(
        "{}/../../testdata/oracle/{pin}/x64.tsv",
        env!("CARGO_MANIFEST_DIR")
    );
    let data = std::fs::read_to_string(&path).expect("x64.tsv (tools/go-oracle/run.sh)");
    let mut n = 0;
    for (ln, line) in data.lines().enumerate() {
        let f: Vec<&str> = line.split('\t').collect();
        let ctx = format!("line {}: {line}", ln + 1);
        match f[0] {
            "prefix" => {
                let ips: Vec<Ipv6Addr> = f[1]
                    .split(',')
                    .map(|s| match s.parse::<IpAddr>().unwrap() {
                        IpAddr::V6(v6) => v6,
                        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
                    })
                    .collect();
                let got: Vec<String> = x64::prefixes_of(&ips)
                    .iter()
                    .map(|p| p.to_string())
                    .collect();
                let want: Vec<Prefix> = f[2]
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(|s| Prefix::parse(s).unwrap())
                    .collect();
                assert_eq!(
                    got,
                    want.iter().map(|p| p.to_string()).collect::<Vec<_>>(),
                    "{ctx}"
                );
                assert_eq!(f[3] == "true", want.is_empty(), "{ctx}");
            }
            "x46" => {
                let p = Prefix::parse(f[1]).unwrap();
                let ip4: Ipv4Addr = f[2].parse().unwrap();
                assert!(same(f[3], x64::x46(&p, ip4).map(IpAddr::V6)), "x46 {ctx}");
                let ttl: u32 = f[4].parse().unwrap();
                let s = x64::synth6(&p, ip4);
                let synth = if s.is_unspecified() {
                    "nil".to_string()
                } else {
                    format!("{}|{}", s, ttl.max(fs_dns::msg::ANS_TTL))
                };
                match f[5].split_once('|') {
                    None => assert_eq!(synth, "nil", "synth {ctx}"),
                    Some((ip, t)) => {
                        assert!(same(ip, Some(IpAddr::V6(s))), "synth {ctx}");
                        assert_eq!(
                            t,
                            ttl.max(fs_dns::msg::ANS_TTL).to_string(),
                            "synth ttl {ctx}"
                        );
                    }
                }
            }
            "x64" => {
                let p = Prefix::parse(f[1]).unwrap();
                let ip6 = match f[2].parse::<IpAddr>().unwrap() {
                    IpAddr::V6(v6) => v6,
                    IpAddr::V4(v4) => v4.to_ipv6_mapped(),
                };
                assert!(same(f[3], x64::x64(&p, ip6).map(IpAddr::V4)), "x64 {ctx}");
            }
            op => panic!("unknown op {op}"),
        }
        n += 1;
    }
    assert!(n > 500, "{n}");
}
