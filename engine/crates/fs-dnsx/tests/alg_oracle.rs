// Copyright (c) 2026 RethinkReloaded contributors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Replays firestack's recorded DNS gateway (ALG) sequences (engine/testdata/oracle/<PIN>/alg.tsv, from
//! tools/go-oracle/run.sh): address generation, registrations, translate/split, transport stops, X, PTR, RDNSBL
//! and resolv. Address and name lists compare as sorted sets (their order only feeds dialing, which shuffles).

use fs_dnsx::alg::{Gateway, IpType, SecAns, gen4, gen6};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

fn fixture(name: &str) -> Vec<Vec<String>> {
    let engine = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let pin = std::fs::read_to_string(engine.join("api/PIN")).unwrap();
    let p = engine.join("testdata/oracle").join(pin.trim()).join(name);
    let s = std::fs::read_to_string(&p)
        .unwrap_or_else(|e| panic!("{}: {e} (run tools/go-oracle/run.sh)", p.display()));
    s.lines()
        .map(|l| l.split('\t').map(String::from).collect())
        .collect()
}

fn ips(csv: &str) -> Vec<IpAddr> {
    csv.split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.parse().unwrap())
        .collect()
}

fn sorted(v: &[IpAddr]) -> String {
    let mut s: Vec<String> = v.iter().map(|i| i.to_string()).collect();
    s.sort();
    s.join(",")
}

fn sorted_csv(csv: &str) -> String {
    let mut s: Vec<&str> = csv.split(',').filter(|s| !s.is_empty()).collect();
    s.sort();
    s.join(",")
}

/// Go prints an invalid netip.Addr as "invalid IP"
fn ipstr(ip: Option<IpAddr>) -> String {
    ip.map(|i| i.to_string())
        .unwrap_or_else(|| "invalid IP".into())
}

#[test]
fn gateway_matches_firestack() {
    let g = Gateway::new(vec!["10.111.222.3:53".parse().unwrap()]);
    let (mut checked, mut mism) = (0, Vec::new());
    for (n, f) in fixture("alg.tsv").iter().enumerate() {
        let (op, a1, a2, want) = (f[0].as_str(), f[1].as_str(), f[2].as_str(), f[3].as_str());
        let got: String = match op {
            "gen4" => gen4(a1, a2.parse().unwrap()).to_string(),
            "gen6" => gen6(a1, a2.parse().unwrap()).to_string(),
            "tr" => {
                g.translate(a1 == "true", a2 == "true");
                String::new()
            }
            "split" => {
                g.split_tunnel();
                String::new()
            }
            "stop" => {
                g.on_stopped(a1);
                String::new()
            }
            "reg" => {
                let p: Vec<&str> = a1.split('|').collect();
                let (d, tid, uid, real, sec) = (p[0], p[1], p[2], ips(p[3]), ips(p[4]));
                let ttl = Duration::from_secs(p[5].parse().unwrap());
                let targets: Vec<String> = p[6].split(',').map(String::from).collect();
                let sa = SecAns {
                    ips: sec,
                    blocklists: p[7].to_string(),
                    ..Default::default()
                };
                let (a4, a6, ok) = g.with_state(|t| {
                    let a4 = if real.iter().any(|i| i.is_ipv4()) {
                        t.take4(d)
                    } else {
                        None
                    };
                    let a6 = if real.iter().any(|i| i.is_ipv6()) {
                        t.take6(d)
                    } else {
                        None
                    };
                    let ok = t.register(d, tid, uid, a4, a6, &real, ttl, &targets, &sa);
                    (a4, a6, ok)
                });
                format!("{}|{}|{ok}", ipstr(a4), ipstr(a6))
            }
            "x" => {
                let (ip, uid) = a1.split_once('|').unwrap();
                let tids: Vec<&str> = a2.split(',').filter(|s| !s.is_empty()).collect();
                let (r, undid) = g.x(ip.parse().unwrap(), uid, &tids);
                format!("{}|{undid}", sorted(&r))
            }
            "ptr" => {
                let (ip, uid) = a1.split_once('|').unwrap();
                let (d, useptr) = g.ptr(ip.parse().unwrap(), uid, "", a2 == "true");
                format!("{}|{useptr}", sorted_csv(&d))
            }
            "bl" => g.rdnsbl(a1.parse().unwrap()),
            "resolv" => {
                let p: Vec<&str> = a1.split('|').collect();
                let typ = match a2 {
                    "0" => IpType::Alg,
                    "1" => IpType::Real,
                    _ => IpType::Secondary,
                };
                let (i4, i6, _) = g.resolv(p[0], typ, p[1], p[2]);
                format!("{}|{}", sorted(&i4), sorted(&i6))
            }
            o => panic!("unknown op {o}"),
        };
        checked += 1;
        if got != want {
            mism.push(format!(
                "{}: {op}({a1}, {a2}) = {got:?}, want {want:?}",
                n + 1
            ));
        }
    }
    assert!(
        mism.is_empty(),
        "{} of {checked} differ from firestack:\n{}",
        mism.len(),
        mism.iter().take(25).cloned().collect::<Vec<_>>().join("\n")
    );
    eprintln!("alg: {checked} operations match firestack");
}
