// Copyright (c) 2026 RethinkReloaded contributors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Replays firestack's recorded results (engine/testdata/oracle/<PIN>, produced by tools/go-oracle/run.sh).
//! Operations where firestack itself panicked are skipped (engine/PARITY.md).

use fs_iptree::{IpTree, RadixTree};
use std::path::PathBuf;

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

fn b(v: bool) -> String {
    v.to_string()
}

#[test]
fn iptree_matches_firestack() {
    let mut t = IpTree::new();
    let (mut checked, mut mismatches) = (0, Vec::new());
    for (n, f) in fixture("iptree.tsv").iter().enumerate() {
        let (op, a1, a2, want, want_err) = (
            f[0].as_str(),
            f[1].as_str(),
            f[2].as_str(),
            f[3].as_str(),
            f[4] == "1",
        );
        let (got, got_err): (String, bool) = match op {
            "new" => {
                t = IpTree::new();
                continue;
            }
            "panic" => continue,
            "clear" => {
                t.clear();
                continue;
            }
            "add" => (String::new(), t.add(a1, a2).is_err()),
            "set" => (String::new(), t.set(a1, a2).is_err()),
            "esc" => (b(t.esc(a1, a2)), false),
            "del" => (b(t.del(a1)), false),
            "get" => t.get(a1).map_or((String::new(), true), |v| (v, false)),
            "has" => t.has(a1).map_or((String::new(), true), |v| (b(v), false)),
            "routes" => (t.routes(a1), false),
            "values" => (t.values(a1), false),
            "getAny" => t.get_any(a1).map_or((String::new(), true), |v| (v, false)),
            "hasAny" => t
                .has_any(a1)
                .map_or((String::new(), true), |v| (b(v), false)),
            "escLike" => (t.esc_like(a1, a2).to_string(), false),
            "routesLike" => (t.routes_like(a1, a2), false),
            "valuesLike" => (t.values_like(a1, a2), false),
            "getLike" => (t.get_like(a1, a2), false),
            "getAll" => t.get_all(a1).map_or((String::new(), true), |v| (v, false)),
            "delAll" => (t.del_all(a1).to_string(), false),
            "len" => (t.len().to_string(), false),
            other => panic!("unknown op {other}"),
        };
        // Go returns "" alongside errors; compare the error flag and the value
        let want = if want_err { "" } else { want };
        checked += 1;
        if got != want || got_err != want_err {
            mismatches.push(format!("line {}: {op}({a1:?}, {a2:?}) = {got:?} err={got_err}; firestack {want:?} err={want_err}", n + 1));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} of {checked} differ:\n{}",
        mismatches.len(),
        mismatches[..mismatches.len().min(25)].join("\n")
    );
    assert!(checked > 9000);
}

#[test]
fn radixtree_matches_firestack() {
    let mut t = RadixTree::new();
    let (mut checked, mut mismatches) = (0, Vec::new());
    for (n, f) in fixture("radixtree.tsv").iter().enumerate() {
        let (op, a1, a2, want) = (f[0].as_str(), f[1].as_str(), f[2].as_str(), f[3].as_str());
        let got = match op {
            "new" => {
                t = RadixTree::new();
                continue;
            }
            "getAnyPanics" | "hasAnyPanics" => continue,
            "add" => b(t.add(a1)),
            "set" => {
                t.set(a1, a2);
                String::new()
            }
            "del" => b(t.del(a1)),
            "get" => t.get(a1),
            "has" => b(t.has(a1)),
            "getAny" => t.get_any(a1),
            "hasAny" => b(t.has_any(a1)),
            "delAll" => t.del_all(a1).to_string(),
            "len" => t.len().to_string(),
            other => panic!("unknown op {other}"),
        };
        checked += 1;
        if got != want {
            mismatches.push(format!(
                "line {}: {op}({a1:?}, {a2:?}) = {got:?}; firestack {want:?}",
                n + 1
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} of {checked} differ:\n{}",
        mismatches.len(),
        mismatches[..mismatches.len().min(25)].join("\n")
    );
    assert!(checked > 7000);
}
