// Copyright (c) 2026 RethinkReloaded contributors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Replays firestack's recorded blocklist results (engine/testdata/oracle/<PIN>/rdns*.tsv, from
//! tools/go-oracle/run.sh). Operations where firestack itself panicked (err = p) are skipped.
//!
//! rdns.tsv needs only the committed filetag (rdns-filetag.json). rdnstrie.tsv needs the full on-device trie the
//! fixture was recorded with (about 180 MB, not committed): set RR_BLOCKLIST_DIR to a directory holding td.txt,
//! rd.txt, basicconfig.json and filetag.json downloaded from dl.rethinkdns.com (see engine/PARITY.md).

use fs_blocklist::RdnsLocal;
use fs_blocklist::stamp::{Mode, Rdns};
use std::path::PathBuf;

fn oracle_dir() -> PathBuf {
    let engine = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let pin = std::fs::read_to_string(engine.join("api/PIN")).unwrap();
    engine.join("testdata/oracle").join(pin.trim())
}

fn fixture(name: &str) -> Vec<Vec<String>> {
    let p = oracle_dir().join(name);
    let s = std::fs::read_to_string(&p)
        .unwrap_or_else(|e| panic!("{}: {e} (run tools/go-oracle/run.sh)", p.display()));
    s.lines()
        .map(|l| l.split('\t').map(String::from).collect())
        .collect()
}

fn res(r: Result<String, String>) -> (String, String) {
    match r {
        Ok(s) => (s, "0".into()),
        Err(_) => (String::new(), "1".into()),
    }
}

fn report(what: &str, checked: usize, mismatches: &[String]) {
    assert!(
        mismatches.is_empty(),
        "{what}: {} of {checked} differ from firestack:\n{}",
        mismatches.len(),
        mismatches
            .iter()
            .take(20)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
    eprintln!("{what}: {checked} operations match firestack");
}

#[test]
fn stamps_match_firestack() {
    let r = Rdns::from_filetag(&oracle_dir().join("rdns-filetag.json"), Mode::Local).unwrap();
    let (mut checked, mut mism) = (0, Vec::new());
    for (n, f) in fixture("rdns.tsv").iter().enumerate() {
        let (op, a1, a2, want, werr) = (&f[0], &f[1], &f[2], &f[3], &f[4]);
        if werr == "p" {
            continue;
        }
        let got = match op.as_str() {
            "flagsToStamp" => res(r.flags_to_stamp(a1, a2.parse().unwrap())),
            "stampToFlags" => res(r.stamp_to_flags(a1)),
            "stampToNames" => res(r.stamp_to_names(a1)),
            "setStamp" => res(r.set_stamp(a1).and_then(|_| r.get_stamp())),
            o => panic!("unknown op {o}"),
        };
        checked += 1;
        if (got.0.as_str(), got.1.as_str()) != (want.as_str(), werr.as_str()) {
            mism.push(format!(
                "{}: {op}({a1:?}, {a2}) = {got:?}, want ({want:?}, {werr})",
                n + 1
            ));
        }
    }
    report("rdns stamps", checked, &mism);
}

fn fqdn(d: &str) -> String {
    if d.ends_with('.') {
        d.to_string()
    } else {
        format!("{d}.")
    }
}

#[test]
fn trie_matches_firestack() {
    let Some(dir) = std::env::var_os("RR_BLOCKLIST_DIR").map(PathBuf::from) else {
        eprintln!("skipped: RR_BLOCKLIST_DIR not set");
        return;
    };
    let fx = fixture("rdnstrie.tsv");
    let bc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("basicconfig.json")).unwrap()).unwrap();
    assert_eq!(fx[0][0], "trie");
    if bc["tdmd5"].as_str() != Some(fx[0][1].as_str()) {
        eprintln!(
            "skipped: RR_BLOCKLIST_DIR holds another trie than the fixture ({})",
            fx[0][1]
        );
        return;
    }
    let j = |n: &str| dir.join(n).to_string_lossy().into_owned();
    let t0 = std::time::Instant::now();
    let rl = RdnsLocal::new(
        &j("td.txt"),
        &j("rd.txt"),
        &j("basicconfig.json"),
        &j("filetag.json"),
    )
    .unwrap();
    eprintln!("trie loaded in {:?}", t0.elapsed());
    let (mut checked, mut mism) = (0, Vec::new());
    let mut stamp_ok = false;
    for (n, f) in fx.iter().enumerate().skip(1) {
        let (op, a1, a2, want, werr) = (&f[0], &f[1], &f[2], &f[3], &f[4]);
        if werr == "p" {
            continue;
        }
        let got: (String, String) = match op.as_str() {
            "lookup" => {
                let w: Vec<u8> = a1.bytes().rev().collect();
                let (ok, v) = rl.trie.lookup(&w);
                let v: Vec<String> = v.iter().map(|x| x.to_string()).collect();
                (format!("{ok}:{}", v.join(",")), "0".into())
            }
            "stamp" => {
                let r = rl.rdns.set_stamp(a1);
                stamp_ok = r.is_ok();
                (
                    if r.is_ok() {
                        want.clone()
                    } else {
                        String::new()
                    },
                    if r.is_ok() { "0" } else { "1" }.into(),
                )
            }
            "blockQuery" => {
                assert!(stamp_ok);
                res(rl.block_query(&[fqdn(a1)], a2.parse().unwrap()))
            }
            "blockAnswer" => match rl.block_answer("cloak.example.", 1, &[fqdn(a1)]) {
                Ok((t, l)) => (format!("{t}|{l}"), "0".into()),
                Err(_) => ("|".into(), "1".into()),
            },
            o => panic!("unknown op {o}"),
        };
        checked += 1;
        if (got.0.as_str(), got.1.as_str()) != (want.as_str(), werr.as_str()) {
            mism.push(format!(
                "{}: {op}({a1:?}, {a2}) = {got:?}, want ({want:?}, {werr})",
                n + 1
            ));
        }
    }
    report("rdns trie", checked, &mism);
}
