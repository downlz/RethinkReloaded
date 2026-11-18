// Copyright (c) 2026 RethinkReloaded contributors. SPDX-License-Identifier: MPL-2.0
//! Replays firestack's WgKey results (engine/testdata/oracle/<PIN>/wgkey.tsv).

use fs_wg::WgKey;
use std::path::PathBuf;

#[test]
fn wgkey_matches_firestack() {
    let engine = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let pin = std::fs::read_to_string(engine.join("api/PIN")).unwrap();
    let s = std::fs::read_to_string(
        engine
            .join("testdata/oracle")
            .join(pin.trim())
            .join("wgkey.tsv"),
    )
    .unwrap();
    let mut n = 0;
    for l in s.lines() {
        let f: Vec<&str> = l.split('\t').collect();
        let input = f[1].replace("\\n", "\n");
        let got = WgKey::from_base64(&input).map(|k| {
            format!(
                "{}|{}|{}|{}",
                k.hex(),
                k.base64(),
                k.is_zero(),
                k.mult().hex()
            )
        });
        match (f[4], got) {
            ("1", Err(_)) => {}
            ("0", Ok(g)) => assert_eq!(g, f[3], "input {input:?}"),
            (e, g) => panic!("input {input:?}: firestack err={e}, rust {g:?}"),
        }
        n += 1;
    }
    assert!(n > 60);
}
