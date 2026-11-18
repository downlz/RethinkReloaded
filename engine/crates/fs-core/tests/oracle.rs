// Copyright (c) 2026 RethinkReloaded contributors. SPDX-License-Identifier: MPL-2.0
//! Replays firestack's settings results (engine/testdata/oracle/<PIN>/settings.tsv). Single test: the
//! settings are process-wide globals and the recorded sequence is order-dependent.

use fs_core::settings as s;
use std::path::PathBuf;

#[test]
fn settings_match_firestack() {
    let engine = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let pin = std::fs::read_to_string(engine.join("api/PIN")).unwrap();
    let data = std::fs::read_to_string(
        engine
            .join("testdata/oracle")
            .join(pin.trim())
            .join("settings.tsv"),
    )
    .unwrap();
    for l in data.lines() {
        let f: Vec<&str> = l.split('\t').collect();
        let got = match f[0] {
            "mode2String" => s::mode2string(f[1], f[2].parse().unwrap()),
            "l3" => s::l3(f[1].parse().unwrap()).to_string(),
            "engine" => s::engine(f[1]).to_string(),
            "setDialerOpts" => {
                let a: Vec<i32> = f[1].split(',').map(|x| x.parse().unwrap()).collect();
                let ok = s::set_dialer_opts(a[0], a[1], a[2], a[3], a[4] == 1);
                format!("{ok}|{}", s::dialer_opts())
            }
            "setAutoMode" => {
                let prev = s::set_auto_mode(f[1].parse().unwrap());
                format!(
                    "{prev}|{}|{}|{}",
                    s::auto_mode_str(),
                    s::auto_active(),
                    s::auto_always_remote()
                )
            }
            o => panic!("unknown op {o}"),
        };
        assert_eq!(got, f[3], "{l}");
    }
}
