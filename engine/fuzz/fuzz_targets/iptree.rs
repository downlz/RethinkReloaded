// Copyright (c) 2026 RethinkReloaded contributors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! IpTree operation sequences (Kotlin's IP rules) on arbitrary CIDR strings: none may panic, and a value set on a
//! parsable CIDR reads back.
#![no_main]
use arbitrary::Arbitrary;
use fs_iptree::iptree::IpTree;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum Op {
    Set(String, String),
    Del(String),
    Get(String),
    Routes(String),
    Values(String),
    GetAny(String),
    EscLike(String, String),
    GetLike(String, String),
    DelAll(String),
    Clear,
}

fuzz_target!(|ops: Vec<Op>| {
    let t = IpTree::new();
    for op in ops.into_iter().take(64) {
        match op {
            Op::Set(c, v) => {
                if t.set(&c, &v).is_ok() && !v.is_empty() && !v.contains(['|', ',', ':']) {
                    assert!(t.get(&c).is_ok(), "set {c:?} then get");
                }
            }
            Op::Del(c) => {
                t.del(&c);
            }
            Op::Get(c) => {
                let _ = t.get(&c);
            }
            Op::Routes(c) => {
                let _ = t.routes(&c);
            }
            Op::Values(c) => {
                let _ = t.values(&c);
            }
            Op::GetAny(c) => {
                let _ = (t.get_any(&c), t.has_any(&c), t.get_all(&c));
            }
            Op::EscLike(c, l) => {
                let _ = t.esc_like(&c, &l);
            }
            Op::GetLike(c, l) => {
                let _ = (
                    t.get_like(&c, &l),
                    t.routes_like(&c, &l),
                    t.values_like(&c, &l),
                );
            }
            Op::DelAll(c) => {
                let _ = t.del_all(&c);
            }
            Op::Clear => {
                t.clear();
            }
        }
    }
});
