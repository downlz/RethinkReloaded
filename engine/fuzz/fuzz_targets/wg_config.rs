// Copyright (c) 2026 RethinkReloaded contributors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! WireGuard configs (Kotlin passes user-imported configs as UAPI-like text) and allowed-IP networks.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|s: &str| {
    let _ = fs_proxy::wg::config::parse("wgfuzz", s);
    for l in s.lines() {
        let _ = fs_proxy::wg::config::Net::parse(l);
    }
});
