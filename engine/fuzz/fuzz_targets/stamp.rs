// Copyright (c) 2026 RethinkReloaded contributors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! DNS stamps (sdns://) from Kotlin's resolver lists and user input; NAT64 prefixes and tid lists.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|s: &str| {
    let _ = fs_dns::stamp::Stamp::parse(s);
    let _ = fs_dns::stamp::Stamp::parse(&format!("sdns://{s}"));
    let _ = fs_dnsx::x64::Prefix::parse(s);
});
