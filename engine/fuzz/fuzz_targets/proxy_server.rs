// Copyright (c) 2026 RethinkReloaded contributors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Local proxy servers (fs-rnet): HTTP request heads and SOCKS5 UDP headers from (local) clients.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fs_rnet::fuzz::socks_udp(data);
    fs_rnet::fuzz::http_head(data);
});
