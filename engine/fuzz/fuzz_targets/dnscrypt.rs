// Copyright (c) 2026 RethinkReloaded contributors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! DNSCrypt: certificate TXT records (from the network) and responses/queries through the interceptor.
#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct In {
    pk: [u8; 32],
    records: Vec<Vec<u8>>,
    now: u32,
    ignore_ts: bool,
    msg: Vec<u8>,
}

fuzz_target!(|i: In| {
    let _ = fs_dns::dnscrypt::cert::pick(&i.pk, &i.records, i.now, i.ignore_ts);
    fs_dns::dnscrypt::fuzz::intercept(&i.msg);
});
