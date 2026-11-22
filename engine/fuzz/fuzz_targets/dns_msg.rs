// Copyright (c) 2026 RethinkReloaded contributors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! DNS messages from the network (answers) and from apps (queries), and every transform the resolver applies.
#![no_main]
use fs_dns::msg;
use libfuzzer_sys::fuzz_target;
use std::net::IpAddr;

fuzz_target!(|data: &[u8]| {
    let Some(mut m) = msg::parse(data) else {
        return;
    };
    let _ = msg::pack(&m);
    let _ = msg::question(&m);
    let _ = (
        msg::has_do_bit(&m),
        msg::max_ttl(&m),
        msg::qname(&m),
        msg::qtype(&m),
        msg::has_answers(&m),
    );
    let _ = msg::interesting_rdata(Some(&m));
    let _ = (
        msg::answer_ips(&m),
        msg::a_answers(&m),
        msg::aaaa_answers(&m),
        msg::aquada_unspecified(&m),
    );
    let _ = (
        msg::ip_hints(&m, false),
        msg::ip_hints(&m, true),
        msg::targets(&m),
        msg::copy_ans(&m),
    );
    let _ = (
        msg::empty_response(&m),
        msg::refused_response(&m),
        msg::servfail(&m),
    );
    let _ = msg::normalize(&msg::qname(&m));
    let _ = fs_dns::ech::from_answer(&m);
    let v4: IpAddr = [192, 0, 2, 1].into();
    let v6: IpAddr = "2001:db8::1".parse().unwrap();
    let _ = msg::aquada_for_query(&m, 60, &[v4, v6]);
    let mut c = m.clone();
    msg::subst_addr_records(&mut c, v4, 30);
    msg::subst_svcb_hints(&mut c, true, v6, 30);
    msg::subst_svcb_hints(&mut c, false, v4, 30);
    msg::bust_android_cache(&mut c);
    let _ = msg::pack(&c);
    msg::add_padding_if_none(&mut m);
    let _ = msg::pack(&m);
});
