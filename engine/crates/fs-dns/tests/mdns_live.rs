// Copyright (c) 2026 RethinkReloaded contributors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! mDNS one-shot queries against a real LAN responder (network). Name a host that answers mDNS, e.g. a Mac's
//! `<LocalHostName>.local`:
//!   RR_MDNS_NAME=host.local cargo test -p fs-dns --test mdns_live -- --ignored --nocapture
//! On a phone: build with `cargo ndk -t arm64-v8a test --no-run`, push the binary, run it with no VPN active.

use fs_core::bridge::AllowAllBridge;
use fs_dialers::Protector;
use fs_dns::mdns::MdnsTransport;
use fs_dns::msg;
use fs_dns::transport::Transport;
use hickory_proto::rr::RecordType;
use std::sync::Arc;

#[tokio::test]
#[ignore]
async fn resolves_a_lan_host() {
    let Ok(name) = std::env::var("RR_MDNS_NAME") else {
        return;
    };
    let t = Arc::new(MdnsTransport::new(Arc::new(Protector::new(Arc::new(AllowAllBridge)))));
    t.refresh_proto("4");
    let q = msg::pack(&msg::query(&format!("{name}."), RecordType::A, 0x6d64).unwrap()).unwrap();
    let a = t.query(q, "Base".into()).await.expect("an mDNS answer");
    let m = msg::parse(&a.msg).unwrap();
    assert_eq!(m.metadata.id, 0x6d64, "the app's id");
    let ips = msg::a_answers(&m);
    assert!(!ips.is_empty(), "no A record");
    println!("answered in {:?}; {} address(es)", a.latency, ips.len());
}
