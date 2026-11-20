// Copyright (c) 2026 RethinkReloaded contributors. SPDX-License-Identifier: MPL-2.0
//! Live network tests (ignored by default): `cargo test -p fs-dns --test live -- --ignored`

use fs_core::bridge::AllowAllBridge;
use fs_dialers::Protector;
use fs_dns::dns53::Dns53Transport;
use fs_dns::doh::DohTransport;
use fs_dns::msg;
use fs_dns::transport::Transport;
use hickory_proto::rr::RecordType;
use std::sync::Arc;

fn protector() -> Protector {
    Protector::new(Arc::new(AllowAllBridge))
}

#[tokio::test]
#[ignore]
async fn doh_cloudflare() {
    let t = Arc::new(
        DohTransport::new(
            "Preferred",
            "https://cloudflare-dns.com/dns-query",
            vec!["1.1.1.1".parse().unwrap()],
            protector(),
            None,
        )
        .unwrap(),
    );
    for name in ["example.com.", "wikipedia.org."] {
        let q = msg::pack(&msg::query(name, RecordType::A, 0xbeef).unwrap()).unwrap();
        let a = t.query(q, "Exit".into()).await.expect("doh answer");
        let m = msg::parse(&a.msg).unwrap();
        assert_eq!(m.id(), 0xbeef, "query id restored");
        assert!(
            !msg::answer_ips(&m).is_empty(),
            "{name}: {:?}",
            msg::interesting_rdata(Some(&m))
        );
        println!(
            "{name} -> {} in {:?} via {}",
            msg::interesting_rdata(Some(&m)),
            a.latency,
            a.server
        );
    }
    assert_eq!(t.status(), fs_core::bridge::dns_status::COMPLETE);
}

#[tokio::test]
#[ignore]
async fn dns53_cloudflare() {
    let t = Arc::new(Dns53Transport::new(
        "System",
        Dns53Transport::parse_servers("1.1.1.1"),
        protector(),
    ));
    let q = msg::pack(&msg::query("example.com.", RecordType::AAAA, 7).unwrap()).unwrap();
    let a = t.query(q, "Exit".into()).await.expect("dns53 answer");
    let m = msg::parse(&a.msg).unwrap();
    println!(
        "AAAA example.com -> {} in {:?}",
        msg::interesting_rdata(Some(&m)),
        a.latency
    );
    assert_eq!(m.id(), 7);
}
