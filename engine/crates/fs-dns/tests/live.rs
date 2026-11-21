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

fn protector() -> fs_dialers::SharedDial {
    Arc::new(Protector::new(Arc::new(AllowAllBridge)))
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
        let a = t.clone().query(q, "Exit".into()).await.expect("doh answer");
        let m = msg::parse(&a.msg).unwrap();
        assert_eq!(m.metadata.id, 0xbeef, "query id restored");
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
    let a = t
        .clone()
        .query(q, "Exit".into())
        .await
        .expect("dns53 answer");
    let m = msg::parse(&a.msg).unwrap();
    println!(
        "AAAA example.com -> {} in {:?}",
        msg::interesting_rdata(Some(&m)),
        a.latency
    );
    assert_eq!(m.metadata.id, 7);
}

#[tokio::test]
#[ignore]
async fn dot_cloudflare() {
    let t = Arc::new(
        fs_dns::dot::DotTransport::new(
            "Plus2dot",
            "tls://one.one.one.one",
            vec!["1.1.1.1".parse().unwrap()],
            protector(),
            None,
        )
        .unwrap(),
    );
    let q = msg::pack(&msg::query("example.org.", RecordType::A, 0x77).unwrap()).unwrap();
    let a = t.clone().query(q, "Exit".into()).await.expect("dot answer");
    let m = msg::parse(&a.msg).unwrap();
    println!(
        "DoT example.org -> {} in {:?}",
        msg::interesting_rdata(Some(&m)),
        a.latency
    );
    assert_eq!(m.metadata.id, 0x77);
    assert!(!msg::answer_ips(&m).is_empty());
}

/// `http://` DoH skips certificate checks (firestack's insecure resolvers): `dns.google` pointed at Cloudflare's
/// address fails verification over https, and works over http.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn insecure_doh_and_dot() {
    let q = || msg::pack(&msg::query("example.com.", RecordType::A, 9).unwrap()).unwrap();
    let cf: Vec<std::net::IpAddr> = vec!["1.1.1.1".parse().unwrap()];
    let secure = Arc::new(
        DohTransport::new(
            "s",
            "https://dns.google/dns-query",
            cf.clone(),
            protector(),
            None,
        )
        .unwrap(),
    );
    assert!(
        secure.query(q(), "Base".into()).await.is_err(),
        "certificate mismatch must fail"
    );
    let insecure = Arc::new(
        DohTransport::new(
            "i",
            "http://dns.google/dns-query",
            cf.clone(),
            protector(),
            None,
        )
        .unwrap(),
    );
    // past TLS: Cloudflare answers (or refuses the foreign Host with an HTTP status), no certificate error
    if let Err(e) = insecure.query(q(), "Base".into()).await {
        assert!(e.msg.starts_with("doh: http"), "{e:?}");
    }

    let dot_secure = Arc::new(
        fs_dns::dot::DotTransport::new("ds", "tls://dns.google", cf.clone(), protector(), None)
            .unwrap(),
    );
    assert!(dot_secure.query(q(), "Base".into()).await.is_err());
    let dot_insecure = Arc::new(
        fs_dns::dot::DotTransport::new("di", "dns.google", cf, protector(), None).unwrap(),
    );
    assert!(dot_insecure.query(q(), "Base".into()).await.is_ok());
}
