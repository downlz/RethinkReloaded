// Copyright (c) 2026 RethinkReloaded contributors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! ODoH against the app's preset targets (network; `cargo test -p fs-dns --test odoh_live -- --ignored`).

use fs_core::bridge::AllowAllBridge;
use fs_dialers::{Protector, SharedDial};
use fs_dns::msg;
use fs_dns::odoh::OdohTransport;
use fs_dns::transport::Transport;
use hickory_proto::rr::RecordType;
use std::net::IpAddr;
use std::sync::Arc;

fn dialer() -> SharedDial {
    Arc::new(Protector::new(Arc::new(AllowAllBridge)))
}

fn system_resolver() -> fs_dns::doh::HostResolver {
    Arc::new(|h: String| {
        Box::pin(async move {
            tokio::net::lookup_host((h.as_str(), 443))
                .await
                .map(|it| it.map(|a| a.ip()).collect::<Vec<IpAddr>>())
                .unwrap_or_default()
        })
    })
}

async fn ask(t: Arc<OdohTransport>, name: &str) -> usize {
    let q = msg::pack(&msg::query(name, RecordType::A, 0x77).unwrap()).unwrap();
    let a = t
        .query(q, "Base".into())
        .await
        .unwrap_or_else(|e| panic!("{name}: {e:?}"));
    let m = msg::parse(&a.msg).unwrap();
    assert_eq!(m.metadata.id, 0x77);
    msg::a_answers(&m).len()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn cloudflare_target() {
    let t = Arc::new(
        OdohTransport::new(
            "odoh",
            "",
            "https://odoh.cloudflare-dns.com/dns-query",
            vec![],
            dialer(),
            Some(system_resolver()),
        )
        .unwrap(),
    );
    assert_eq!(
        (t.typ(), t.addr().as_str()),
        ("Oblivious DNS-over-HTTPS", "odoh.cloudflare-dns.com")
    );
    assert!(ask(t.clone(), "example.com.").await > 0);
    assert!(ask(t, "example.org.").await > 0, "cached config");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn crypto_sx_target() {
    let t = Arc::new(
        OdohTransport::new(
            "odoh2",
            "",
            "https://odoh.crypto.sx/dns-query",
            vec![],
            dialer(),
            Some(system_resolver()),
        )
        .unwrap(),
    );
    assert!(ask(t, "example.com.").await > 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn through_a_relay() {
    let t = Arc::new(
        OdohTransport::new(
            "odoh3",
            "https://odoh-relay.edgecompute.app/proxy",
            "https://odoh.cloudflare-dns.com/dns-query",
            vec![],
            dialer(),
            Some(system_resolver()),
        )
        .unwrap(),
    );
    assert_eq!(
        t.addr(),
        "odoh-relay.edgecompute.app>odoh.cloudflare-dns.com"
    );
    assert!(ask(t, "example.com.").await > 0);
}
