// Copyright (c) 2026 RethinkReloaded contributors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! DNS64 through the resolver: an AAAA question for an IPv4-only name gets addresses synthesized under the local
//! 464 prefix (or the network's, once System reveals one), only while the PT mode allows it.

use fs_core::bridge::{AllowAllBridge, BoxFuture};
use fs_core::settings;
use fs_dns::msg;
use fs_dns::transport::{Answer, QueryError, Stats, TYPE_DNS53, Transport};
use fs_dnsx::resolver::Resolver;
use hickory_proto::rr::RecordType;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

/// An IPv4-only resolver: A for example.com, nothing for AAAA; ipv4only.arpa per `nat64`.
struct V4Only {
    id: &'static str,
    nat64: Option<&'static str>,
    stats: Stats,
}

impl Transport for V4Only {
    fn id(&self) -> &str {
        self.id
    }
    fn typ(&self) -> &str {
        TYPE_DNS53
    }
    fn addr(&self) -> String {
        "192.0.2.53:53".into()
    }
    fn status(&self) -> i32 {
        self.stats.status()
    }
    fn p50(&self) -> i64 {
        0
    }
    fn query(self: Arc<Self>, q: Vec<u8>, pid: String) -> BoxFuture<Result<Answer, QueryError>> {
        Box::pin(async move {
            let m = msg::parse(&q).unwrap();
            let r = match (msg::qname(&m).as_str(), msg::qtype(&m)) {
                ("ipv4only.arpa", 28) => match self.nat64 {
                    Some(ip) => msg::aquada_for_query(&m, 300, &[ip.parse().unwrap()]).unwrap(),
                    None => msg::empty_response(&m),
                },
                (_, 1) => {
                    msg::aquada_for_query(&m, 300, &["93.184.216.34".parse().unwrap()]).unwrap()
                }
                _ => msg::empty_response(&m),
            };
            self.stats.ok(std::time::Duration::from_millis(1));
            Ok(Answer {
                msg: msg::pack(&r).unwrap(),
                server: self.addr(),
                pid,
                ..Default::default()
            })
        })
    }
}

async fn aaaa(r: &Resolver) -> Vec<IpAddr> {
    aaaa_of(r, "example.com.").await
}

async fn aaaa_of(r: &Resolver, name: &str) -> Vec<IpAddr> {
    let q = msg::pack(&msg::query(name, RecordType::AAAA, 5).unwrap()).unwrap();
    let a = r.forward(&q, "tunnel", "f1", "10123").await.unwrap();
    msg::aaaa_answers(&msg::parse(&a).unwrap())
}

#[tokio::test]
async fn synthesizes_per_pt_mode() {
    let r = Resolver::new("10.111.222.3:53", Arc::new(AllowAllBridge));
    r.add(Arc::new(V4Only {
        id: "Preferred",
        nat64: None,
        stats: Stats::default(),
    }));

    settings::PT_MODE.store(settings::PT_MODE_NONE, Ordering::SeqCst);
    assert!(aaaa(&r).await.is_empty(), "off: no synthesis");

    settings::PT_MODE.store(settings::PT_MODE_AUTO, Ordering::SeqCst);
    r.natpt().set_has6(false);
    r.clear_cache();
    assert!(
        aaaa(&r).await.is_empty(),
        "auto on an IPv4-only network: no synthesis"
    );

    r.natpt().set_has6(true);
    r.clear_cache();
    assert_eq!(
        aaaa(&r).await,
        ["64:ff9b:1:fffe::5db8:d822".parse::<IpAddr>().unwrap()],
        "local 464 prefix"
    );

    // the network's NAT64 (RFC 7050 via System) takes over from the local prefix
    r.add(Arc::new(V4Only {
        id: "System",
        nat64: Some("64:ff9b::c000:aa"),
        stats: Stats::default(),
    }));
    assert!(r.discover64("System").await);
    // (a new name: the gateway keeps answers it registered for their TTL)
    assert_eq!(
        aaaa_of(&r, "example.net.").await,
        ["64:ff9b::5db8:d822".parse::<IpAddr>().unwrap()],
        "underlay prefix"
    );
    settings::PT_MODE.store(settings::PT_MODE_NONE, Ordering::SeqCst);
}
