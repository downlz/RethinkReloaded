// Copyright (c) 2026 RethinkReloaded contributors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! DNSCrypt against public resolvers (network; `cargo test -p fs-dns --test dnscrypt_live -- --ignored`).

use fs_core::bridge::AllowAllBridge;
use fs_dialers::{Protector, SharedDial};
use fs_dns::dnscrypt::DcMulti;
use fs_dns::msg;
use fs_dns::transport::Transport;
use hickory_proto::rr::RecordType;
use std::sync::Arc;

/// AdGuard (94.140.14.14:5443) and OpenDNS (208.67.220.220:443), from the public dnscrypt-resolvers list
const ADGUARD: &str = "sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20";
const OPENDNS: &str = "sdns://AQAAAAAAAAAADjIwOC42Ny4yMjAuMjIwILc1EUAgbyJdPivYItf9aR6hwzzI1maNDL4Ev6vKQ_t5GzIuZG5zY3J5cHQtY2VydC5vcGVuZG5zLmNvbQ";

fn dialer() -> SharedDial {
    Arc::new(Protector::new(Arc::new(AllowAllBridge)))
}

async fn ask(t: &Arc<dyn Transport>, name: &str) -> (u16, usize, String) {
    let q = msg::pack(&msg::query(name, RecordType::A, 0x4242).unwrap()).unwrap();
    let a = t
        .clone()
        .query(q, "Base".into())
        .await
        .unwrap_or_else(|e| panic!("{name}: {e:?}"));
    let m = msg::parse(&a.msg).unwrap();
    (m.metadata.id, msg::a_answers(&m).len(), a.pid)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn public_resolvers() {
    let dc = DcMulti::new(dialer());
    let t: Arc<dyn Transport> = dc.add("dc1", ADGUARD).await.unwrap();
    assert_eq!(
        (t.typ(), t.addr().as_str()),
        ("DNSCrypt", "2.dnscrypt.default.ns1.adguard.com")
    );
    let (id, n, pid) = ask(&t, "example.com.").await;
    assert!(id == 0x4242 && n > 0, "id {id:x} answers {n}");
    assert_eq!(pid, "Base");
    let t2: Arc<dyn Transport> = dc.add("dc2", OPENDNS).await.unwrap();
    let (_, n, _) = ask(&t2, "example.org.").await;
    assert!(n > 0);
    let mut live = dc.live();
    live.sort();
    assert_eq!(live, ["dc1", "dc2"]);
    assert!(dc.remove("dc2"));
    assert!(dc.add("bad", "sdns://AQcAAAAAAAAA").await.is_err());
    assert!(dc.remove("dc1") && dc.live().is_empty());
}

/// A minimal anonymizing relay on loopback: checks and strips the relay header, forwards to the server it names.
async fn local_relay() -> std::net::SocketAddr {
    let u = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a = u.local_addr().unwrap();
    tokio::spawn(async move {
        let mut b = vec![0u8; 8192];
        while let Ok((n, from)) = u.recv_from(&mut b).await {
            let p = b[..n].to_vec();
            assert_eq!(
                &p[..10],
                &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0]
            );
            let ip: [u8; 16] = p[10..26].try_into().unwrap();
            let ip = std::net::Ipv6Addr::from(ip).to_canonical();
            let to = std::net::SocketAddr::new(ip, u16::from_be_bytes([p[26], p[27]]));
            let up = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
            up.send_to(&p[28..], to).await.unwrap();
            let mut r = vec![0u8; 8192];
            if let Ok(Ok((m, _))) =
                tokio::time::timeout(std::time::Duration::from_secs(5), up.recv_from(&mut r)).await
            {
                let _ = u.send_to(&r[..m], from).await;
            }
        }
    });
    a
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn through_a_relay() {
    let dc = DcMulti::new(dialer());
    let t: Arc<dyn Transport> = dc.add("dc1", ADGUARD).await.unwrap();
    let relay = local_relay().await;
    dc.add_relay(&relay.to_string()).unwrap();
    assert!(dc.has_relay(&relay.to_string()));
    let (_, n, pid) = ask(&t, "example.com.").await;
    assert!(n > 0);
    assert_eq!(pid, relay.to_string(), "the relay is reported as the pid");
    assert!(dc.remove(&relay.to_string()));
    let (_, _, pid) = ask(&t, "example.net.").await;
    assert_eq!(pid, "Base", "direct again");
}
