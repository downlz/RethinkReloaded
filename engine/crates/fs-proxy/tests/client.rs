// Copyright (c) 2026 RethinkReloaded contributors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! `Proxy.client()` IP metadata: provider fallback, status/route gating and the cache, against loopback servers;
//! and the real providers over Exit (network; `cargo test -p fs-proxy --test client -- --ignored`).

use fs_core::bridge::AllowAllBridge;
use fs_dialers::Protector;
use fs_proxy::client::{Providers, client};
use fs_proxy::{Proxifier, SharedProxy};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn px() -> Arc<Proxifier> {
    let b = Arc::new(AllowAllBridge);
    Proxifier::new("46", 1500, Protector::new(b.clone()), b)
}

/// Serves `/ip` with a 500 (so the client falls through), `/trace` as Cloudflare does (chunked), anything else 404.
async fn providers(hits: Arc<AtomicUsize>) -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let hits = hits.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut b = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if s.read(&mut b).await.unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(b[0]);
                }
                let h = String::from_utf8(head).unwrap();
                let path = h.split_whitespace().nth(1).unwrap_or("").to_string();
                let r = match path.as_str() {
                    "/ip" => "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n"
                        .to_string(),
                    "/trace" => {
                        hits.fetch_add(1, Ordering::Relaxed);
                        let body = "fl=1\nip=198.51.100.7\nloc=nz\n";
                        format!(
                            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n",
                            body.len()
                        )
                    }
                    _ => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_string(),
                };
                let _ = s.write_all(r.as_bytes()).await;
            });
        }
    });
    a
}

#[tokio::test]
async fn falls_back_and_caches() {
    let hits = Arc::new(AtomicUsize::new(0));
    let a = providers(hits.clone()).await;
    let base = format!("http://{a}");
    *client().providers.write() = Providers {
        ipinfo: format!("{base}/ip"),
        trace: format!("{base}/trace"),
        warp: format!("{base}/warp"),
        mullvad4: format!("{base}/m4"),
        mullvad6: format!("{base}/m6"),
    };
    let px = px();
    let exit: SharedProxy = px.proxy_for("Exit").unwrap();

    let e = client().ip_metadata(exit.clone(), false).await.unwrap_err();
    assert_eq!(
        e, "proxy: not active",
        "no dial yet (firestack: TOK/TKO only)"
    );

    drop(exit.dial_tcp(a, Duration::from_secs(2)).await.unwrap()); // now OK
    let m = client().ip_metadata(exit.clone(), false).await.unwrap();
    assert_eq!(
        (m.id.as_str(), m.ip.as_str(), m.cc.as_str()),
        ("Exit", "198.51.100.7", "NZ")
    );
    assert_eq!(m.provider_url, format!("{base}/trace"));
    let again = client().ip_metadata(exit.clone(), false).await.unwrap();
    assert_eq!(again, m);
    assert_eq!(hits.load(Ordering::Relaxed), 1, "cached");

    // v6: no IPv6 addresses for a v4 literal; every provider fails
    let e = client().ip_metadata(exit, true).await.unwrap_err();
    assert!(
        e.starts_with("proxy: client: Exit tcp6 lookup failed"),
        "{e}"
    );
}

#[tokio::test]
#[ignore]
async fn live_over_exit() {
    client().set_resolver(Arc::new(|host: String, _tid: String| {
        Box::pin(async move {
            tokio::net::lookup_host((host.as_str(), 443))
                .await
                .map(|it| it.map(|a| a.ip()).collect::<Vec<IpAddr>>())
                .unwrap_or_default()
        })
    }));
    *client().providers.write() = Providers::default();
    let px = px();
    let exit = px.proxy_for("Exit").unwrap();
    let _ = exit
        .dial_tcp("1.1.1.1:443".parse().unwrap(), Duration::from_secs(3))
        .await;
    let m = client().ip_metadata(exit, false).await.unwrap();
    assert!(
        m.ip.parse::<IpAddr>().is_ok(),
        "not an address from {}",
        m.provider_url
    );
    assert!(!m.provider_url.is_empty());
}
