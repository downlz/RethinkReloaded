// Copyright (c) 2026 RethinkReloaded contributors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Split and desync connections complete real TLS handshakes and HTTP exchanges (network;
//! `cargo test -p fs-proxy --test split_live -- --ignored`). Desync only desyncs on Linux.

use fs_core::bridge::AllowAllBridge;
use fs_core::settings::{RETRY_NEVER, SPLIT_DESYNC, SPLIT_NEVER, SPLIT_TCP, SPLIT_TCP_OR_TLS};
use fs_dialers::split::{Retrier, Splitter, StratDial};
use fs_dialers::{Protector, TcpConn, desync};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn dialer(dst: SocketAddr) -> StratDial {
    let p = Protector::new(Arc::new(AllowAllBridge));
    Arc::new(move |strat| {
        let p = p.clone();
        Box::pin(async move {
            let t = Duration::from_secs(5);
            match strat {
                SPLIT_DESYNC => desync::dial(&p, "Exit", dst, t).await,
                SPLIT_TCP | SPLIT_TCP_OR_TLS => Ok(TcpConn::Dyn(Box::new(Splitter::new(
                    TcpConn::Sock(p.dial_tcp("Exit", dst, t).await?),
                    strat,
                )))),
                _ => p.dial_tcp("Exit", dst, t).await.map(TcpConn::Sock),
            }
        })
    })
}

#[tokio::test]
#[ignore]
async fn handshakes_with_every_strategy() {
    let dst: SocketAddr = "1.1.1.1:443".parse().unwrap();
    for strat in [SPLIT_NEVER, SPLIT_TCP, SPLIT_TCP_OR_TLS, SPLIT_DESYNC] {
        let r = Retrier::dial_with(dialer(dst), 443, strat, RETRY_NEVER)
            .await
            .unwrap();
        assert_eq!(r.current_strat(), strat);
        let sni = rustls_pki_types::ServerName::try_from("one.one.one.one").unwrap();
        let mut s = tokio_rustls::TlsConnector::from(fs_dns::tls::client_config(&[b"http/1.1"]))
            .connect(sni, r)
            .await
            .unwrap_or_else(|e| panic!("strat {strat}: {e}"));
        s.write_all(
            b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: one.one.one.one\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
        let mut b = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut b)).await;
        assert!(b.starts_with(b"HTTP/1.1 200"), "strat {strat}");
    }
    println!(
        "desync: ttl {:?}, decoys sent {}",
        desync::ttl_of(dst.ip()),
        desync::decoys()
    );
}
