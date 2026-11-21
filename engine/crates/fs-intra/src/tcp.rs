// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/tcp.go
// Derived-From: celzero/firestack@d3d530ea3e:intra/common.go (forward, summaries)

//! TCP flows: the app's handshake is already complete (netstack accepted it). Decide (`preflow`/`flow`), then
//! block (stall + close), answer DNS-over-TCP to the fake DNS address (Base), or dial a protected socket and relay
//! with half-close, reporting `flowing` and finally `postflow`.

use crate::flow::{self, BASE, BLOCK, Verdict};
use crate::tunnel::Shared;
use fs_core::bridge::{FlowSummary, Mark, PROTO_TCP};
use fs_netstack::TcpStream;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub async fn handle(sh: Arc<Shared>, mut app: TcpStream, src: SocketAddr, dst: SocketAddr) {
    let start = Instant::now();
    let v: Verdict = flow::decide(&sh.bridge, &sh.resolver, PROTO_TCP, src, dst).await;
    let targets = flow::targets(&v, dst);
    let target = targets[0];
    let mut smm = FlowSummary {
        proto: "tcp".into(),
        id: v.mark.cid.clone(),
        uid: v.uid.clone(),
        source: src.ip().to_string(),
        target: target.ip().to_string(),
        msg: "no error".into(),
        ..Default::default()
    };

    if v.blocked() {
        smm.pid = BLOCK.into();
        smm.msg = if v.undid_alg && v.realips.is_empty() && !v.domains.is_empty() {
            "no ips for domain".into()
        } else {
            "tcp: firewalled".into()
        };
        let delay = sh.stall.delay(&format!("{}|{}", v.uid, dst.ip()));
        tokio::time::sleep(delay).await;
        let _ = app.shutdown().await;
        smm.duration = start.elapsed().as_millis() as i64;
        sh.bridge.postflow(smm);
        return;
    }

    if v.has(BASE) && sh.resolver.is_dns_addr(dst) {
        smm.pid = BASE.into();
        let (rx, tx) = serve_dns_tcp(&sh, &mut app, &v).await;
        smm.rx = rx;
        smm.tx = tx;
        smm.duration = start.elapsed().as_millis() as i64;
        sh.bridge.postflow(smm);
        return;
    }

    let who = flow::who(&v);
    smm.pid = who.into();
    // firestack: the real addresses in turn, until one connects or the retry window closes
    let mut remote = Err(std::io::Error::other("tcp: no target"));
    for t in &targets {
        let t0 = Instant::now();
        remote = sh
            .protector
            .dial_tcp(who, *t, fs_dialers::DIAL_TIMEOUT)
            .await;
        smm.rtt = t0.elapsed().as_millis() as i64;
        smm.target = t.ip().to_string();
        if remote.is_ok() || start.elapsed() > flow::RETRY_TIMEOUT {
            break;
        }
    }
    let mut remote = match remote {
        Ok(r) => r,
        Err(e) => {
            smm.msg = e.to_string();
            let _ = app.shutdown().await;
            smm.duration = start.elapsed().as_millis() as i64;
            sh.bridge.postflow(smm);
            return;
        }
    };
    sh.bridge.flowing(Mark {
        pidcsv: smm.pid.clone(),
        cid: v.mark.cid.clone(),
        uid: v.uid.clone(),
        ip: smm.target.clone(),
    });
    let conn = sh.conns.track(&v.mark.cid, &v.uid, &smm.pid);
    let relay = tokio::io::copy_bidirectional(&mut app, &mut remote);
    tokio::select! {
        r = relay => match r {
            Ok((up, down)) => {
                smm.tx = up as i64;
                smm.rx = down as i64;
            }
            Err(e) => smm.msg = e.to_string(),
        },
        _ = conn.closed() => smm.msg = "closed by user".into(),
    }
    sh.conns.untrack(&v.mark.cid);
    smm.duration = start.elapsed().as_millis() as i64;
    sh.bridge.postflow(smm);
}

/// DNS over TCP (2-byte length framing) on the fake DNS address. Returns (bytes answered, bytes queried).
async fn serve_dns_tcp(sh: &Arc<Shared>, app: &mut TcpStream, v: &Verdict) -> (i64, i64) {
    let (mut rx, mut tx) = (0i64, 0i64);
    loop {
        let mut len = [0u8; 2];
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(120),
            app.read_exact(&mut len),
        )
        .await;
        if !matches!(read, Ok(Ok(_))) {
            break;
        }
        let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
        if app.read_exact(&mut q).await.is_err() {
            break;
        }
        tx += q.len() as i64 + 2;
        let Some(ans) = sh
            .resolver
            .forward(&q, fs_dnsx::resolver::ORIGIN_TUNNEL, &v.mark.cid, &v.uid)
            .await
        else {
            continue; // upstream failed: no answer (firestack)
        };
        let mut framed = (ans.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&ans);
        if app.write_all(&framed).await.is_err() {
            break;
        }
        rx += framed.len() as i64;
    }
    let _ = app.shutdown().await;
    (rx, tx)
}
