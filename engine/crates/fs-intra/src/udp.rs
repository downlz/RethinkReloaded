// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/udp.go
// Derived-From: celzero/firestack@d3d530ea3e:intra/dnsx/transport.go (reply: DNS over UDP)

//! UDP flows: datagrams are grouped into sessions by (src, dst). The first datagram of a session triggers the
//! policy decision; then the session is blocked (datagrams dropped), served by the resolver (fake DNS address,
//! Base: each datagram answered in its own task), or relayed over a protected connected socket. Sessions end after
//! 120 s without traffic (firestack `udptimeout`), reporting `postflow`.
//!
//! Not yet ported: endpoint-independent mapping/filtering (one socket per source, `Intra.transparency`).

use crate::flow::{self, BASE, BLOCK};
use crate::tunnel::Shared;
use fs_core::bridge::{FlowSummary, Mark, PROTO_UDP};
use fs_core::settings;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

pub const UDP_IDLE: Duration = Duration::from_secs(120);
const SESSION_QUEUE: usize = 256;

/// Datagram towards an app: (payload, from = remote, to = app).
pub type Outbound = (Vec<u8>, SocketAddr, SocketAddr);

/// (src, dst) -> datagrams for the session task
type SessionMap = HashMap<(SocketAddr, SocketAddr), mpsc::Sender<Vec<u8>>>;

#[derive(Default)]
pub struct Sessions {
    m: Mutex<SessionMap>,
}

impl Sessions {
    /// Routes an inbound datagram to its session, creating the session (and its task) on first sight.
    pub fn dispatch(
        self: &Arc<Self>,
        sh: &Arc<Shared>,
        out: &mpsc::Sender<Outbound>,
        payload: Vec<u8>,
        src: SocketAddr,
        dst: SocketAddr,
    ) {
        let key = (src, dst);
        let mut m = self.m.lock();
        if let Some(tx) = m.get(&key) {
            match tx.try_send(payload) {
                Ok(()) => return,
                Err(mpsc::error::TrySendError::Full(_)) => return, // session backlogged: drop (UDP is lossy)
                Err(mpsc::error::TrySendError::Closed(p)) => {
                    m.remove(&key);
                    return self.spawn(&mut m, sh, out, key, p);
                }
            }
        }
        self.spawn(&mut m, sh, out, key, payload);
    }

    fn spawn(
        self: &Arc<Self>,
        m: &mut SessionMap,
        sh: &Arc<Shared>,
        out: &mpsc::Sender<Outbound>,
        key: (SocketAddr, SocketAddr),
        first: Vec<u8>,
    ) {
        let (tx, rx) = mpsc::channel(SESSION_QUEUE);
        let _ = tx.try_send(first);
        m.insert(key, tx);
        let (sh, out, me) = (sh.clone(), out.clone(), self.clone());
        tokio::spawn(async move {
            session(sh, out, rx, key.0, key.1).await;
            me.m.lock().remove(&key);
        });
    }

    pub fn clear(&self) {
        self.m.lock().clear();
    }
}

async fn session(
    sh: Arc<Shared>,
    out: mpsc::Sender<Outbound>,
    mut rx: mpsc::Receiver<Vec<u8>>,
    src: SocketAddr,
    dst: SocketAddr,
) {
    let start = Instant::now();
    let v = flow::decide(&sh.bridge, PROTO_UDP, src, dst).await;
    let target = flow::target(&v, dst);
    let mut smm = FlowSummary {
        proto: "udp".into(),
        id: v.mark.cid.clone(),
        uid: v.uid.clone(),
        source: src.ip().to_string(),
        target: target.ip().to_string(),
        msg: "no error".into(),
        ..Default::default()
    };

    if v.blocked() {
        smm.pid = BLOCK.into();
        smm.msg = "udp: firewalled".into();
        // drop everything the app sends until it goes quiet
        while let Ok(Some(_)) = tokio::time::timeout(UDP_IDLE, rx.recv()).await {}
        return finish(&sh, smm, start);
    }

    if v.has(BASE) && sh.resolver.is_dns_addr(dst) {
        smm.pid = BASE.into();
        let (cid, uid) = (v.mark.cid.clone(), v.uid.clone());
        let (rxb, txb) = (
            Arc::new(std::sync::atomic::AtomicI64::new(0)),
            Arc::new(std::sync::atomic::AtomicI64::new(0)),
        );
        while let Ok(Some(q)) = tokio::time::timeout(UDP_IDLE, rx.recv()).await {
            txb.fetch_add(q.len() as i64, Ordering::Relaxed);
            let (sh, out, cid, uid, rxb) = (
                sh.clone(),
                out.clone(),
                cid.clone(),
                uid.clone(),
                rxb.clone(),
            );
            tokio::spawn(async move {
                if let Some(ans) = sh
                    .resolver
                    .forward(&q, fs_dnsx::resolver::ORIGIN_TUNNEL, &cid, &uid)
                    .await
                {
                    rxb.fetch_add(ans.len() as i64, Ordering::Relaxed);
                    let _ = out.send((ans, dst, src)).await;
                }
            });
        }
        smm.rx = rxb.load(Ordering::Relaxed);
        smm.tx = txb.load(Ordering::Relaxed);
        return finish(&sh, smm, start);
    }

    let who = flow::who(&v);
    smm.pid = who.into();
    let t0 = Instant::now();
    let sock = match sh.protector.dial_udp(who, target).await {
        Ok(s) => s,
        Err(e) => {
            smm.rtt = t0.elapsed().as_millis() as i64;
            smm.msg = e.to_string();
            return finish(&sh, smm, start);
        }
    };
    sh.bridge.flowing(Mark {
        pidcsv: smm.pid.clone(),
        cid: v.mark.cid.clone(),
        uid: v.uid.clone(),
        ip: smm.target.clone(),
    });
    let conn = sh.conns.track(&v.mark.cid, &v.uid, &smm.pid);
    let idle = UDP_IDLE.max(Duration::from_secs(
        settings::dialer_opts().read_timeout_sec.max(0) as u64,
    ));
    let mut buf = vec![0u8; 65535];
    loop {
        tokio::select! {
            q = tokio::time::timeout(idle, rx.recv()) => match q {
                Ok(Some(p)) => {
                    smm.tx += p.len() as i64;
                    if let Err(e) = sock.send(&p).await {
                        smm.msg = e.to_string();
                        break;
                    }
                }
                _ => break, // app idle or session closed
            },
            r = sock.recv(&mut buf) => match r {
                Ok(n) => {
                    smm.rx += n as i64;
                    // replies appear to come from the original destination (not a Mark.IP override)
                    if out.send((buf[..n].to_vec(), dst, src)).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    smm.msg = e.to_string();
                    break;
                }
            },
            _ = conn.closed() => {
                smm.msg = "closed by user".into();
                break;
            }
        }
    }
    sh.conns.untrack(&v.mark.cid);
    finish(&sh, smm, start);
}

fn finish(sh: &Arc<Shared>, mut smm: FlowSummary, start: Instant) {
    smm.duration = start.elapsed().as_millis() as i64;
    sh.bridge.postflow(smm);
}
