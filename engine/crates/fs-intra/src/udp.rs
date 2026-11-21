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
//! Base: each datagram answered in its own task), or relayed over a protected socket. Sessions end after 120 s
//! without traffic (firestack `udptimeout`), reporting `postflow`.
//!
//! Relays use a connected socket per session, or, with endpoint-independent mapping (`Intra.transparency`, off in
//! loopback mode), one unconnected socket per (proxy, app source) shared by all of that source's sessions
//! (firestack `muxTable`/`muxer`), so the app keeps one public port (NAT traversal, STUN). With
//! endpoint-independent filtering, datagrams reaching that socket from peers the app never contacted become
//! inbound sessions, subject to Kotlin's `inflow` verdict; otherwise they are dropped.

use crate::flow::{self, BASE, BLOCK};
use crate::tunnel::Shared;
use fs_core::bridge::SharedBridge;
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
/// firestack `maxInFlight`: datagrams queued per demuxed route
const ROUTE_QUEUE: usize = 512;
/// firestack `maxtimeouterrors`: a muxer stops after this many idle read windows in a row
const MUX_MAX_IDLE: u32 = 3;
const INFLOW_TIMEOUT: Duration = Duration::from_secs(5);

/// Datagram towards an app: (payload, from = remote, to = app).
pub type Outbound = (Vec<u8>, SocketAddr, SocketAddr);

/// (src, dst) -> datagrams for the session task
type SessionMap = HashMap<(SocketAddr, SocketAddr), mpsc::Sender<Vec<u8>>>;

#[derive(Default)]
pub struct Sessions {
    m: Mutex<SessionMap>,
    mux: MuxTable,
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
            session(&me, sh, out, rx, key.0, key.1).await;
            me.m.lock().remove(&key);
        });
    }

    pub fn clear(&self) {
        self.m.lock().clear();
        self.mux.reset();
    }
}

/// endpoint-independent mapping in effect (never in loopback mode)
fn eim() -> bool {
    !settings::LOOPINGBACK.load(Ordering::Relaxed)
        && settings::ENDPOINT_INDEPENDENT_MAPPING.load(Ordering::Relaxed)
}
fn eif() -> bool {
    !settings::LOOPINGBACK.load(Ordering::Relaxed)
        && settings::ENDPOINT_INDEPENDENT_FILTERING.load(Ordering::Relaxed)
}

/// v4 peers on the dual-stack socket appear as `::ffff:a.b.c.d`.
fn canon(a: SocketAddr) -> SocketAddr {
    SocketAddr::new(a.ip().to_canonical(), a.port())
}
fn to_sock(a: SocketAddr, v6: bool) -> SocketAddr {
    match (a, v6) {
        (SocketAddr::V4(v4), true) => SocketAddr::new(v4.ip().to_ipv6_mapped().into(), v4.port()),
        _ => a,
    }
}

/// One unconnected protected socket shared by an app source's sessions via one proxy (firestack `muxer`).
struct Muxer {
    sock: tokio::net::UdpSocket,
    v6: bool,
    uid: String,
    /// remote -> the session receiving its datagrams
    routes: Mutex<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>,
    stop: tokio::sync::Notify,
}

impl Muxer {
    async fn send_to(&self, p: &[u8], to: SocketAddr) -> std::io::Result<usize> {
        self.sock.send_to(p, to_sock(to, self.v6)).await
    }
    fn route(&self, remote: SocketAddr) -> mpsc::Receiver<Vec<u8>> {
        let (tx, rx) = mpsc::channel(ROUTE_QUEUE);
        self.routes.lock().insert(canon(remote), tx);
        rx
    }
    fn unroute(&self, remote: SocketAddr) {
        self.routes.lock().remove(&canon(remote));
    }
}

/// (proxy, app source) -> muxer (firestack `muxTable`)
#[derive(Default)]
struct MuxTable {
    t: Mutex<HashMap<(String, SocketAddr), Arc<Muxer>>>,
}

impl MuxTable {
    /// firestack `associate`: the source's muxer for `pid` (created on first use) and a route for `dst`.
    async fn associate(
        &self,
        ctx: &MuxCtx,
        pid: &str,
        uid: &str,
        src: SocketAddr,
        dst: SocketAddr,
    ) -> std::io::Result<(Arc<Muxer>, mpsc::Receiver<Vec<u8>>)> {
        let key = (pid.to_string(), src);
        let existing = self.t.lock().get(&key).cloned();
        let mxr = match existing {
            Some(m) => m,
            None => {
                // dial outside the lock; another session may win the race
                let (sock, v6) = match ctx.sh.protector.announce_udp(pid, true).await {
                    Ok(s) => (s, true),
                    Err(_) => (ctx.sh.protector.announce_udp(pid, false).await?, false),
                };
                let fresh = Arc::new(Muxer {
                    sock,
                    v6,
                    uid: uid.to_string(),
                    routes: Mutex::new(HashMap::new()),
                    stop: tokio::sync::Notify::new(),
                });
                let mut t = self.t.lock();
                match t.get(&key) {
                    Some(m) => m.clone(),
                    None => {
                        t.insert(key.clone(), fresh.clone());
                        tokio::spawn(readers(ctx.clone(), fresh.clone(), key.clone()));
                        fresh
                    }
                }
            }
        };
        if mxr.uid != uid && !(uid == "-1" && mxr.uid == "-1") {
            return Err(std::io::Error::other(format!(
                "udp: mux: assoc uid mismatch: {} != {uid}",
                mxr.uid
            )));
        }
        let rx = mxr.route(dst);
        Ok((mxr, rx))
    }

    fn remove(&self, key: &(String, SocketAddr), m: &Arc<Muxer>) {
        let mut t = self.t.lock();
        if t.get(key).is_some_and(|x| Arc::ptr_eq(x, m)) {
            t.remove(key);
        }
    }

    /// Closes every muxer (tunnel restart / disconnect).
    fn reset(&self) {
        for (_, m) in self.t.lock().drain() {
            m.stop.notify_one();
        }
    }
}

/// What a muxer's reader needs to vend inbound sessions.
#[derive(Clone)]
struct MuxCtx {
    sh: Arc<Shared>,
    out: mpsc::Sender<Outbound>,
    sessions: Arc<Sessions>,
}

/// firestack `muxer.readers`: dispatches datagrams to their routes; unknown peers become inbound sessions with
/// endpoint-independent filtering (else they are dropped). Stops after three idle windows in a row.
async fn readers(ctx: MuxCtx, m: Arc<Muxer>, key: (String, SocketAddr)) {
    let src = key.1;
    let mut buf = vec![0u8; 65535];
    let mut idle = 0;
    loop {
        tokio::select! {
            r = tokio::time::timeout(UDP_IDLE, m.sock.recv_from(&mut buf)) => match r {
                Err(_) => {
                    idle += 1;
                    if idle >= MUX_MAX_IDLE {
                        break;
                    }
                }
                Ok(Err(_)) => break,
                Ok(Ok((n, from))) => {
                    idle = 0;
                    let from = canon(from);
                    let p = buf[..n].to_vec();
                    let tx = m.routes.lock().get(&from).cloned();
                    match tx {
                        Some(tx) => {
                            let _ = tx.try_send(p); // full or closed: drop (UDP is lossy)
                        }
                        None if eif() => {
                            let rx = m.route(from);
                            let _ = m.routes.lock().get(&from).map(|t| t.try_send(p));
                            tokio::spawn(ingress(ctx.clone(), m.clone(), src, from, rx));
                        }
                        None => {} // filtered out
                    }
                }
            },
            _ = m.stop.notified() => break,
        }
    }
    m.routes.lock().clear(); // sessions see their route close
    ctx.sessions.mux.remove(&key, &m);
}

/// firestack `ReverseProxy`: an unsolicited flow from `remote` to the app at `app`, judged by Kotlin's `inflow`.
async fn ingress(
    ctx: MuxCtx,
    m: Arc<Muxer>,
    app: SocketAddr,
    remote: SocketAddr,
    mut from_remote: mpsc::Receiver<Vec<u8>>,
) {
    let start = Instant::now();
    let mark = on_inflow(&ctx.sh.bridge, app, remote).await;
    let v = flow::judge(mark);
    let mut smm = FlowSummary {
        proto: "udp".into(),
        id: v.mark.cid.clone(),
        uid: v.uid.clone(),
        source: app.ip().to_string(),
        target: remote.ip().to_string(),
        pid: v.pids.first().cloned().unwrap_or_default(),
        msg: "no error".into(),
        ..Default::default()
    };
    if v.blocked() {
        m.unroute(remote);
        smm.pid = BLOCK.into();
        smm.msg = "udp: inbound firewalled".into();
        return finish(&ctx.sh, smm, start);
    }
    // the app's datagrams to `remote` belong to this flow
    let key = (app, remote);
    let (tx_app, mut from_app) = mpsc::channel(SESSION_QUEUE);
    ctx.sessions.m.lock().insert(key, tx_app);
    let conn = ctx.sh.conns.track(&v.mark.cid, &v.uid, &smm.pid);
    loop {
        tokio::select! {
            r = tokio::time::timeout(UDP_IDLE, from_remote.recv()) => match r {
                Ok(Some(p)) => {
                    smm.rx += p.len() as i64;
                    if ctx.out.send((p, remote, app)).await.is_err() {
                        break;
                    }
                }
                _ => break,
            },
            Some(p) = from_app.recv() => {
                smm.tx += p.len() as i64;
                if let Err(e) = m.send_to(&p, remote).await {
                    smm.msg = e.to_string();
                    break;
                }
            }
            _ = conn.closed() => {
                smm.msg = "closed by user".into();
                break;
            }
        }
    }
    ctx.sh.conns.untrack(&v.mark.cid);
    ctx.sessions.m.lock().remove(&key);
    m.unroute(remote);
    finish(&ctx.sh, smm, start);
}

/// firestack `onInflow`: Sink blocks everything; no verdict within 5 s blocks.
async fn on_inflow(bridge: &SharedBridge, to: SocketAddr, from: SocketAddr) -> Mark {
    let block = Mark {
        pidcsv: BLOCK.into(),
        ..Default::default()
    };
    if settings::BLOCK_MODE.load(Ordering::Relaxed) == settings::BLOCK_MODE_SINK {
        return block;
    }
    match tokio::time::timeout(
        INFLOW_TIMEOUT,
        bridge.inflow(PROTO_UDP, -1, to.to_string(), from.to_string()),
    )
    .await
    {
        Ok(Some(m)) => m,
        _ => block,
    }
}

async fn session(
    me: &Arc<Sessions>,
    sh: Arc<Shared>,
    out: mpsc::Sender<Outbound>,
    mut rx: mpsc::Receiver<Vec<u8>>,
    src: SocketAddr,
    dst: SocketAddr,
) {
    let start = Instant::now();
    let v = flow::decide(&sh.bridge, &sh.resolver, PROTO_UDP, src, dst).await;
    let targets = flow::targets(&v, dst);
    let target = targets[0];
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
        smm.msg = if v.undid_alg && v.realips.is_empty() && !v.domains.is_empty() {
            "no ips for domain".into()
        } else {
            "udp: firewalled".into()
        };
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
    if eim() {
        return relay_muxed(me, sh, out, rx, src, dst, target, v, smm, start).await;
    }
    let t0 = Instant::now();
    let mut dialed = Err(std::io::Error::other("udp: no target"));
    for t in &targets {
        dialed = sh.protector.dial_udp(who, *t).await;
        smm.target = t.ip().to_string();
        if dialed.is_ok() || start.elapsed() > flow::RETRY_TIMEOUT {
            break;
        }
    }
    let sock = match dialed {
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

/// A relayed session over the source's shared (endpoint-independent) socket.
#[allow(clippy::too_many_arguments)]
async fn relay_muxed(
    me: &Arc<Sessions>,
    sh: Arc<Shared>,
    out: mpsc::Sender<Outbound>,
    mut rx: mpsc::Receiver<Vec<u8>>,
    src: SocketAddr,
    dst: SocketAddr,
    target: SocketAddr,
    v: flow::Verdict,
    mut smm: FlowSummary,
    start: Instant,
) {
    let ctx = MuxCtx {
        sh: sh.clone(),
        out: out.clone(),
        sessions: me.clone(),
    };
    let t0 = Instant::now();
    let (mxr, mut from_remote) = match me.mux.associate(&ctx, &smm.pid, &v.uid, src, target).await {
        Ok(x) => x,
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
    loop {
        tokio::select! {
            q = tokio::time::timeout(UDP_IDLE, rx.recv()) => match q {
                Ok(Some(p)) => {
                    smm.tx += p.len() as i64;
                    if let Err(e) = mxr.send_to(&p, target).await {
                        smm.msg = e.to_string();
                        break;
                    }
                }
                _ => break,
            },
            r = from_remote.recv() => match r {
                Some(p) => {
                    smm.rx += p.len() as i64;
                    if out.send((p, dst, src)).await.is_err() {
                        break;
                    }
                }
                None => break, // muxer stopped
            },
            _ = conn.closed() => {
                smm.msg = "closed by user".into();
                break;
            }
        }
    }
    mxr.unroute(target);
    sh.conns.untrack(&v.mark.cid);
    finish(&sh, smm, start);
}

fn finish(sh: &Arc<Shared>, mut smm: FlowSummary, start: Instant) {
    smm.duration = start.elapsed().as_millis() as i64;
    sh.bridge.postflow(smm);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::Conns;
    use fs_core::bridge::AllowAllBridge;
    use tokio::net::UdpSocket;

    /// Replies to every datagram with the sender's address, as seen by the server.
    async fn echo() -> SocketAddr {
        let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let a = s.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 1500];
            while let Ok((_, peer)) = s.recv_from(&mut b).await {
                let _ = s.send_to(canon(peer).to_string().as_bytes(), peer).await;
            }
        });
        a
    }

    async fn next(rx: &mut mpsc::Receiver<Outbound>) -> Outbound {
        tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("datagram for the app")
            .unwrap()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn endpoint_independent_mapping_and_filtering() {
        settings::LOOPINGBACK.store(false, Ordering::SeqCst);
        settings::ENDPOINT_INDEPENDENT_MAPPING.store(true, Ordering::SeqCst);
        settings::ENDPOINT_INDEPENDENT_FILTERING.store(true, Ordering::SeqCst);
        let bridge: SharedBridge = Arc::new(AllowAllBridge);
        let sh = Arc::new(Shared {
            bridge: bridge.clone(),
            resolver: Arc::new(fs_dnsx::Resolver::new("10.111.222.3:53", bridge.clone())),
            protector: fs_dialers::Protector::new(bridge.clone()),
            stall: flow::Stall::default(),
            conns: Conns::default(),
        });
        let sessions = Arc::new(Sessions::default());
        let (out, mut rx) = mpsc::channel(64);
        let app: SocketAddr = "10.111.222.1:40000".parse().unwrap();
        let (e1, e2) = (echo().await, echo().await);

        sessions.dispatch(&sh, &out, b"one".to_vec(), app, e1);
        let (p1, from, to) = next(&mut rx).await;
        assert_eq!((from, to), (e1, app));
        sessions.dispatch(&sh, &out, b"two".to_vec(), app, e2);
        let (p2, from, _) = next(&mut rx).await;
        assert_eq!(from, e2);
        let (p1, p2) = (
            String::from_utf8(p1).unwrap(),
            String::from_utf8(p2).unwrap(),
        );
        assert_eq!(
            p1, p2,
            "both destinations see the same public address (EIM)"
        );

        // an unsolicited peer reaches the app (EIF), and the app's reply goes back through the same port
        let public: SocketAddr = p1.parse().unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        peer.send_to(b"knock", public).await.unwrap();
        let (p, from, to) = next(&mut rx).await;
        assert_eq!(
            (p.as_slice(), from, to),
            (&b"knock"[..], peer.local_addr().unwrap(), app)
        );
        sessions.dispatch(
            &sh,
            &out,
            b"welcome".to_vec(),
            app,
            peer.local_addr().unwrap(),
        );
        let mut b = [0u8; 64];
        let (n, src) = tokio::time::timeout(Duration::from_secs(5), peer.recv_from(&mut b))
            .await
            .unwrap()
            .unwrap();
        assert_eq!((&b[..n], canon(src)), (&b"welcome"[..], public));

        // without EIF, unsolicited datagrams are dropped
        settings::ENDPOINT_INDEPENDENT_FILTERING.store(false, Ordering::SeqCst);
        let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        stranger.send_to(b"psst", public).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(300), rx.recv())
                .await
                .is_err()
        );

        settings::ENDPOINT_INDEPENDENT_MAPPING.store(false, Ordering::SeqCst);
        sessions.clear();
    }
}
