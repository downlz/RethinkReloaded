// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/ipn/wgproxy.go (wgproxy, wgtun: status listener, Stat, DNS,
//               Self, Contains, MTU reconciliation, serve, Pause/Resume, Refresh, Ping)
// Derived-From: celzero/firestack@d3d530ea3e:intra/ipn/wg/wgconn.go (the UDP bind)
// WireGuard® is a registered trademark of Jason A. Donenfeld. The protocol implementation is gotatun (Mullvad,
// MPL-2.0), a fork of Cloudflare's boringtun.

//! WireGuard proxies (ids starting `wg`). gotatun runs the device (peers, handshakes, allowed IPs, timers) over two
//! engine-provided transports: a UDP bind (protected as the proxy, or announced through the proxy it hops through)
//! and a virtual TUN backed by the proxy's userspace [`stack`]. Connections through the proxy are sockets of that
//! stack; Kotlin sees firestack's status machine (TUP → TOK / TKO / TNT / TZZ, TPU, END) and stats.

pub mod config;
pub mod stack;

use crate::upstream::HostResolver;
use crate::{
    END, Proxy, RouterStats, SharedProxy, TKO, TNT, TOK, TPU, TUP, TZZ, WG, new_handle, now_millis,
};
use config::WgCfg;
use fs_dialers::{Fut, Protector, TcpConn, UdpConn};
use gotatun::device::{Device, DeviceBuilder, Peer};
use gotatun::packet::{Ip, Packet, PacketBufPool};
use gotatun::tun::{IpRecv, IpSend, MtuWatcher};
use gotatun::udp::{UdpRecv, UdpSend, UdpTransportFactory, UdpTransportFactoryParams};
use gotatun::x25519::{PublicKey, StaticSecret};
use parking_lot::{Mutex, RwLock};
use stack::Stack;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicI32, AtomicI64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::sync::mpsc;

/// firestack `markTNTAfterMillis`: reads or writes failing for this long make the proxy unresponsive
const MARK_TNT_AFTER_MS: i64 = 20_000;

/// What the UDP bind reports (firestack `wg.PktDir`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Opn,
    Snd,
    Rcv,
    Clo,
}

/// Status, stats and the hop shared by the proxy and its bind.
pub struct WgState {
    id: String,
    protector: Protector,
    via: Mutex<Option<Weak<dyn Proxy>>>,
    status: AtomicI32,
    reason: Mutex<String>,
    since: AtomicI64,
    latest_open: AtomicI64,
    latest_refresh: AtomicI64,
    latest_rx: AtomicI64,
    latest_tx: AtomicI64,
    latest_good_rx: AtomicI64,
    latest_good_tx: AtomicI64,
    latest_handshake: AtomicI64,
    err_rx: AtomicI64,
    err_tx: AtomicI64,
    rx_bytes: AtomicI64,
    tx_bytes: AtomicI64,
    last_err: Mutex<String>,
    last_rx_err: Mutex<String>,
    last_tx_err: Mutex<String>,
}

impl WgState {
    fn via(&self) -> Option<SharedProxy> {
        self.via.lock().as_ref().and_then(Weak::upgrade)
    }

    /// firestack `wgtun.listener`: status transitions from bind events.
    fn listener(&self, op: Op, err: Option<&io::Error>) {
        let cur = self.status.load(Ordering::Relaxed);
        if let Some(e) = err {
            let m = e.to_string();
            match op {
                Op::Rcv => *self.last_rx_err.lock() = m,
                Op::Snd => *self.last_tx_err.lock() = m,
                _ => *self.last_err.lock() = m,
            }
        }
        if cur == END || cur == TPU {
            return;
        }
        let now = now_millis();
        let (mut s, mut why): (i32, String);
        if op == Op::Clo {
            s = TNT;
            why = "TNT: closed".into();
        } else {
            if op == Op::Opn {
                self.latest_open.store(now, Ordering::Relaxed);
            }
            match err {
                Some(e) => {
                    s = TKO;
                    why = format!("TKO: {e}");
                    if op == Op::Opn {
                        s = TNT;
                        why = "TNT: could not open conn".into();
                    } else if op == Op::Rcv && e.kind() == io::ErrorKind::TimedOut {
                        s = TZZ;
                        why = "TZZ: read timeout".into();
                    }
                    match op {
                        Op::Rcv if e.kind() != io::ErrorKind::TimedOut => {
                            self.err_rx.fetch_add(1, Ordering::Relaxed);
                            self.latest_rx.store(now, Ordering::Relaxed);
                        }
                        Op::Snd => {
                            self.err_tx.fetch_add(1, Ordering::Relaxed);
                            self.latest_tx.store(now, Ordering::Relaxed);
                        }
                        _ => {}
                    }
                }
                None => {
                    s = TOK;
                    why = "TOK: ok".into();
                    match op {
                        Op::Rcv => {
                            self.latest_good_rx.store(now, Ordering::Relaxed);
                            self.latest_rx.store(now, Ordering::Relaxed);
                            why = "TOK: read ok".into();
                        }
                        Op::Snd => {
                            self.latest_good_tx.store(now, Ordering::Relaxed);
                            self.latest_tx.store(now, Ordering::Relaxed);
                            why = "TOK: write ok".into();
                        }
                        _ => {}
                    }
                }
            }
            let age = now - self.latest_open.load(Ordering::Relaxed);
            if age > crate::AGE_THRESHOLD.as_millis() as i64 && (s == TOK || s == TKO) {
                let (gr, gw) = (
                    self.latest_good_rx.load(Ordering::Relaxed),
                    self.latest_good_tx.load(Ordering::Relaxed),
                );
                let (r, w) = (
                    self.latest_rx.load(Ordering::Relaxed),
                    self.latest_tx.load(Ordering::Relaxed),
                );
                let deviation = gr.max(gw) - gr.min(gw);
                let (new_reads, new_writes) = (r > age, w > age);
                let read_thres = new_reads && r - gr > MARK_TNT_AFTER_MS;
                let write_thres = new_writes && w - gw > MARK_TNT_AFTER_MS;
                let rw_apart = (new_reads || new_writes) && deviation > 2 * MARK_TNT_AFTER_MS;
                if !new_reads && !new_writes {
                    s = TZZ;
                    why = "TZZ: idling after start/refresh".into();
                } else if read_thres || write_thres || rw_apart {
                    s = TNT;
                    why = format!(
                        "TNT: r !ok? {read_thres}, w !ok? {write_thres}, rw apart? {rw_apart}"
                    );
                }
            }
        }
        *self.reason.lock() = why;
        let _ = self
            .status
            .compare_exchange(cur, s, Ordering::Relaxed, Ordering::Relaxed);
    }
}

/// v4 peers on the dual-stack bind appear as `::ffff:a.b.c.d`.
fn canon(a: SocketAddr) -> SocketAddr {
    SocketAddr::new(a.ip().to_canonical(), a.port())
}

/// The UDP bind (firestack `wg.NewEndpoint` + `wgtun.serve`).
struct Bind(Arc<WgState>);

#[derive(Clone)]
struct BindIo {
    conn: UdpConn,
    st: Arc<WgState>,
    v6: bool,
}

impl UdpTransportFactory for Bind {
    type Send = BindIo;
    type Recv = BindIo;
    async fn bind(&mut self, _: &UdpTransportFactoryParams) -> io::Result<(BindIo, BindIo)> {
        let st = self.0.clone();
        crate::candial(st.status.load(Ordering::Relaxed)).map_err(io::Error::other)?;
        let open = async {
            match st.via() {
                Some(v) => match v.announce_udp(true).await {
                    Ok(c) => Ok((c, true)),
                    Err(_) => v.announce_udp(false).await.map(|c| (c, false)),
                },
                None => match st.protector.announce_udp(&st.id, true).await {
                    Ok(c) => Ok((UdpConn::from(c), true)),
                    Err(_) => st
                        .protector
                        .announce_udp(&st.id, false)
                        .await
                        .map(|c| (UdpConn::from(c), false)),
                },
            }
        };
        let r = open.await;
        st.listener(Op::Opn, r.as_ref().err());
        let (conn, v6) = r?;
        let io = BindIo { conn, st, v6 };
        Ok((io.clone(), io))
    }
}

impl UdpSend for BindIo {
    type SendManyBuf = ();
    async fn send_to(&self, packet: Packet, dst: SocketAddr) -> io::Result<()> {
        let to = match (dst, self.v6) {
            (SocketAddr::V4(v4), true) => {
                SocketAddr::new(v4.ip().to_ipv6_mapped().into(), v4.port())
            }
            _ => dst,
        };
        let r = self.conn.send_to(&packet, to).await;
        if let Ok(n) = &r {
            self.st.tx_bytes.fetch_add(*n as i64, Ordering::Relaxed);
        }
        self.st.listener(Op::Snd, r.as_ref().err());
        r.map(|_| ())
    }
}

impl UdpRecv for BindIo {
    type RecvManyBuf = ();
    async fn recv_from(&mut self, pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        let mut buf = pool.get();
        let r = self.conn.recv_from(&mut buf).await;
        self.st.listener(Op::Rcv, r.as_ref().err());
        let (n, from) = r?;
        buf.truncate(n);
        self.st.rx_bytes.fetch_add(n as i64, Ordering::Relaxed);
        // message type 2: handshake response (firestack reports the latest handshake as LastOK)
        if n >= 4 && buf[0] == 2 {
            self.st
                .latest_handshake
                .store(now_millis(), Ordering::Relaxed);
        }
        Ok((buf, canon(from)))
    }
}

/// Decrypted packets into the stack.
struct ToStack(Arc<Stack>);

impl IpSend for ToStack {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        self.0.input(packet.into_bytes().to_vec());
        Ok(())
    }
}

/// Packets the stack emits, to be encrypted.
struct FromStack {
    rx: mpsc::Receiver<Vec<u8>>,
    mtu: u16,
}

impl IpRecv for FromStack {
    async fn recv<'a>(
        &'a mut self,
        _: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        let first = self
            .rx
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "wg: stack closed"))?;
        fn push(out: &mut Vec<Packet<Ip>>, p: Vec<u8>) {
            if let Ok(ip) = Packet::from_bytes(stack::to_bytes(p)).try_into_ip() {
                out.push(ip);
            }
        }
        let mut out = Vec::with_capacity(8);
        push(&mut out, first);
        while out.len() < 64 {
            match self.rx.try_recv() {
                Ok(p) => push(&mut out, p),
                Err(_) => break,
            }
        }
        Ok(out.into_iter())
    }
    fn mtu(&self) -> MtuWatcher {
        MtuWatcher::new(self.mtu)
    }
}

type Dev = Device<(Bind, ToStack, FromStack)>;

/// firestack `reconcileMtu` / `calcTunMtu2`: the tunnel's MTU from the link's and the configured one.
pub fn reconcile_mtu(underlay: i64, overlay: i64, minoverlay: i64) -> i64 {
    if underlay < overlay {
        return (underlay - 80).max(crate::NOMTU);
    }
    (minoverlay - 80).max(overlay - 80)
}

pub struct WgProxy {
    id: String,
    hdl: u64,
    cfg: RwLock<WgCfg>,
    st: Arc<WgState>,
    stack: Arc<Stack>,
    dev: Arc<tokio::sync::Mutex<Option<Dev>>>,
    rt: fs_iptree::IpTree,
    /// resolved peer endpoints (the proxy's own addresses)
    endpoints: RwLock<Vec<SocketAddr>>,
    mtu: i64,
    resolver: Option<HostResolver>,
    handle: tokio::runtime::Handle,
}

async fn resolve(resolver: &Option<HostResolver>, hp: &str) -> Vec<SocketAddr> {
    if let Ok(a) = hp.parse::<SocketAddr>() {
        return vec![a];
    }
    let Some((host, port)) = hp.rsplit_once(':') else {
        return vec![];
    };
    let Ok(port) = port.parse::<u16>() else {
        return vec![];
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = host.parse::<IpAddr>() {
        return vec![SocketAddr::new(ip, port)];
    }
    match resolver {
        Some(r) => r(host.to_string())
            .await
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect(),
        None => vec![],
    }
}

impl WgProxy {
    /// firestack `NewWgProxy`: parses the config, builds the stack, and brings the device up in the background.
    pub fn new(
        id: &str,
        txt: &str,
        protector: Protector,
        resolver: Option<HostResolver>,
        link: &crate::proxifier::LinkProps,
        handle: tokio::runtime::Handle,
    ) -> Result<Arc<Self>, String> {
        let cfg = config::parse(id, txt)?;
        let minmtu = if link.l3 == "4" {
            crate::MIN_MTU4
        } else {
            crate::MIN_MTU6
        };
        let underlay = if link.mtu > 0 {
            link.mtu
        } else {
            crate::MAXMTU
        };
        let mtu = reconcile_mtu(underlay, cfg.mtu, minmtu);
        if mtu <= crate::NOMTU {
            return Err("proxy: missing mtu".into());
        }
        let rt = fs_iptree::IpTree::new();
        for n in &cfg.allowed {
            let _ = rt.set(&n.to_string(), id);
        }
        let (tx, rx) = mpsc::channel(stack::OUT_QUEUE);
        let stack = {
            let _g = handle.enter();
            Stack::new(&cfg.ifaddrs, mtu as usize, tx)
        };
        let now = now_millis();
        let st = Arc::new(WgState {
            id: id.to_string(),
            protector,
            via: Mutex::new(None),
            status: AtomicI32::new(TUP),
            reason: Mutex::new("TUP: waiting to connect".into()),
            since: AtomicI64::new(now),
            latest_open: AtomicI64::new(0),
            latest_refresh: AtomicI64::new(now),
            latest_rx: AtomicI64::new(0),
            latest_tx: AtomicI64::new(0),
            latest_good_rx: AtomicI64::new(0),
            latest_good_tx: AtomicI64::new(0),
            latest_handshake: AtomicI64::new(0),
            err_rx: AtomicI64::new(0),
            err_tx: AtomicI64::new(0),
            rx_bytes: AtomicI64::new(0),
            tx_bytes: AtomicI64::new(0),
            last_err: Mutex::new(String::new()),
            last_rx_err: Mutex::new(String::new()),
            last_tx_err: Mutex::new(String::new()),
        });
        let w = Arc::new(WgProxy {
            id: id.to_string(),
            hdl: new_handle(),
            cfg: RwLock::new(cfg),
            st,
            stack,
            dev: Arc::new(tokio::sync::Mutex::new(None)),
            rt,
            endpoints: RwLock::new(Vec::new()),
            mtu,
            resolver,
            handle,
        });
        w.start(rx);
        Ok(w)
    }

    /// Resolves the peers' endpoints and builds the device.
    fn start(self: &Arc<Self>, rx: mpsc::Receiver<Vec<u8>>) {
        let me = Arc::downgrade(self);
        self.handle.spawn(async move {
            let Some(w) = me.upgrade() else { return };
            let peers = w.peers().await;
            let cfg = w.cfg.read().clone();
            let built = DeviceBuilder::new()
                .with_udp(Bind(w.st.clone()))
                .with_ip_pair(
                    ToStack(w.stack.clone()),
                    FromStack {
                        rx,
                        mtu: w.mtu.min(u16::MAX as i64) as u16,
                    },
                )
                .with_private_key(StaticSecret::from(cfg.private_key))
                .with_peers(peers)
                .build()
                .await;
            match built {
                Ok(d) => {
                    *w.dev.lock().await = Some(d);
                    // first handshakes now rather than on the first packet
                    w.ping();
                }
                Err(e) => {
                    *w.st.last_err.lock() = e.to_string();
                    w.st.listener(Op::Opn, Some(&io::Error::other(e.to_string())));
                }
            }
        });
    }

    async fn peers(&self) -> Vec<Peer> {
        let cfg = self.cfg.read().clone();
        let mut out = Vec::new();
        let mut eps = Vec::new();
        for p in &cfg.peers {
            let mut peer = Peer::new(PublicKey::from(p.public_key));
            for e in &p.endpoints {
                let a = resolve(&self.resolver, e).await;
                eps.extend(a.iter().copied());
                if peer.endpoint.is_none()
                    && let Some(first) = a.first()
                {
                    peer.endpoint = Some(*first);
                }
            }
            peer.preshared_key = p.preshared_key;
            peer.keepalive = p.keepalive;
            peer.allowed_ips = p
                .allowed
                .iter()
                .filter_map(|n| ipnetwork::IpNetwork::new(n.ip, n.bits).ok())
                .collect();
            out.push(peer);
        }
        *self.endpoints.write() = eps;
        out
    }

    fn cfg_dns(&self) -> Vec<String> {
        self.cfg.read().dns.clone()
    }
}

impl Proxy for WgProxy {
    fn id(&self) -> &str {
        &self.id
    }
    fn typ(&self) -> &str {
        WG
    }
    fn addr(&self) -> String {
        self.endpoints
            .read()
            .first()
            .map(|a| a.to_string())
            .unwrap_or_else(|| {
                self.cfg
                    .read()
                    .peers
                    .first()
                    .and_then(|p| p.endpoints.first().cloned())
                    .unwrap_or_default()
            })
    }
    fn status(&self) -> i32 {
        self.st.status.load(Ordering::Relaxed)
    }
    fn handle(&self) -> u64 {
        self.hdl
    }
    /// firestack `dnsResolvers`: hostnames when the config has any, else addresses.
    fn dns(&self) -> String {
        let all = self.cfg_dns();
        let names: Vec<&String> = all
            .iter()
            .filter(|d| d.parse::<IpAddr>().is_err())
            .collect();
        if !names.is_empty() {
            return names
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(",");
        }
        all.iter()
            .filter_map(|d| d.parse::<IpAddr>().ok())
            .filter(|ip| !ip.is_unspecified())
            .map(|ip| ip.to_canonical().to_string())
            .collect::<Vec<_>>()
            .join(",")
    }
    fn dial_tcp<'a>(&'a self, dst: SocketAddr, timeout: Duration) -> Fut<'a, io::Result<TcpConn>> {
        Box::pin(async move {
            crate::candial(self.status()).map_err(io::Error::other)?;
            let s = self.stack.connect(dst, timeout).await?;
            Ok(TcpConn::Dyn(Box::new(s)))
        })
    }
    fn dial_udp<'a>(&'a self, dst: SocketAddr) -> Fut<'a, io::Result<UdpConn>> {
        Box::pin(async move {
            crate::candial(self.status()).map_err(io::Error::other)?;
            Ok(UdpConn::Dyn(Arc::new(self.stack.udp(Some(dst))?)))
        })
    }
    fn announce_udp<'a>(&'a self, _v6: bool) -> Fut<'a, io::Result<UdpConn>> {
        Box::pin(async move {
            crate::candial(self.status()).map_err(io::Error::other)?;
            Ok(UdpConn::Dyn(Arc::new(self.stack.udp(None)?)))
        })
    }
    fn probe_icmp<'a>(&'a self, dst: IpAddr) -> Fut<'a, io::Result<UdpConn>> {
        Box::pin(async move {
            crate::candial(self.status()).map_err(io::Error::other)?;
            Ok(UdpConn::Dyn(Arc::new(self.stack.icmp(dst)?)))
        })
    }
    fn ip4(&self) -> bool {
        self.stack.ip4()
    }
    fn ip6(&self) -> bool {
        self.stack.ip6()
    }
    fn mtu(&self) -> Option<i64> {
        Some(self.mtu)
    }
    /// firestack `wgproxy.Stat`
    fn stat(&self) -> RouterStats {
        let st = &self.st;
        let cfg = self.cfg.read();
        let hs = st.latest_handshake.load(Ordering::Relaxed);
        let ended = self.status() == END;
        RouterStats {
            hdl: format!("{}:{:x}", self.id, self.hdl),
            addrs: cfg
                .ifaddrs
                .iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(","),
            rx: if ended {
                -1
            } else {
                st.rx_bytes.load(Ordering::Relaxed)
            },
            tx: if ended {
                -2
            } else {
                st.tx_bytes.load(Ordering::Relaxed)
            },
            last_ok: if ended { -3 } else { hs },
            err_rx: st.err_rx.load(Ordering::Relaxed),
            err_tx: st.err_tx.load(Ordering::Relaxed),
            last_err: st.last_err.lock().clone(),
            last_rx_err: st.last_rx_err.lock().clone(),
            last_tx_err: st.last_tx_err.lock().clone(),
            last_rx: st.latest_rx.load(Ordering::Relaxed),
            last_tx: st.latest_tx.load(Ordering::Relaxed),
            last_good_rx: st.latest_good_rx.load(Ordering::Relaxed),
            last_good_tx: st.latest_good_tx.load(Ordering::Relaxed),
            last_refresh: st.latest_refresh.load(Ordering::Relaxed),
            last_open: st.latest_open.load(Ordering::Relaxed),
            since: st.since.load(Ordering::Relaxed),
            status: status_str(self.status()).into(),
            status_reason: st.reason.lock().clone(),
            extra: format!(
                "{}\n{}\nallowed:{}",
                self.endpoints
                    .read()
                    .iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
                cfg.dns.join(","),
                cfg.allowed
                    .iter()
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        }
    }
    /// firestack `wgtun.Contains`: within the peers' allowed IPs, in a family the interface has.
    fn contains(&self, _who: &str, ipp: &str) -> bool {
        if !self.rt.has_any(ipp).unwrap_or(false) {
            return false;
        }
        match crate::addr_of(ipp) {
            Some(IpAddr::V4(_)) => self.ip4(),
            Some(IpAddr::V6(_)) => self.ip6(),
            None => true,
        }
    }
    /// firestack `wgtun.Self`: a peer endpoint address.
    fn is_self(&self, ip: &str) -> bool {
        let Ok(ip) = ip.parse::<IpAddr>() else {
            return false;
        };
        self.endpoints
            .read()
            .iter()
            .any(|a| a.ip().to_canonical() == ip.to_canonical())
    }
    fn reaches(&self, csv: &str) -> bool {
        csv.is_empty() || csv.split(',').map(str::trim).any(|h| self.contains("", h))
    }
    fn via(&self) -> Option<SharedProxy> {
        self.st.via()
    }
    /// Routes the tunnel's UDP through `via` (rebinding the device).
    fn hop(&self, via: Option<SharedProxy>, dryrun: bool) -> crate::Result<()> {
        if dryrun {
            return Ok(());
        }
        *self.st.via.lock() = via.as_ref().map(Arc::downgrade);
        let dev = self.dev.clone();
        self.handle.spawn(async move {
            if let Some(d) = dev.lock().await.as_ref() {
                d.suspend().await;
                let _ = d.resume().await;
            }
        });
        Ok(())
    }
    fn pause(&self) -> bool {
        let cur = self.status();
        if cur == END
            || self
                .st
                .status
                .compare_exchange(cur, TPU, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
        {
            return false;
        }
        let dev = self.dev.clone();
        self.handle.spawn(async move {
            if let Some(d) = dev.lock().await.as_ref() {
                d.suspend().await;
            }
        });
        true
    }
    fn resume(&self) -> bool {
        if self
            .st
            .status
            .compare_exchange(TPU, TUP, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return false;
        }
        let dev = self.dev.clone();
        self.handle.spawn(async move {
            if let Some(d) = dev.lock().await.as_ref() {
                let _ = d.resume().await;
            }
        });
        true
    }
    fn stop(&self) {
        self.st.status.store(END, Ordering::Relaxed);
        self.stack.close();
        let dev = self.dev.clone();
        self.handle.spawn(async move {
            if let Some(d) = dev.lock().await.take() {
                d.stop().await;
            }
        });
    }
    /// firestack `Refresh`: re-resolves the peers' endpoints and handshakes again.
    fn refresh(&self) -> crate::Result<()> {
        crate::candial(self.status())?;
        self.st
            .latest_refresh
            .store(now_millis(), Ordering::Relaxed);
        self.ping();
        Ok(())
    }
    /// firestack `Ping`: a handshake with every peer (re-resolving endpoints).
    fn ping(&self) -> bool {
        if crate::candial(self.status()).is_err() {
            return false;
        }
        let dev = self.dev.clone();
        let cfg = self.cfg.read().clone();
        let resolver = self.resolver.clone();
        self.handle.spawn(async move {
            let mut g = dev.lock().await;
            let Some(d) = g.as_mut() else { return };
            for p in &cfg.peers {
                let key = PublicKey::from(p.public_key);
                for e in &p.endpoints {
                    if let Some(a) = resolve(&resolver, e).await.first() {
                        let _ = d.modify_peer(&key, |m| m.set_endpoint(Some(*a))).await;
                        break;
                    }
                }
                let _ = d.force_handshake(&key).await;
            }
        });
        true
    }
    fn on_not_ok(&self) {
        let _ = self.refresh();
    }
    fn set_since(&self, ms: i64) {
        self.st.since.store(ms, Ordering::Relaxed);
    }
}

fn status_str(s: i32) -> &'static str {
    match s {
        TKO => "notok",
        TOK => "ok",
        TUP => "up",
        TZZ => "idle",
        TNT => "unresponsive",
        TPU => "paused",
        END => "ended",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fs_core::bridge::AllowAllBridge;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// The far end's bind: a plain loopback socket.
    struct Plain(Arc<tokio::net::UdpSocket>);
    #[derive(Clone)]
    struct PlainIo(Arc<tokio::net::UdpSocket>);
    impl UdpTransportFactory for Plain {
        type Send = PlainIo;
        type Recv = PlainIo;
        async fn bind(&mut self, _: &UdpTransportFactoryParams) -> io::Result<(PlainIo, PlainIo)> {
            Ok((PlainIo(self.0.clone()), PlainIo(self.0.clone())))
        }
    }
    impl UdpSend for PlainIo {
        type SendManyBuf = ();
        async fn send_to(&self, p: Packet, dst: SocketAddr) -> io::Result<()> {
            self.0.send_to(&p, dst).await.map(|_| ())
        }
    }
    impl UdpRecv for PlainIo {
        type RecvManyBuf = ();
        async fn recv_from(
            &mut self,
            pool: &mut PacketBufPool,
        ) -> io::Result<(Packet, SocketAddr)> {
            let mut b = pool.get();
            let (n, a) = self.0.recv_from(&mut b).await?;
            b.truncate(n);
            Ok((b, canon(a)))
        }
    }

    fn hex(k: &[u8; 32]) -> String {
        k.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// A WireGuard proxy against an in-process WireGuard peer (gotatun with its own userspace stack) that
    /// echoes TCP and UDP: handshakes, data both ways, stats and status.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tunnel_to_a_peer() {
        let (ck, sk) = ([7u8; 32], [9u8; 32]);
        let (cpub, spub) = (
            PublicKey::from(&StaticSecret::from(ck)).to_bytes(),
            PublicKey::from(&StaticSecret::from(sk)).to_bytes(),
        );
        // far end: 10.9.0.1, echo on tcp/udp 7
        let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sport = sock.local_addr().unwrap().port();
        let (tx, rx) = mpsc::channel(1024);
        let server = Stack::new(&[config::Net::parse("10.9.0.1/32").unwrap()], 1420, tx);
        let _dev = DeviceBuilder::new()
            .with_udp(Plain(sock))
            .with_ip_pair(ToStack(server.clone()), FromStack { rx, mtu: 1420 })
            .with_private_key(StaticSecret::from(sk))
            .with_peer(
                Peer::new(PublicKey::from(cpub)).with_allowed_ip("10.9.0.2/32".parse().unwrap()),
            )
            .build()
            .await
            .unwrap();
        let s2 = server.clone();
        tokio::spawn(async move {
            let mut c = s2.accept(7).await.unwrap();
            let mut b = [0u8; 64];
            while let Ok(n) = c.read(&mut b).await {
                if n == 0 || c.write_all(&b[..n]).await.is_err() {
                    break;
                }
            }
        });
        let us = server.udp_on(7).unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 1500];
            while let Ok((n, from)) = fs_dialers::Datagram::recv_from(&us, &mut b).await {
                let _ = fs_dialers::Datagram::send_to(&us, &b[..n], from).await;
            }
        });

        let txt = format!(
            "private_key={}\naddress=10.9.0.2/32\ndns=10.9.0.1\nmtu=1420\npublic_key={}\nendpoint=127.0.0.1:{sport}\n\
             allowed_ip=10.9.0.0/24\npersistent_keepalive_interval=25\n",
            hex(&ck),
            hex(&spub)
        );
        let b = Arc::new(AllowAllBridge);
        let lp = crate::proxifier::LinkProps {
            l3: "46".into(),
            mtu: 1500,
        };
        let w = WgProxy::new(
            "wg0",
            &txt,
            Protector::new(b),
            None,
            &lp,
            tokio::runtime::Handle::current(),
        )
        .unwrap();
        // firestack treats the configured MTU as the network MTU: 1420 - 80
        assert_eq!(
            (w.typ(), w.dns().as_str(), w.mtu()),
            ("wg", "10.9.0.1", Some(1340))
        );
        assert!(
            w.contains("c", "10.9.0.1:7") && !w.contains("c", "1.1.1.1:443"),
            "routes only allowed ips"
        );
        assert!(w.ip4() && !w.ip6());

        let dst: SocketAddr = "10.9.0.1:7".parse().unwrap();
        let mut c = w.dial_tcp(dst, Duration::from_secs(10)).await.unwrap();
        c.write_all(b"through the tunnel").await.unwrap();
        let mut got = [0u8; 18];
        tokio::time::timeout(Duration::from_secs(10), c.read_exact(&mut got))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&got, b"through the tunnel");

        let u = w.dial_udp(dst).await.unwrap();
        u.send(b"datagram").await.unwrap();
        let mut ub = [0u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(10), u.recv(&mut ub))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&ub[..n], b"datagram");

        let s = w.stat();
        assert!(s.last_ok > 0 && s.rx > 0 && s.tx > 0, "{s:?}");
        assert_eq!(w.status(), TOK);
        assert!(
            w.is_self("127.0.0.1"),
            "the peer endpoint is the proxy's own address"
        );
        w.stop();
        assert_eq!(w.status(), END);
        assert!(w.dial_tcp(dst, Duration::from_secs(1)).await.is_err());
    }

    #[test]
    fn mtu_reconciliation() {
        assert_eq!(
            reconcile_mtu(1500, 65535, 1280),
            1420,
            "link smaller than config: link - 80"
        );
        assert_eq!(reconcile_mtu(1500, 1280, 1280), 1200);
        assert_eq!(reconcile_mtu(0, 1420, 1280), 0, "unknown link");
    }
}
