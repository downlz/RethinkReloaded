// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/ipn/proxies.go (ids, types, statuses, Proxy, predicates)
// Derived-From: celzero/firestack@d3d530ea3e:intra/ipn/proxy.go (healthy, candial)
// Derived-From: celzero/firestack@d3d530ea3e:intra/ipn/nop.go (GW router)
// Derived-From: celzero/firestack@d3d530ea3e:intra/backend/ipn_proxies.go (constants, RouterStats)

//! Proxies (`backend.Proxies`): a registry of egress paths by id. The built-in ones dial directly through
//! protected sockets (`Exit`, `Base`), refuse (`Block`) or choose for the flow (`Auto`); Kotlin adds SOCKS5, HTTP and
//! WireGuard ones. Flows and DNS transports dial through [`Proxifier`], by proxy id.

pub mod builtin;
pub mod http1;
pub mod proxifier;
pub mod socks5;
pub mod upstream;
pub mod wg;

pub use proxifier::Proxifier;

use fs_dialers::{Fut, TcpConn, UdpConn};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ids (backend constants)
pub const BLOCK: &str = "Block";
pub const BASE: &str = "Base";
pub const EXIT: &str = "Exit";
pub const INGRESS: &str = "Ingress";
pub const AUTO: &str = "Auto";
pub const ORBOT_S5: &str = "OrbotSocks5";
pub const ORBOT_H1: &str = "OrbotHttp1";
pub const GLOBAL_H1: &str = "GlobalHttp1";
pub const RPN64: &str = "nat64rpn";

// types
pub const SOCKS5: &str = "socks5";
pub const HTTP1: &str = "http1";
pub const WG: &str = "wg";
pub const WGFAST: &str = "gsro";
pub const NOOP: &str = "noop";
pub const INTERNET: &str = "net";
pub const RPN: &str = "rpn";
pub const PIPH2: &str = "piph2";
pub const PIPWS: &str = "pipws";

// statuses
pub const TPU: i32 = 3;
pub const TNT: i32 = 2;
pub const TZZ: i32 = 1;
pub const TUP: i32 = 0;
pub const TOK: i32 = -1;
pub const TKO: i32 = -2;
pub const END: i32 = -3;

pub const NOMTU: i64 = 0;
pub const MAXMTU: i64 = 65535;
pub const MIN_MTU4: i64 = 576;
pub const MIN_MTU6: i64 = 1280;

/// firestack `tzzTimeout`: time without new connections before a proxy is idle
pub const TZZ_TIMEOUT: Duration = Duration::from_secs(120);
/// firestack `lastOKThreshold`
pub const LAST_OK_THRESHOLD: Duration = Duration::from_secs(600);
/// firestack `ageThreshold`: time for a proxy to start up
pub const AGE_THRESHOLD: Duration = Duration::from_secs(10);

pub type Result<T> = std::result::Result<T, String>;

pub fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// `backend.RouterStats`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RouterStats {
    pub hdl: String,
    pub addrs: String,
    pub rx: i64,
    pub tx: i64,
    pub err_rx: i64,
    pub err_tx: i64,
    pub last_tx: i64,
    pub last_rx: i64,
    pub last_err: String,
    pub last_rx_err: String,
    pub last_tx_err: String,
    pub last_good_rx: i64,
    pub last_good_tx: i64,
    pub last_ok: i64,
    pub last_refresh: i64,
    pub last_open: i64,
    pub since: i64,
    pub status: String,
    pub status_reason: String,
    pub extra: String,
}

/// firestack `accStats`
pub fn acc_stats(a: &RouterStats, b: &RouterStats) -> RouterStats {
    RouterStats {
        tx: a.tx + b.tx,
        rx: a.rx + b.rx,
        err_rx: a.err_rx + b.err_rx,
        err_tx: a.err_tx + b.err_tx,
        last_ok: a.last_ok.max(b.last_ok),
        last_tx: a.last_tx.max(b.last_tx),
        last_rx: a.last_rx.max(b.last_rx),
        last_good_rx: a.last_good_rx.max(b.last_good_rx),
        last_good_tx: a.last_good_tx.max(b.last_good_tx),
        last_refresh: a.last_refresh.max(b.last_refresh),
        since: match (a.since > 0, b.since > 0) {
            (true, true) => a.since.min(b.since),
            (true, false) => a.since,
            _ => b.since,
        },
        status: format!("{};{}", a.status, b.status),
        status_reason: format!("{};{}", a.status_reason, b.status_reason),
        ..Default::default()
    }
}

/// An egress path (firestack `ipn.Proxy`, with its `Router`).
pub trait Proxy: Send + Sync {
    fn id(&self) -> &str;
    fn typ(&self) -> &str;
    /// address shown to the user (`GetAddr`)
    fn addr(&self) -> String;
    fn status(&self) -> i32;
    /// identity of this instance (`Handle`)
    fn handle(&self) -> u64;
    /// DNS servers of the proxy (WireGuard), csv
    fn dns(&self) -> String {
        String::new()
    }

    fn dial_tcp<'a>(&'a self, dst: SocketAddr, timeout: Duration) -> Fut<'a, io::Result<TcpConn>>;
    fn dial_udp<'a>(&'a self, dst: SocketAddr) -> Fut<'a, io::Result<UdpConn>>;
    fn announce_udp<'a>(&'a self, v6: bool) -> Fut<'a, io::Result<UdpConn>>;
    fn probe_icmp<'a>(&'a self, dst: IpAddr) -> Fut<'a, io::Result<UdpConn>>;

    // Router
    fn ip4(&self) -> bool;
    fn ip6(&self) -> bool;
    /// `None` when unknown (`errNoMtu`)
    fn mtu(&self) -> Option<i64> {
        None
    }
    fn stat(&self) -> RouterStats;
    /// does the proxy route `ipp_or_cidr`?
    fn contains(&self, who: &str, ipp_or_cidr: &str) -> bool;
    /// is `ip` the proxy's own endpoint (a flow to it would loop)?
    fn is_self(&self, ip: &str) -> bool;
    fn reaches(&self, csv: &str) -> bool;
    /// the proxy this one hops through
    fn via(&self) -> Option<Arc<dyn Proxy>> {
        None
    }
    fn hop(&self, _via: Option<Arc<dyn Proxy>>, _dryrun: bool) -> Result<()> {
        Err("proxy: nop".into())
    }
    /// can open unconnected UDP sockets (firestack `viaCanListen("udp")`, which tries `Announce`)
    fn can_announce(&self) -> bool {
        true
    }

    // lifecycle
    fn pause(&self) -> bool {
        false
    }
    fn resume(&self) -> bool {
        false
    }
    fn stop(&self);
    fn refresh(&self) -> Result<()> {
        Ok(())
    }
    fn ping(&self) -> bool {
        false
    }
    fn on_not_ok(&self) {}
    fn set_since(&self, _unix_millis: i64) {}
}

pub type SharedProxy = Arc<dyn Proxy>;

static HANDLES: AtomicU64 = AtomicU64::new(1);

/// A fresh instance handle (firestack uses the object's address).
pub fn new_handle() -> u64 {
    HANDLES.fetch_add(1, Ordering::Relaxed)
}

/// Base, Block, Exit, Rpn64, Ingress
pub fn local(id: &str) -> bool {
    matches!(id, BASE | BLOCK | EXIT | RPN64 | INGRESS)
}
pub fn automatic(id: &str) -> bool {
    id == AUTO
}
pub fn noop(typ: &str) -> bool {
    typ == NOOP
}
pub fn remote(id: &str) -> bool {
    !local(id) && !automatic(id)
}
pub fn immutable(id: &str) -> bool {
    local(id) || id == AUTO
}
pub fn is_rpn(id: &str) -> bool {
    id.contains(RPN)
}
pub fn is_internal(id: &str) -> bool {
    is_rpn(id) || immutable(id)
}
pub fn is_wg(id: &str) -> bool {
    id.starts_with(WG) || id.starts_with(WGFAST)
}
pub fn is_orbot(id: &str) -> bool {
    id == ORBOT_H1 || id == ORBOT_S5
}
pub fn is_wellknown(id: &str) -> bool {
    is_internal(id)
        || is_wg(id)
        || is_orbot(id)
        || id == GLOBAL_H1
        || id.starts_with(PIPH2)
        || id.starts_with(PIPWS)
}
pub fn cant_proxy_h3(id: &str) -> bool {
    id.contains("wgyrpn")
}

/// firestack `candial2`
pub fn candial(st: i32) -> Result<()> {
    match st {
        END => Err("proxy: stopped".into()),
        TPU => Err("proxy: paused".into()),
        _ => Ok(()),
    }
}

/// firestack `healthy`: local and no-op proxies are always fine; others must not be stopped or paused, and must
/// The engine runtime, captured by the first `Proxifier`: work spawned from Kotlin threads (JNI calls are not
/// on the runtime) lands there.
static RT: std::sync::OnceLock<tokio::runtime::Handle> = std::sync::OnceLock::new();

pub(crate) fn set_runtime(h: &tokio::runtime::Handle) {
    let _ = RT.set(h.clone());
}

/// A handle to the runtime the caller is on, else the engine's.
pub(crate) fn rt() -> tokio::runtime::Handle {
    tokio::runtime::Handle::try_current()
        .ok()
        .or_else(|| RT.get().cloned())
        .expect("proxy: no runtime (Proxifier not created)")
}

/// have been OK recently (an old proxy that never was, or was not for 10 min, is not); idle ones get pinged.
pub fn healthy(p: &SharedProxy) -> Result<()> {
    if local(p.id()) || noop(p.typ()) {
        return Ok(());
    }
    let status = p.status();
    candial(status)?;
    let stat = p.stat();
    let now = now_millis();
    let age = now - stat.last_open;
    let old_enough = age > AGE_THRESHOLD.as_millis() as i64;
    let never_ok = stat.last_ok <= 0;
    let beyond = stat.last_ok > 0 && now - stat.last_ok > LAST_OK_THRESHOLD.as_millis() as i64;
    let tzz = TZZ_TIMEOUT.as_millis() as i64;
    let ping = |p: &SharedProxy| {
        let p = p.clone();
        rt().spawn(async move {
            p.ping();
        });
    };
    if (old_enough && never_ok) || beyond {
        let p2 = p.clone();
        rt().spawn(async move { p2.on_not_ok() });
        return Err(format!(
            "proxy: {} not ok; never ok? {never_ok} / stale? {beyond}",
            p.id()
        ));
    } else if now - stat.last_ok > tzz
        || now - stat.last_good_tx > tzz
        || now - stat.last_good_rx > tzz
        || status != TOK
    {
        ping(p);
    }
    Ok(())
}

/// firestack `core.IP2Cidr2`: the address of an `ip`, `ip:port` or `ip/len`.
pub fn addr_of(ipp_or_cidr: &str) -> Option<IpAddr> {
    let s = ipp_or_cidr.trim();
    if let Some((ip, len)) = s.split_once('/') {
        let ip: IpAddr = ip.parse().ok()?;
        let len: u8 = len.parse().ok()?;
        let max = if ip.is_ipv4() { 32 } else { 128 };
        return (len <= max).then_some(ip);
    }
    s.parse::<SocketAddr>()
        .map(|a| a.ip())
        .or_else(|_| s.parse::<IpAddr>())
        .ok()
}

/// A gateway that routes every address of the families it supports (firestack `GW`).
#[derive(Default)]
pub struct Gw {
    pub nov4: bool,
    pub nov6: bool,
    since: AtomicI64,
    lastaddr: parking_lot::Mutex<Option<String>>,
}

impl Gw {
    pub fn new(nov4: bool, nov6: bool) -> Self {
        Gw {
            nov4,
            nov6,
            since: AtomicI64::new(now_millis()),
            lastaddr: parking_lot::Mutex::new(None),
        }
    }
    pub fn ip4(&self) -> bool {
        !self.nov4
    }
    pub fn ip6(&self) -> bool {
        !self.nov6
    }
    pub fn set_since(&self, ms: i64) {
        self.since.store(ms, Ordering::Relaxed);
    }
    pub fn set_lastaddr(&self, a: String) {
        *self.lastaddr.lock() = Some(a);
    }
    pub fn lastaddr(&self) -> Option<String> {
        self.lastaddr.lock().clone()
    }
    pub fn stat(&self) -> RouterStats {
        RouterStats {
            last_ok: if !self.nov4 || !self.nov6 {
                now_millis()
            } else {
                0
            },
            since: self.since.load(Ordering::Relaxed),
            ..Default::default()
        }
    }
    pub fn is_self(&self, ip: &str) -> bool {
        if ip.is_empty() {
            return false;
        }
        self.lastaddr()
            .and_then(|a| a.parse::<SocketAddr>().ok())
            .is_some_and(|a| a.ip().to_string() == ip)
    }
    fn ok(&self, ip: IpAddr) -> bool {
        (self.ip4() && ip.is_ipv4()) || (self.ip6() && ip.is_ipv6())
    }
    pub fn contains(&self, ipp_or_cidr: &str) -> bool {
        addr_of(ipp_or_cidr).is_some_and(|ip| self.ok(ip))
    }
    /// firestack `GW.Reaches`: any address of the csv in a supported family (hostnames count when either is).
    pub fn reaches(&self, csv: &str) -> bool {
        if csv.is_empty() {
            return true;
        }
        csv.split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .any(|h| match addr_of(h) {
                Some(ip) => self.ok(ip),
                None => self.ip4() || self.ip6(),
            })
    }
}

/// firestack `addOrUpdateProxy`: `id` with WireGuard config text (ids starting `wg`), a proxy URL
/// (`socks5://`, `http(s)://`), or nothing (a config-less proxy that dials like Base).
pub fn add_proxy(px: &Arc<Proxifier>, id: &str, txt: &str) -> Result<SharedProxy> {
    if id.is_empty() {
        return Err("proxy: add failed".into());
    }
    let p: SharedProxy = if is_wg(id) {
        wg::WgProxy::new(
            id,
            txt,
            px.protector().clone(),
            px.host_resolver(),
            &px.link_props(),
            px.runtime().clone(),
        )?
    } else if txt.is_empty() {
        builtin::Direct::basic(id, px.protector().clone())
    } else {
        let opts = upstream::parse_url(txt)?;
        let (prot, res) = (px.protector().clone(), px.host_resolver());
        match opts.scheme.as_str() {
            "socks5" => socks5::Socks5::new(id, opts, prot, res)?,
            "http" | "https" => http1::Http1::new(id, opts, prot, res)?,
            "wg" => return Err(format!("proxy: id must be prefixed with {WG} in {id}")),
            _ => return Err("proxy: unsupported scheme".into()),
        }
    };
    if !px.add(p.clone()) {
        return Err("proxy: add failed".into());
    }
    Ok(p)
}
