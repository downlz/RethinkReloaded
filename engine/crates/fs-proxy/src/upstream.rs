// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/settings/proxyopts.go (NewAuthProxyOptions)
// Derived-From: celzero/firestack@d3d530ea3e:intra/ipn/proxy.go (addOrUpdateProxy URL parsing)
// Derived-From: celzero/firestack@d3d530ea3e:intra/ipn/multihost/multihost.go (proxy host addresses)

//! What SOCKS5 and HTTP proxies share: their options (from Kotlin's proxy URL), their upstream's addresses, and
//! dialing that upstream: protected as the proxy's own id, or through the proxy it hops through.

use crate::{END, Gw, Proxy, SharedProxy, TPU, TUP, TZZ, now_millis};
use fs_dialers::{Protector, TcpConn, UdpConn};
use parking_lot::{Mutex, RwLock};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicI32, AtomicI64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

/// Resolves a hostname (the engine's resolver; set by the tunnel).
pub type HostResolver =
    Arc<dyn Fn(String) -> fs_core::bridge::BoxFuture<Vec<IpAddr>> + Send + Sync>;

/// firestack `ProxyOptions`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Opts {
    pub scheme: String,
    pub user: String,
    pub pass: String,
    /// hostname (no port), when the proxy is not addressed by IP
    pub host: String,
    pub ip: Option<IpAddr>,
    pub port: Option<u16>,
    /// `ip:port`, `host:port` or `:port`, as given
    pub ipport: String,
}

impl Opts {
    pub fn has_auth(&self) -> bool {
        !self.user.is_empty() && !self.pass.is_empty()
    }
}

pub fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && let Ok(v) =
                u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("zz"), 16)
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Splits `host[:port]`, with `[v6]:port` and bare IPv6.
pub fn split_host_port(hp: &str) -> (String, Option<u16>) {
    if let Some(rest) = hp.strip_prefix('[')
        && let Some((h, tail)) = rest.split_once(']')
    {
        return (
            h.to_string(),
            tail.strip_prefix(':').and_then(|p| p.parse().ok()),
        );
    }
    if hp.matches(':').count() > 1 {
        return (hp.to_string(), None); // bare IPv6
    }
    match hp.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().ok()),
        None => (hp.to_string(), None),
    }
}

/// firestack `url.Parse` + `NewAuthProxyOptions`: `scheme://[user[:pass]@]host[:port][/…][#ip,ip]`.
pub fn parse_url(txt: &str) -> Result<Opts, String> {
    let (scheme, rest) = txt.split_once("://").ok_or("proxy: invalid config")?;
    let rest = rest.split('#').next().unwrap_or_default();
    let authority = rest.split(['/', '?']).next().unwrap_or_default();
    let (userinfo, hostport) = match authority.rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, authority),
    };
    let (user, pass) = match userinfo {
        Some(u) => match u.split_once(':') {
            Some((a, b)) => (pct_decode(a), pct_decode(b)),
            None => (pct_decode(u), String::new()),
        },
        None => (String::new(), String::new()),
    };
    let (host, port) = split_host_port(hostport);
    if host.is_empty() && port.is_none() {
        return Err("proxy: invalid config".into());
    }
    let ip = host.parse::<IpAddr>().ok();
    let ipport = match (ip, port) {
        (Some(ip), Some(p)) => SocketAddr::new(ip, p).to_string(),
        _ if host.is_empty() => format!(":{}", port.unwrap_or_default()),
        _ => hostport.to_string(),
    };
    Ok(Opts {
        scheme: if scheme.is_empty() {
            "http".into()
        } else {
            scheme.to_ascii_lowercase()
        },
        user,
        pass,
        host: if ip.is_some() { String::new() } else { host },
        ip,
        port,
        ipport,
    })
}

/// The proxy server and how to reach it.
pub struct Upstream {
    pub id: String,
    pub opts: Opts,
    pub protector: Protector,
    pub resolver: Option<HostResolver>,
    /// addresses of the proxy server (its own endpoint: flows to them must not loop through it)
    addrs: RwLock<Vec<IpAddr>>,
    via: Mutex<Option<Weak<dyn Proxy>>>,
    pub gw: Gw,
    pub status: AtomicI32,
    lastdial: AtomicI64,
}

impl Upstream {
    pub fn new(id: &str, opts: Opts, protector: Protector, resolver: Option<HostResolver>) -> Self {
        Upstream {
            id: id.to_string(),
            addrs: RwLock::new(opts.ip.into_iter().collect()),
            opts,
            protector,
            resolver,
            via: Mutex::new(None),
            gw: Gw::new(false, false),
            status: AtomicI32::new(TUP),
            lastdial: AtomicI64::new(0),
        }
    }

    pub fn check(&self) -> io::Result<()> {
        crate::candial(self.status.load(Ordering::Relaxed)).map_err(io::Error::other)
    }

    /// The server's addresses (resolving its hostname when needed).
    async fn addrs(&self, port: u16) -> Vec<SocketAddr> {
        let mut ips = self.addrs.read().clone();
        if ips.is_empty()
            && !self.opts.host.is_empty()
            && let Some(r) = &self.resolver
        {
            ips = r(self.opts.host.clone()).await;
            *self.addrs.write() = ips.clone();
        }
        ips.into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect()
    }

    pub fn via(&self) -> Option<SharedProxy> {
        self.via.lock().as_ref().and_then(Weak::upgrade)
    }

    pub fn set_via(&self, via: Option<SharedProxy>) {
        *self.via.lock() = via.as_ref().map(Arc::downgrade);
    }

    /// firestack `txdial` / `dialProxy`: the first server address that connects.
    pub async fn dial(&self, port: u16, timeout: Duration) -> io::Result<(TcpConn, SocketAddr)> {
        self.lastdial.store(now_millis(), Ordering::Relaxed);
        let addrs = self.addrs(port).await;
        if addrs.is_empty() {
            return Err(io::Error::other(format!(
                "proxy: {}: no address for {}",
                self.id, self.opts.ipport
            )));
        }
        let mut last = io::Error::other("proxy: no route to host");
        for a in addrs {
            let r = match self.via() {
                Some(v) => v.dial_tcp(a, timeout).await,
                None => self
                    .protector
                    .dial_tcp(&self.id, a, timeout)
                    .await
                    .map(TcpConn::Sock),
            };
            match r {
                Ok(c) => {
                    if let TcpConn::Sock(s) = &c
                        && let Ok(l) = s.local_addr()
                    {
                        self.gw.set_lastaddr(l.to_string());
                    }
                    return Ok((c, a));
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// A datagram socket to the server's relay (protected as the proxy, or through its hop).
    pub async fn dial_udp(&self, relay: SocketAddr) -> io::Result<UdpConn> {
        match self.via() {
            Some(v) => v.dial_udp(relay).await,
            None => self
                .protector
                .dial_udp(&self.id, relay)
                .await
                .map(UdpConn::from),
        }
    }

    /// firestack `localDialStatus`
    pub fn note<T>(&self, r: &io::Result<T>) {
        let cur = self.status.load(Ordering::Relaxed);
        if cur == END || cur == TPU {
            return;
        }
        let next = if r.is_ok() { crate::TOK } else { crate::TKO };
        let _ = self
            .status
            .compare_exchange(cur, next, Ordering::Relaxed, Ordering::Relaxed);
    }

    /// firestack socks5/http1 `Status`: idle (TZZ) after 2 min without dials.
    pub fn status(&self) -> i32 {
        let s = self.status.load(Ordering::Relaxed);
        if crate::candial(s).is_err() {
            return s;
        }
        if now_millis() - self.lastdial.load(Ordering::Relaxed)
            > crate::TZZ_TIMEOUT.as_millis() as i64
        {
            return TZZ;
        }
        s
    }

    pub fn pause(&self) -> bool {
        let st = self.status.load(Ordering::Relaxed);
        st != END
            && self
                .status
                .compare_exchange(st, TPU, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
    }

    pub fn resume(&self) -> bool {
        self.status
            .compare_exchange(TPU, TUP, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    }

    pub fn stop(&self) {
        self.status.store(END, Ordering::Relaxed);
    }

    /// firestack `Self`: the gateway's last local address, or one of the server's addresses.
    pub fn is_self(&self, ip: &str) -> bool {
        !ip.is_empty()
            && (self.gw.is_self(ip) || self.addrs.read().iter().any(|a| a.to_string() == ip))
    }

    pub fn addr(&self) -> String {
        self.gw
            .lastaddr()
            .unwrap_or_else(|| self.opts.ipport.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_urls() {
        let o = parse_url("socks5://u%40x:p%3Aw@127.0.0.1:9050").unwrap();
        assert_eq!((o.user.as_str(), o.pass.as_str()), ("u@x", "p:w"));
        assert_eq!(
            (o.ip, o.port, o.ipport.as_str()),
            (
                Some("127.0.0.1".parse().unwrap()),
                Some(9050),
                "127.0.0.1:9050"
            )
        );
        assert!(o.has_auth());
        let o = parse_url("http://proxy.example:3128/").unwrap();
        assert_eq!(
            (o.host.as_str(), o.port, o.ipport.as_str()),
            ("proxy.example", Some(3128), "proxy.example:3128")
        );
        let o = parse_url("https://[2001:db8::1]:443#1.2.3.4").unwrap();
        assert_eq!(
            (o.ip, o.port),
            (Some("2001:db8::1".parse().unwrap()), Some(443))
        );
        assert!(!o.has_auth());
        assert!(parse_url("nonsense").is_err());
    }
}
