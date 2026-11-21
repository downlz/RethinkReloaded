// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/ipn/socks5.go
// SOCKS5 client after RFC 1928 (CONNECT, UDP ASSOCIATE) and RFC 1929 (username/password), as the
// txthinking/socks5 client firestack uses.

//! SOCKS5 proxies (`socks5://[user:pass@]host:port`, and Orbot's `OrbotSocks5`): TCP through CONNECT, UDP through
//! UDP ASSOCIATE (the control connection stays open for as long as the association is used).

use crate::upstream::{HostResolver, Opts, Upstream};
use crate::{Proxy, RouterStats, SOCKS5, SharedProxy, new_handle};
use fs_dialers::{Datagram, Fut, Protector, TcpConn, UdpConn};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const VER: u8 = 5;
const CMD_CONNECT: u8 = 1;
const CMD_UDP_ASSOCIATE: u8 = 3;

fn proto_err(m: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, m.into())
}

/// SOCKS5 address encoding (ATYP + address + port).
fn put_addr(out: &mut Vec<u8>, a: SocketAddr) {
    match a.ip() {
        IpAddr::V4(v4) => {
            out.push(1);
            out.extend(v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(4);
            out.extend(v6.octets());
        }
    }
    out.extend(a.port().to_be_bytes());
}

/// Parses an address from `b`; returns it and the bytes consumed (domain names are not resolved: `None`).
fn get_addr(b: &[u8]) -> io::Result<(Option<SocketAddr>, usize)> {
    let atyp = *b
        .first()
        .ok_or_else(|| proto_err("socks5: short address"))?;
    let (ip, n) = match atyp {
        1 if b.len() >= 7 => (Some(IpAddr::V4(Ipv4Addr::new(b[1], b[2], b[3], b[4]))), 5),
        4 if b.len() >= 19 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(&b[1..17]);
            (Some(IpAddr::V6(Ipv6Addr::from(o))), 17)
        }
        3 if b.len() >= 2 && b.len() >= 2 + b[1] as usize + 2 => (None, 2 + b[1] as usize),
        _ => return Err(proto_err("socks5: bad address")),
    };
    let port = u16::from_be_bytes([b[n], b[n + 1]]);
    Ok((ip.map(|ip| SocketAddr::new(ip, port)), n + 2))
}

/// Method negotiation and (when credentials are set) RFC 1929 authentication.
async fn handshake(c: &mut TcpConn, o: &Opts) -> io::Result<()> {
    let auth = !o.user.is_empty() || !o.pass.is_empty();
    let greet: &[u8] = if auth {
        &[VER, 2, 0x00, 0x02]
    } else {
        &[VER, 1, 0x00]
    };
    c.write_all(greet).await?;
    let mut r = [0u8; 2];
    c.read_exact(&mut r).await?;
    if r[0] != VER {
        return Err(proto_err("socks5: not a socks5 server"));
    }
    match r[1] {
        0x00 => Ok(()),
        0x02 if auth => {
            let (u, p) = (o.user.as_bytes(), o.pass.as_bytes());
            if u.len() > 255 || p.len() > 255 {
                return Err(proto_err("socks5: credentials too long"));
            }
            let mut m = vec![1, u.len() as u8];
            m.extend(u);
            m.push(p.len() as u8);
            m.extend(p);
            c.write_all(&m).await?;
            c.read_exact(&mut r).await?;
            if r[1] != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "socks5: authentication failed",
                ));
            }
            Ok(())
        }
        _ => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "socks5: no acceptable auth method",
        )),
    }
}

/// A request (CONNECT / UDP ASSOCIATE); returns the bound address of the reply.
async fn request(c: &mut TcpConn, cmd: u8, dst: SocketAddr) -> io::Result<Option<SocketAddr>> {
    let mut m = vec![VER, cmd, 0];
    put_addr(&mut m, dst);
    c.write_all(&m).await?;
    let mut h = [0u8; 4];
    c.read_exact(&mut h).await?;
    if h[0] != VER {
        return Err(proto_err("socks5: bad reply"));
    }
    if h[1] != 0 {
        let why = match h[1] {
            2 => "connection not allowed by ruleset",
            3 => "network unreachable",
            4 => "host unreachable",
            5 => "connection refused",
            6 => "ttl expired",
            7 => "command not supported",
            8 => "address type not supported",
            _ => "general failure",
        };
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("socks5: {why}"),
        ));
    }
    let len = match h[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let mut l = [0u8; 1];
            c.read_exact(&mut l).await?;
            let mut skip = vec![0u8; l[0] as usize + 2];
            c.read_exact(&mut skip).await?;
            return Ok(None);
        }
        _ => return Err(proto_err("socks5: bad reply address")),
    };
    let mut rest = vec![0u8; len];
    c.read_exact(&mut rest).await?;
    let mut b = vec![h[3]];
    b.extend(rest);
    Ok(get_addr(&b)?.0)
}

pub struct Socks5 {
    up: Upstream,
    hdl: u64,
    port: u16,
}

impl Socks5 {
    pub fn new(
        id: &str,
        opts: Opts,
        protector: Protector,
        resolver: Option<HostResolver>,
    ) -> Result<Arc<Self>, String> {
        let port = opts
            .port
            .ok_or_else(|| format!("proxy: socks5 {id}: missing port in {}", opts.ipport))?;
        if opts.ip.is_none() && opts.host.is_empty() {
            return Err(format!("proxy: socks5 {id}: missing host"));
        }
        Ok(Arc::new(Socks5 {
            up: Upstream::new(id, opts, protector, resolver),
            hdl: new_handle(),
            port,
        }))
    }

    async fn connect(&self, dst: SocketAddr, timeout: Duration) -> io::Result<TcpConn> {
        let (mut c, _) = self.up.dial(self.port, timeout).await?;
        let r = tokio::time::timeout(timeout, async {
            handshake(&mut c, &self.up.opts).await?;
            request(&mut c, CMD_CONNECT, dst).await
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "socks5: handshake timeout"))?;
        r.map(|_| c)
    }

    /// UDP ASSOCIATE: a control connection and the server's relay endpoint.
    async fn associate(&self, peer: Option<SocketAddr>) -> io::Result<UdpConn> {
        let timeout = fs_dialers::DIAL_TIMEOUT;
        let (mut ctl, server) = self.up.dial(self.port, timeout).await?;
        let any = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        let bnd = tokio::time::timeout(timeout, async {
            handshake(&mut ctl, &self.up.opts).await?;
            request(&mut ctl, CMD_UDP_ASSOCIATE, any).await
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "socks5: associate timeout"))??;
        // an unspecified relay address means: the server's own address
        let relay = match bnd {
            Some(a) if !a.ip().is_unspecified() => a,
            Some(a) => SocketAddr::new(server.ip(), a.port()),
            None => return Err(proto_err("socks5: relay given by name")),
        };
        let udp = self.up.dial_udp(relay).await?;
        Ok(UdpConn::Dyn(Arc::new(Assoc {
            _ctl: tokio::sync::Mutex::new(ctl),
            udp,
            peer,
        })))
    }
}

/// A UDP association: datagrams carry a SOCKS5 header with the remote address (no fragmentation).
struct Assoc {
    /// held open: the association ends when it closes
    _ctl: tokio::sync::Mutex<TcpConn>,
    udp: UdpConn,
    peer: Option<SocketAddr>,
}

impl Assoc {
    fn wrap(b: &[u8], to: SocketAddr) -> Vec<u8> {
        let mut m = vec![0, 0, 0];
        put_addr(&mut m, to);
        m.extend_from_slice(b);
        m
    }
    async fn read(&self, out: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut buf = vec![0u8; out.len() + 262];
        loop {
            let n = self.udp.recv(&mut buf).await?;
            if n < 4 || buf[2] != 0 {
                continue; // short, or a fragment: dropped (firestack's client does not reassemble)
            }
            let (from, used) = get_addr(&buf[3..n])?;
            let Some(from) = from else { continue };
            let start = 3 + used;
            let len = (n - start).min(out.len());
            out[..len].copy_from_slice(&buf[start..start + len]);
            return Ok((len, from));
        }
    }
}

impl Datagram for Assoc {
    fn send<'a>(&'a self, b: &'a [u8]) -> Fut<'a, io::Result<usize>> {
        Box::pin(async move {
            let to = self
                .peer
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))?;
            self.udp.send(&Self::wrap(b, to)).await.map(|_| b.len())
        })
    }
    fn recv<'a>(&'a self, b: &'a mut [u8]) -> Fut<'a, io::Result<usize>> {
        Box::pin(async move { self.read(b).await.map(|(n, _)| n) })
    }
    fn send_to<'a>(&'a self, b: &'a [u8], to: SocketAddr) -> Fut<'a, io::Result<usize>> {
        Box::pin(async move { self.udp.send(&Self::wrap(b, to)).await.map(|_| b.len()) })
    }
    fn recv_from<'a>(&'a self, b: &'a mut [u8]) -> Fut<'a, io::Result<(usize, SocketAddr)>> {
        Box::pin(self.read(b))
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.udp.local_addr()
    }
}

impl Proxy for Socks5 {
    fn id(&self) -> &str {
        &self.up.id
    }
    fn typ(&self) -> &str {
        SOCKS5
    }
    fn addr(&self) -> String {
        self.up.addr()
    }
    fn status(&self) -> i32 {
        self.up.status()
    }
    fn handle(&self) -> u64 {
        self.hdl
    }
    fn dial_tcp<'a>(&'a self, dst: SocketAddr, timeout: Duration) -> Fut<'a, io::Result<TcpConn>> {
        Box::pin(async move {
            self.up.check()?;
            let r = self.connect(dst, timeout).await;
            self.up.note(&r);
            r
        })
    }
    fn dial_udp<'a>(&'a self, dst: SocketAddr) -> Fut<'a, io::Result<UdpConn>> {
        Box::pin(async move {
            self.up.check()?;
            let r = self.associate(Some(dst)).await;
            self.up.note(&r);
            r
        })
    }
    fn announce_udp<'a>(&'a self, _v6: bool) -> Fut<'a, io::Result<UdpConn>> {
        Box::pin(async move {
            self.up.check()?;
            let r = self.associate(None).await;
            self.up.note(&r);
            r
        })
    }
    fn probe_icmp<'a>(&'a self, _: IpAddr) -> Fut<'a, io::Result<UdpConn>> {
        Box::pin(async { Err(io::Error::other("proxy: probe not supported")) })
    }
    fn ip4(&self) -> bool {
        self.up.gw.ip4()
    }
    fn ip6(&self) -> bool {
        self.up.gw.ip6()
    }
    fn stat(&self) -> RouterStats {
        self.up.gw.stat()
    }
    fn contains(&self, _: &str, ipp: &str) -> bool {
        self.up.gw.contains(ipp)
    }
    fn is_self(&self, ip: &str) -> bool {
        self.up.is_self(ip)
    }
    fn reaches(&self, csv: &str) -> bool {
        self.up.gw.reaches(csv)
    }
    fn via(&self) -> Option<SharedProxy> {
        self.up.via()
    }
    fn hop(&self, via: Option<SharedProxy>, dryrun: bool) -> crate::Result<()> {
        if !dryrun {
            self.up.set_via(via);
        }
        Ok(())
    }
    fn pause(&self) -> bool {
        self.up.pause()
    }
    fn resume(&self) -> bool {
        self.up.resume()
    }
    fn stop(&self) {
        self.up.stop();
    }
    fn set_since(&self, ms: i64) {
        self.up.gw.set_since(ms);
    }
}
