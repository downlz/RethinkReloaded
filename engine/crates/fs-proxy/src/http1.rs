// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/ipn/http1.go
// Derived-From: celzero/firestack@d3d530ea3e:intra/ipn/h1/dialer.go (HttpTunnel: CONNECT, 407 challenge)
// Derived-From: celzero/firestack@d3d530ea3e:intra/ipn/h1/auth.go (Basic)

//! HTTP proxies (`http(s)://[user:pass@]host[:port]`, Orbot's `OrbotHttp1`, `GlobalHttp1`): TCP through CONNECT,
//! optionally over TLS to the proxy; no UDP (as firestack). Default ports are 8080 (http) and 443 (https).

use crate::upstream::{HostResolver, Opts, Upstream};
use crate::{HTTP1, Proxy, RouterStats, SharedProxy, new_handle};
use base64::Engine;
use fs_dialers::{Fut, Protector, TcpConn, UdpConn};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAX_HEADER: usize = 16 * 1024;

pub struct Http1 {
    up: Upstream,
    hdl: u64,
    port: u16,
    tls: bool,
}

impl Http1 {
    pub fn new(
        id: &str,
        opts: Opts,
        protector: Protector,
        resolver: Option<HostResolver>,
    ) -> Result<Arc<Self>, String> {
        if opts.ip.is_none() && opts.host.is_empty() {
            return Err(format!("proxy: http1 {id}: missing host"));
        }
        let tls = opts.scheme == "https";
        let port = opts.port.unwrap_or(if tls { 443 } else { 8080 });
        Ok(Arc::new(Http1 {
            up: Upstream::new(id, opts, protector, resolver),
            hdl: new_handle(),
            port,
            tls,
        }))
    }

    fn auth_header(&self) -> Option<String> {
        let o = &self.up.opts;
        o.has_auth().then(|| {
            let creds =
                base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", o.user, o.pass));
            format!("Proxy-Authorization: Basic {creds}\r\n")
        })
    }

    async fn proxy_conn(&self, timeout: Duration) -> io::Result<TcpConn> {
        let (c, a) = self.up.dial(self.port, timeout).await?;
        if !self.tls {
            return Ok(c);
        }
        // TLS to the proxy itself (server name: its hostname, else its address)
        let name = if self.up.opts.host.is_empty() {
            a.ip().to_string()
        } else {
            self.up.opts.host.clone()
        };
        let sni = rustls_pki_types::ServerName::try_from(name).map_err(io::Error::other)?;
        let cfg = fs_dns::tls::client_config(&[]);
        let s = tokio_rustls::TlsConnector::from(cfg)
            .connect(sni, c)
            .await?;
        Ok(TcpConn::Dyn(Box::new(s)))
    }

    /// firestack `HttpTunnel.Dial`: CONNECT, answering one 407 challenge with Basic credentials.
    async fn connect(&self, dst: SocketAddr, timeout: Duration) -> io::Result<TcpConn> {
        let mut c = self.proxy_conn(timeout).await?;
        let r = tokio::time::timeout(timeout, async {
            let auth = self.auth_header();
            let mut status = roundtrip(&mut c, dst, auth.as_deref()).await?;
            if status == 407 && auth.is_some() {
                status = roundtrip(&mut c, dst, auth.as_deref()).await?;
            }
            if status != 200 {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("http1: tunnel: failed proxying {status}"),
                ));
            }
            Ok(())
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "http1: tunnel timeout"))?;
        r.map(|_| c)
    }
}

/// One CONNECT request; returns the response status. The response head is read byte by byte so that no tunnelled
/// bytes are consumed.
async fn roundtrip(c: &mut TcpConn, dst: SocketAddr, auth: Option<&str>) -> io::Result<u16> {
    let req = format!(
        "CONNECT {dst} HTTP/1.1\r\nHost: {dst}\r\nUser-Agent: Go-http-client/1.1\r\n{}\r\n",
        auth.unwrap_or("")
    );
    c.write_all(req.as_bytes()).await?;
    let mut head = Vec::with_capacity(256);
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if c.read(&mut b).await? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "http1: tunnel: proxy closed",
            ));
        }
        head.push(b[0]);
        if head.len() > MAX_HEADER {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "http1: tunnel: response too large",
            ));
        }
    }
    let line = head.split(|x| *x == b'\n').next().unwrap_or_default();
    let line = String::from_utf8_lossy(line);
    let status = line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("http1: tunnel: bad response {line:?}"),
            )
        })?;
    // a 407 with a body: skip it before retrying on the same connection
    if status == 407 {
        let text = String::from_utf8_lossy(&head).to_ascii_lowercase();
        let len = text
            .lines()
            .find_map(|l| l.strip_prefix("content-length:"))
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(0)
            .min(MAX_HEADER);
        let mut body = vec![0u8; len];
        c.read_exact(&mut body).await?;
    }
    Ok(status)
}

impl Proxy for Http1 {
    fn id(&self) -> &str {
        &self.up.id
    }
    fn typ(&self) -> &str {
        HTTP1
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
            let r = match self.up.via() {
                Some(v) => v.dial_tcp(dst, timeout).await, // firestack dials the hop directly
                None => self.connect(dst, timeout).await,
            };
            self.up.note(&r);
            r
        })
    }
    fn dial_udp<'a>(&'a self, _: SocketAddr) -> Fut<'a, io::Result<UdpConn>> {
        Box::pin(async {
            Err(io::Error::other(
                "http1: tunnel: network type 'udp' unsupported (only 'tcp')",
            ))
        })
    }
    fn announce_udp<'a>(&'a self, _: bool) -> Fut<'a, io::Result<UdpConn>> {
        Box::pin(async { Err(io::Error::other("proxy: announce not supported")) })
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
