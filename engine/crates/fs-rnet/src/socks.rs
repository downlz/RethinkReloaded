// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/rnet/socks5.go

//! SOCKS5 server (RFC 1928, username/password per RFC 1929): CONNECT and UDP ASSOCIATE. A UDP association lives
//! as long as its control connection; it relays only for the client's address, one egress per destination.

use crate::{Moved, Server, UDP_IDLE, relay};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

const VER: u8 = 5;
const NO_AUTH: u8 = 0;
const USER_PASS: u8 = 2;
const NO_METHOD: u8 = 0xff;
const CMD_CONNECT: u8 = 1;
const CMD_UDP: u8 = 3;
const ATYP_V4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_V6: u8 = 4;
const REP_OK: u8 = 0;
const REP_UNREACHABLE: u8 = 4;
const REP_CMD_UNSUPPORTED: u8 = 7;

pub(crate) async fn serve(s: &Arc<Server>, mut c: TcpStream, from: SocketAddr) {
    if handshake(s, &mut c).await.is_err() {
        return;
    }
    let Ok((cmd, atyp, dst)) = request(&mut c).await else {
        return;
    };
    match cmd {
        CMD_CONNECT => connect(s, c, from, atyp, &dst).await,
        CMD_UDP => associate(s, c, from).await,
        _ => {
            let _ = reply(&mut c, REP_CMD_UNSUPPORTED, None).await;
        }
    }
}

/// Method selection, then credentials when the server has them.
async fn handshake(s: &Server, c: &mut TcpStream) -> io::Result<()> {
    let mut h = [0u8; 2];
    c.read_exact(&mut h).await?;
    if h[0] != VER {
        return Err(io::Error::other("socks5: bad version"));
    }
    let mut methods = vec![0u8; h[1] as usize];
    c.read_exact(&mut methods).await?;
    let auth = !s.user.is_empty() || !s.pass.is_empty();
    let want = if auth { USER_PASS } else { NO_AUTH };
    if !methods.contains(&want) {
        c.write_all(&[VER, NO_METHOD]).await?;
        return Err(io::Error::other("socks5: no acceptable method"));
    }
    c.write_all(&[VER, want]).await?;
    if !auth {
        return Ok(());
    }
    let mut v = [0u8; 2];
    c.read_exact(&mut v).await?;
    let mut user = vec![0u8; v[1] as usize];
    c.read_exact(&mut user).await?;
    let mut pl = [0u8; 1];
    c.read_exact(&mut pl).await?;
    let mut pass = vec![0u8; pl[0] as usize];
    c.read_exact(&mut pass).await?;
    let ok = user == s.user.as_bytes() && pass == s.pass.as_bytes();
    c.write_all(&[1, if ok { 0 } else { 1 }]).await?;
    if ok {
        Ok(())
    } else {
        Err(io::Error::other("socks5: bad credentials"))
    }
}

/// `(cmd, atyp, "host:port")`
async fn request(c: &mut TcpStream) -> io::Result<(u8, u8, String)> {
    let mut h = [0u8; 4];
    c.read_exact(&mut h).await?;
    if h[0] != VER {
        return Err(io::Error::other("socks5: bad request"));
    }
    let host = match h[3] {
        ATYP_V4 => {
            let mut a = [0u8; 4];
            c.read_exact(&mut a).await?;
            Ipv4Addr::from(a).to_string()
        }
        ATYP_V6 => {
            let mut a = [0u8; 16];
            c.read_exact(&mut a).await?;
            format!("[{}]", Ipv6Addr::from(a))
        }
        ATYP_DOMAIN => {
            let mut l = [0u8; 1];
            c.read_exact(&mut l).await?;
            let mut d = vec![0u8; l[0] as usize];
            c.read_exact(&mut d).await?;
            String::from_utf8_lossy(&d).into_owned()
        }
        _ => return Err(io::Error::other("socks5: bad address type")),
    };
    let mut p = [0u8; 2];
    c.read_exact(&mut p).await?;
    Ok((h[1], h[3], format!("{host}:{}", u16::from_be_bytes(p))))
}

fn put_addr(out: &mut Vec<u8>, a: SocketAddr) {
    match a.ip().to_canonical() {
        IpAddr::V4(v4) => {
            out.push(ATYP_V4);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(ATYP_V6);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.extend_from_slice(&a.port().to_be_bytes());
}

async fn reply(c: &mut TcpStream, rep: u8, bound: Option<SocketAddr>) -> io::Result<()> {
    let mut b = vec![VER, rep, 0];
    put_addr(
        &mut b,
        bound.unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0))),
    );
    c.write_all(&b).await
}

async fn connect(s: &Arc<Server>, mut c: TcpStream, from: SocketAddr, atyp: u8, dst: &str) {
    let (tab, smm) = s.route("tcp", from, dst).await;
    let egress = if tab.block {
        Err(io::Error::other(crate::ERR_BLOCKED))
    } else {
        s.dial_tcp(dst).await
    };
    let e = match egress {
        Err(e) => {
            // firestack replies host-unreachable in the request's family
            let zero = if atyp == ATYP_V6 {
                SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
            } else {
                SocketAddr::from(([0, 0, 0, 0], 0))
            };
            let _ = reply(&mut c, REP_UNREACHABLE, Some(zero)).await;
            s.summarize(smm.done(Moved::default(), Some(e.to_string())));
            return;
        }
        Ok(e) => e,
    };
    let bound = match &e {
        fs_dialers::TcpConn::Sock(t) => t.local_addr().ok(),
        _ => None,
    };
    if let Err(err) = reply(&mut c, REP_OK, bound).await {
        s.summarize(smm.done(Moved::default(), Some(err.to_string())));
        return;
    }
    let (moved, err) = relay(c, e, &[]).await;
    s.summarize(smm.done(moved, err));
}

/// UDP ASSOCIATE: a relay socket next to the control connection's local address, for this client only.
async fn associate(s: &Arc<Server>, mut c: TcpStream, from: SocketAddr) {
    let local = match c.local_addr() {
        Ok(a) => a,
        Err(_) => return,
    };
    let sock = match UdpSocket::bind(SocketAddr::new(local.ip(), 0)).await {
        Ok(u) => Arc::new(u),
        Err(_) => {
            let _ = reply(&mut c, REP_UNREACHABLE, None).await;
            return;
        }
    };
    let Ok(mut bound) = sock.local_addr() else {
        return;
    };
    if bound.ip().is_loopback() {
        // clients behind a NAT or port forward (an emulator, adb) cannot reach our loopback by its address:
        // unspecified tells them to use the address they connected to
        bound.set_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    }
    if reply(&mut c, REP_OK, Some(bound)).await.is_err() {
        return;
    }
    // backhauls end when this association does (the sender drops)
    let (_end, end) = tokio::sync::watch::channel(());
    let relays = async {
        let mut egresses: HashMap<String, fs_dialers::UdpConn> = HashMap::new();
        let mut b = vec![0u8; 64 * 1024];
        loop {
            let Ok((n, client)) = sock.recv_from(&mut b).await else {
                return;
            };
            if client.ip().to_canonical() != from.ip().to_canonical() {
                continue; // only the client that asked
            }
            let Some((dst, off)) = parse_udp(&b[..n]) else {
                continue;
            };
            let data = b[off..n].to_vec();
            if let Some(e) = egresses.get(&dst) {
                if e.send(&data).await.is_ok() {
                    continue;
                }
                egresses.remove(&dst);
            }
            let (tab, smm) = s.route("udp", client, &dst).await;
            let e = if tab.block {
                Err(io::Error::other(crate::ERR_BLOCKED))
            } else {
                s.dial_udp(&dst).await
            };
            let e = match e {
                Ok(e) => e,
                Err(err) => {
                    s.summarize(smm.done(Moved::default(), Some(err.to_string())));
                    continue;
                }
            };
            let sent = e.send(&data).await;
            if let Err(err) = sent {
                s.summarize(smm.done(Moved::default(), Some(err.to_string())));
                continue;
            }
            egresses.insert(dst.clone(), e.clone());
            let (s, sock, tx0, end) = (s.clone(), sock.clone(), data.len() as i64, end.clone());
            tokio::spawn(async move {
                let (moved, err) = backhaul(&e, &sock, client, &dst, end).await;
                s.summarize(smm.done(
                    Moved {
                        rx: moved.rx,
                        tx: tx0 + moved.tx,
                    },
                    err,
                ));
            });
        }
    };
    // the association ends with its control connection
    let control = async {
        let mut sink = [0u8; 512];
        while matches!(c.read(&mut sink).await, Ok(n) if n > 0) {}
    };
    tokio::select! {
        _ = relays => {}
        _ = control => {}
    }
}

/// Replies from `dst` back to the client, wrapped in the SOCKS5 UDP header, until idle.
async fn backhaul(
    e: &fs_dialers::UdpConn,
    sock: &UdpSocket,
    client: SocketAddr,
    dst: &str,
    mut end: tokio::sync::watch::Receiver<()>,
) -> (Moved, Option<String>) {
    let mut moved = Moved::default();
    let mut b = vec![0u8; 64 * 1024];
    let hdr = udp_header(dst);
    loop {
        let n = tokio::select! {
            _ = end.changed() => return (moved, None),
            r = tokio::time::timeout(UDP_IDLE, e.recv(&mut b)) => match r {
                Err(_) => return (moved, None),
                Ok(Err(err)) => return (moved, Some(err.to_string())),
                Ok(Ok(n)) => n,
            },
        };
        moved.rx += n as i64;
        let mut out = hdr.clone();
        out.extend_from_slice(&b[..n]);
        if let Err(err) = sock.send_to(&out, client).await {
            return (moved, Some(err.to_string()));
        }
    }
}

/// `RSV RSV FRAG ATYP ADDR PORT` for `dst` ("host:port"; names as domains).
fn udp_header(dst: &str) -> Vec<u8> {
    let mut h = vec![0, 0, 0];
    if let Ok(a) = dst.parse::<SocketAddr>() {
        put_addr(&mut h, a);
    } else {
        let (host, port) = fs_proxy::upstream::split_host_port(dst);
        h.push(ATYP_DOMAIN);
        h.push(host.len().min(255) as u8);
        h.extend_from_slice(&host.as_bytes()[..host.len().min(255)]);
        h.extend_from_slice(&port.unwrap_or(0).to_be_bytes());
    }
    h
}

/// `("host:port", payload offset)`; fragments are dropped (as most servers do).
pub(crate) fn parse_udp(b: &[u8]) -> Option<(String, usize)> {
    if b.len() < 4 || b[2] != 0 {
        return None;
    }
    let (host, at) = match b[3] {
        ATYP_V4 if b.len() >= 10 => (Ipv4Addr::new(b[4], b[5], b[6], b[7]).to_string(), 8),
        ATYP_V6 if b.len() >= 22 => {
            let a: [u8; 16] = b[4..20].try_into().ok()?;
            (format!("[{}]", Ipv6Addr::from(a)), 20)
        }
        ATYP_DOMAIN if b.len() >= 5 && b.len() >= 7 + b[4] as usize => {
            let l = b[4] as usize;
            (String::from_utf8_lossy(&b[5..5 + l]).into_owned(), 5 + l)
        }
        _ => return None,
    };
    let port = u16::from_be_bytes([b[at], b[at + 1]]);
    Some((format!("{host}:{port}"), at + 2))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_headers_roundtrip() {
        for dst in ["1.2.3.4:53", "[2001:db8::1]:443", "example.com:80"] {
            let mut p = udp_header(dst);
            p.extend_from_slice(b"x");
            let (got, off) = parse_udp(&p).unwrap();
            assert_eq!((got.as_str(), &p[off..]), (dst, &b"x"[..]));
        }
        assert!(
            parse_udp(&[0, 0, 1, ATYP_V4, 1, 2, 3, 4, 0, 53]).is_none(),
            "fragments"
        );
        assert!(
            parse_udp(&[0, 0, 0, ATYP_DOMAIN, 9, b'a']).is_none(),
            "short"
        );
    }
}
