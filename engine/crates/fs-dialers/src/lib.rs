// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/protect/protect.go
// Derived-From: celzero/firestack@d3d530ea3e:intra/backend/protect.go
// Derived-From: celzero/firestack@d3d530ea3e:intra/dialers/xdial.go

//! Protected sockets. Every socket the engine opens towards the network is handed to Kotlin's `Controller`
//! (`bind4`/`bind6` with the destination, or the local wildcard for listens) *before* connecting, so that
//! `VpnService.protect` excludes it from the tunnel (otherwise traffic would loop back into the TUN).
//!
//! `who` is the owner of the dial: `"Exit"`, `"Base"`, or a proxy id. Kotlin skips protection for `"Base"` when
//! Rethink-in-Rethink (loopback) is on, deliberately routing that traffic back through the tunnel.

use fs_core::bridge::Controller;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

/// firestack dialer timeout.
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

pub const WHO_EXIT: &str = "Exit";
pub const WHO_BASE: &str = "Base";

/// Opens sockets protected through a [`Controller`].
#[derive(Clone)]
pub struct Protector {
    ctl: Arc<dyn Controller>,
}

impl Protector {
    pub fn new(ctl: Arc<dyn Controller>) -> Self {
        Protector { ctl }
    }

    /// Hands `sock` to Kotlin: `bind4`/`bind6` with `addrport` (firestack: tcp4/udp4 -> Bind4, tcp6/udp6 -> Bind6).
    async fn protect(&self, who: &str, sock: &Socket, v6: bool, addrport: String) {
        let fd = sock.as_raw_fd() as i64;
        if v6 {
            self.ctl.bind6(who.to_string(), addrport, fd).await
        } else {
            self.ctl.bind4(who.to_string(), addrport, fd).await
        }
    }

    fn socket(addr_v6: bool, ty: Type, proto: Protocol) -> io::Result<Socket> {
        let s = Socket::new(
            if addr_v6 { Domain::IPV6 } else { Domain::IPV4 },
            ty,
            Some(proto),
        )?;
        s.set_nonblocking(true)?;
        s.set_cloexec(true)?;
        Ok(s)
    }

    /// Protected TCP connection to `dst` within `timeout`.
    pub async fn dial_tcp(
        &self,
        who: &str,
        dst: SocketAddr,
        timeout: Duration,
    ) -> io::Result<TcpStream> {
        let s = Self::socket(dst.is_ipv6(), Type::STREAM, Protocol::TCP)?;
        s.set_tcp_nodelay(true)?;
        self.protect(who, &s, dst.is_ipv6(), dst.to_string()).await;
        let std_stream: std::net::TcpStream = s.into();
        let sock = TcpSocket::from_std_stream(std_stream);
        match tokio::time::timeout(timeout, sock.connect(dst)).await {
            Ok(r) => r,
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("dial tcp {dst}: i/o timeout"),
            )),
        }
    }

    /// Protected UDP socket connected to `dst`.
    pub async fn dial_udp(&self, who: &str, dst: SocketAddr) -> io::Result<UdpSocket> {
        let s = Self::socket(dst.is_ipv6(), Type::DGRAM, Protocol::UDP)?;
        self.protect(who, &s, dst.is_ipv6(), dst.to_string()).await;
        let local: SocketAddr = if dst.is_ipv6() {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        };
        s.bind(&SockAddr::from(local))?;
        let u = UdpSocket::from_std(s.into())?;
        u.connect(dst).await?;
        Ok(u)
    }

    /// Protected, unconnected UDP socket (endpoint-independent mapping: one socket per source, many remotes).
    /// firestack announces on `udp4 0.0.0.0:0` when the peer is IPv4 and IPv6 is off, else dual-stack `[::]:0`.
    pub async fn announce_udp(&self, who: &str, v6: bool) -> io::Result<UdpSocket> {
        let s = Self::socket(v6, Type::DGRAM, Protocol::UDP)?;
        let local: SocketAddr = if v6 {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        };
        if v6 {
            s.set_only_v6(false)?;
        }
        self.protect(who, &s, v6, local.to_string()).await;
        s.bind(&SockAddr::from(local))?;
        UdpSocket::from_std(s.into())
    }

    /// Protected unprivileged ICMP echo socket (`SOCK_DGRAM` + `IPPROTO_ICMP[V6]`). firestack binds with the bare
    /// wildcard IP (no port) as `addrport`.
    pub async fn probe_icmp(&self, who: &str, dst: IpAddr) -> io::Result<UdpSocket> {
        let v6 = dst.is_ipv6();
        let proto = if v6 {
            Protocol::ICMPV6
        } else {
            Protocol::ICMPV4
        };
        let s = Self::socket(v6, Type::DGRAM, proto)?;
        let wildcard = if v6 { "::" } else { "0.0.0.0" };
        self.protect(who, &s, v6, wildcard.to_string()).await;
        UdpSocket::from_std(s.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fs_core::bridge::BoxFuture;
    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[derive(Default)]
    struct Recorder(Mutex<Vec<(String, String, String)>>);
    impl Controller for Recorder {
        fn bind4(&self, who: String, addrport: String, _fd: i64) -> BoxFuture<()> {
            self.0.lock().unwrap().push(("bind4".into(), who, addrport));
            Box::pin(async {})
        }
        fn bind6(&self, who: String, addrport: String, _fd: i64) -> BoxFuture<()> {
            self.0.lock().unwrap().push(("bind6".into(), who, addrport));
            Box::pin(async {})
        }
        fn protect(&self, who: String, _fd: i64) -> BoxFuture<()> {
            self.0
                .lock()
                .unwrap()
                .push(("protect".into(), who, String::new()));
            Box::pin(async {})
        }
    }

    #[tokio::test]
    async fn tcp_and_udp_are_protected_before_use() {
        let rec = Arc::new(Recorder::default());
        let p = Protector::new(rec.clone());

        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            let (mut c, _) = l.accept().await.unwrap();
            c.write_all(b"hi").await.unwrap();
        });
        let mut c = p.dial_tcp(WHO_EXIT, addr, DIAL_TIMEOUT).await.unwrap();
        let mut buf = [0u8; 2];
        c.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hi");
        srv.await.unwrap();

        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let eaddr = echo.local_addr().unwrap();
        let u = p.dial_udp(WHO_BASE, eaddr).await.unwrap();
        u.send(b"x").await.unwrap();
        let mut b = [0u8; 4];
        let (n, from) = echo.recv_from(&mut b).await.unwrap();
        assert_eq!((n, from.ip()), (1, u.local_addr().unwrap().ip()));

        let calls = rec.0.lock().unwrap().clone();
        assert_eq!(calls[0], ("bind4".into(), "Exit".into(), addr.to_string()));
        assert_eq!(calls[1], ("bind4".into(), "Base".into(), eaddr.to_string()));
    }

    #[tokio::test]
    async fn dial_timeout() {
        let p = Protector::new(Arc::new(Recorder::default()));
        // TEST-NET-1 is unroutable: connect should time out
        let r = p
            .dial_tcp(
                WHO_EXIT,
                "192.0.2.1:9".parse().unwrap(),
                Duration::from_millis(200),
            )
            .await;
        assert!(r.is_err());
    }
}
