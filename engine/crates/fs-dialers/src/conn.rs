// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/protect/xdial.go (RDialer: Dial, Announce, Probe)

//! Connections and dialers. A connection is either a direct protected socket (the common case, with no
//! indirection) or one that lives elsewhere: tunnelled through a SOCKS5/HTTP proxy, or a socket of a userspace
//! network stack (WireGuard). [`Dial`] opens them by owner: the proxy id for the proxy layer, or the owner a
//! protected socket is handed to Kotlin with.

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpStream, UdpSocket};

/// A future borrowed for `'a`.
pub type Fut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A byte stream that is not a plain socket.
pub trait Stream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Stream for T {}

/// A stream connection.
pub enum TcpConn {
    Sock(TcpStream),
    Dyn(Box<dyn Stream>),
}

impl From<TcpStream> for TcpConn {
    fn from(s: TcpStream) -> Self {
        TcpConn::Sock(s)
    }
}

impl AsyncRead for TcpConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            TcpConn::Sock(s) => Pin::new(s).poll_read(cx, buf),
            TcpConn::Dyn(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TcpConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            TcpConn::Sock(s) => Pin::new(s).poll_write(cx, buf),
            TcpConn::Dyn(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            TcpConn::Sock(s) => Pin::new(s).poll_flush(cx),
            TcpConn::Dyn(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            TcpConn::Sock(s) => Pin::new(s).poll_shutdown(cx),
            TcpConn::Dyn(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            TcpConn::Sock(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            TcpConn::Dyn(s) => Pin::new(s).poll_write_vectored(cx, bufs),
        }
    }
    fn is_write_vectored(&self) -> bool {
        match self {
            TcpConn::Sock(s) => s.is_write_vectored(),
            TcpConn::Dyn(s) => s.is_write_vectored(),
        }
    }
}

/// A datagram endpoint that is not a plain socket (SOCKS5 UDP ASSOCIATE, a userspace stack's UDP socket).
pub trait Datagram: Send + Sync {
    /// to the connected peer
    fn send<'a>(&'a self, b: &'a [u8]) -> Fut<'a, io::Result<usize>>;
    /// from the connected peer
    fn recv<'a>(&'a self, b: &'a mut [u8]) -> Fut<'a, io::Result<usize>>;
    fn send_to<'a>(&'a self, b: &'a [u8], to: SocketAddr) -> Fut<'a, io::Result<usize>>;
    fn recv_from<'a>(&'a self, b: &'a mut [u8]) -> Fut<'a, io::Result<(usize, SocketAddr)>>;
    fn local_addr(&self) -> io::Result<SocketAddr>;
}

/// A datagram endpoint: connected (dial) or not (announce).
#[derive(Clone)]
pub enum UdpConn {
    Sock(Arc<UdpSocket>),
    Dyn(Arc<dyn Datagram>),
}

impl From<UdpSocket> for UdpConn {
    fn from(s: UdpSocket) -> Self {
        UdpConn::Sock(Arc::new(s))
    }
}

impl UdpConn {
    /// Multicast TTL / IPv6 hop limit for a plain socket (RFC 6762 §11: mDNS uses 255; sockets default to 1, which
    /// some responders drop). No-op for sockets of other stacks.
    pub fn set_multicast_hops(&self, v6: bool, hops: u32) -> io::Result<()> {
        match self {
            UdpConn::Sock(s) => {
                let r = socket2::SockRef::from(s.as_ref());
                if v6 {
                    r.set_multicast_hops_v6(hops)
                } else {
                    r.set_multicast_ttl_v4(hops)
                }
            }
            UdpConn::Dyn(_) => Ok(()),
        }
    }

    pub async fn send(&self, b: &[u8]) -> io::Result<usize> {
        match self {
            UdpConn::Sock(s) => s.send(b).await,
            UdpConn::Dyn(d) => d.send(b).await,
        }
    }
    pub async fn recv(&self, b: &mut [u8]) -> io::Result<usize> {
        match self {
            UdpConn::Sock(s) => s.recv(b).await,
            UdpConn::Dyn(d) => d.recv(b).await,
        }
    }
    pub async fn send_to(&self, b: &[u8], to: SocketAddr) -> io::Result<usize> {
        match self {
            UdpConn::Sock(s) => s.send_to(b, to).await,
            UdpConn::Dyn(d) => d.send_to(b, to).await,
        }
    }
    pub async fn recv_from(&self, b: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match self {
            UdpConn::Sock(s) => s.recv_from(b).await,
            UdpConn::Dyn(d) => d.recv_from(b).await,
        }
    }
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        match self {
            UdpConn::Sock(s) => s.local_addr(),
            UdpConn::Dyn(d) => d.local_addr(),
        }
    }
    /// The plain socket, when this is one.
    pub fn socket(&self) -> Option<&UdpSocket> {
        match self {
            UdpConn::Sock(s) => Some(s),
            UdpConn::Dyn(_) => None,
        }
    }
}

/// Opens connections on behalf of `who` (firestack `RDialer`).
pub trait Dial: Send + Sync {
    fn dial_tcp<'a>(
        &'a self,
        who: &'a str,
        dst: SocketAddr,
        timeout: Duration,
    ) -> Fut<'a, io::Result<TcpConn>>;
    /// a datagram endpoint connected to `dst`
    fn dial_udp<'a>(&'a self, who: &'a str, dst: SocketAddr) -> Fut<'a, io::Result<UdpConn>>;
    /// an unconnected datagram endpoint (dual-stack when `v6`)
    fn announce_udp<'a>(&'a self, who: &'a str, v6: bool) -> Fut<'a, io::Result<UdpConn>>;
    /// an ICMP echo socket towards `dst`'s family
    fn probe_icmp<'a>(&'a self, who: &'a str, dst: IpAddr) -> Fut<'a, io::Result<UdpConn>>;
}

impl Dial for crate::Protector {
    fn dial_tcp<'a>(
        &'a self,
        who: &'a str,
        dst: SocketAddr,
        timeout: Duration,
    ) -> Fut<'a, io::Result<TcpConn>> {
        Box::pin(async move {
            crate::Protector::dial_tcp(self, who, dst, timeout)
                .await
                .map(TcpConn::Sock)
        })
    }
    fn dial_udp<'a>(&'a self, who: &'a str, dst: SocketAddr) -> Fut<'a, io::Result<UdpConn>> {
        Box::pin(async move {
            crate::Protector::dial_udp(self, who, dst)
                .await
                .map(UdpConn::from)
        })
    }
    fn announce_udp<'a>(&'a self, who: &'a str, v6: bool) -> Fut<'a, io::Result<UdpConn>> {
        Box::pin(async move {
            crate::Protector::announce_udp(self, who, v6)
                .await
                .map(UdpConn::from)
        })
    }
    fn probe_icmp<'a>(&'a self, who: &'a str, dst: IpAddr) -> Fut<'a, io::Result<UdpConn>> {
        Box::pin(async move {
            crate::Protector::probe_icmp(self, who, dst)
                .await
                .map(UdpConn::from)
        })
    }
}

/// Shared dialer.
pub type SharedDial = Arc<dyn Dial>;
