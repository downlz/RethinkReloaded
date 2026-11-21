// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/ipn/wgnet.go (the userspace stack behind a WireGuard proxy)
// Derived-From: celzero/firestack@d3d530ea3e:intra/ipn/wgproxy.go (makeWgTun, setRoutes, Dial/Announce/Probe)

//! The userspace network stack inside a WireGuard proxy (firestack uses gVisor; this is smoltcp). Its interface
//! carries the proxy's addresses with a default route per family; decrypted packets come in through
//! [`Stack::input`], and packets the stack emits go out to WireGuard for encryption. Connections through the proxy
//! are sockets of this stack: TCP streams, UDP datagrams and ICMP echo probes.

use bytes::BytesMut;
use fs_dialers::{Datagram, Fut};
use parking_lot::Mutex;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{icmp, tcp, udp};
use smoltcp::time::Instant as SInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint};
use std::collections::VecDeque;
use std::future::poll_fn;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Notify, mpsc};

use super::config::Net;

const TCP_BUF: usize = 64 * 1024;
const UDP_PACKETS: usize = 64;
const RX_LIMIT: usize = 1024;
/// packets towards WireGuard that wait for encryption
pub const OUT_QUEUE: usize = 1024;

struct Queue {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    mtu: usize,
}

struct Rx(Vec<u8>);
struct Tx<'a>(&'a mut VecDeque<Vec<u8>>);

impl RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut b = vec![0u8; len];
        let r = f(&mut b);
        self.0.push_back(b);
        r
    }
}

impl Device for Queue {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;
    fn receive(&mut self, _: SInstant) -> Option<(Rx, Tx<'_>)> {
        let p = self.rx.pop_front()?;
        Some((Rx(p), Tx(&mut self.tx)))
    }
    fn transmit(&mut self, _: SInstant) -> Option<Tx<'_>> {
        Some(Tx(&mut self.tx))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = self.mtu;
        c
    }
}

struct Inner {
    iface: Interface,
    sockets: SocketSet<'static>,
    dev: Queue,
    /// sockets whose owners are gone: removed once closed
    orphans: Vec<SocketHandle>,
}

pub struct Stack {
    inner: Mutex<Inner>,
    kick: Arc<Notify>,
    out: mpsc::Sender<Vec<u8>>,
    port: AtomicU16,
    addr4: Option<IpAddr>,
    addr6: Option<IpAddr>,
    closed: AtomicBool,
}

fn err(m: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!("wg: {m}"))
}

impl Stack {
    /// A stack with `addrs` (default routes for each family present) and `mtu`; packets it emits go to `out`.
    pub fn new(addrs: &[Net], mtu: usize, out: mpsc::Sender<Vec<u8>>) -> Arc<Self> {
        let mut dev = Queue {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            mtu,
        };
        let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut dev, SInstant::now());
        let (mut a4, mut a6) = (None, None);
        iface.update_ip_addrs(|ips| {
            for n in addrs {
                if ips.push(IpCidr::new(IpAddress::from(n.ip), n.bits)).is_ok() {
                    match n.ip {
                        IpAddr::V4(_) if a4.is_none() => a4 = Some(n.ip),
                        IpAddr::V6(_) if a6.is_none() => a6 = Some(n.ip),
                        _ => {}
                    }
                }
            }
        });
        // point-to-point medium: the gateway is never resolved, only needed to have a route
        if let Some(IpAddr::V4(v4)) = a4 {
            let _ = iface.routes_mut().add_default_ipv4_route(v4);
        }
        if let Some(IpAddr::V6(v6)) = a6 {
            let _ = iface.routes_mut().add_default_ipv6_route(v6);
        }
        let seed = crate::new_handle() as u16;
        let s = Arc::new(Stack {
            inner: Mutex::new(Inner {
                iface,
                sockets: SocketSet::new(vec![]),
                dev,
                orphans: Vec::new(),
            }),
            kick: Arc::new(Notify::new()),
            out,
            port: AtomicU16::new(49152 + seed % 16000),
            addr4: a4,
            addr6: a6,
            closed: AtomicBool::new(false),
        });
        let me = Arc::downgrade(&s);
        tokio::spawn(async move {
            while let Some(s) = me.upgrade() {
                if s.closed.load(Ordering::Relaxed) {
                    break;
                }
                let delay = s.poll();
                let kick = s.kick.clone();
                drop(s); // a dropped proxy ends the loop
                match delay {
                    Some(d) => {
                        let _ = tokio::time::timeout(d, kick.notified()).await;
                    }
                    None => kick.notified().await,
                }
            }
        });
        s
    }

    /// One round of the stack: process input, emit output, reap closed orphans. Returns when to come back.
    fn poll(&self) -> Option<Duration> {
        let mut g = self.inner.lock();
        let now = SInstant::now();
        let Inner {
            iface,
            sockets,
            dev,
            orphans,
        } = &mut *g;
        iface.poll(now, dev, sockets);
        while let Some(p) = dev.tx.pop_front() {
            let _ = self.out.try_send(p); // dropped when WireGuard lags (as a full TUN would)
        }
        orphans.retain(|h| {
            let gone = match sockets.iter().find(|(x, _)| x == h).map(|(_, s)| s) {
                Some(smoltcp::socket::Socket::Tcp(t)) => {
                    matches!(t.state(), tcp::State::Closed | tcp::State::TimeWait)
                }
                Some(_) => true,
                None => false,
            };
            if gone {
                sockets.remove(*h);
            }
            !gone && sockets.iter().any(|(x, _)| x == *h)
        });
        iface
            .poll_delay(now, sockets)
            .map(|d| Duration::from_micros(d.total_micros()))
    }

    fn wake(&self) {
        self.kick.notify_one();
    }

    /// A decrypted packet from the tunnel.
    pub fn input(&self, p: Vec<u8>) {
        {
            let mut g = self.inner.lock();
            if g.dev.rx.len() >= RX_LIMIT {
                return;
            }
            g.dev.rx.push_back(p);
        }
        self.wake();
    }

    pub fn ip4(&self) -> bool {
        self.addr4.is_some()
    }

    /// New MTU for the interface (hops shrink it).
    pub fn set_mtu(&self, mtu: usize) {
        self.inner.lock().dev.mtu = mtu;
    }
    pub fn ip6(&self) -> bool {
        self.addr6.is_some()
    }

    fn local_port(&self) -> u16 {
        let p = self.port.fetch_add(1, Ordering::Relaxed);
        if p < 49152 {
            self.port.store(49153, Ordering::Relaxed);
            49152
        } else {
            p
        }
    }

    fn routable(&self, ip: IpAddr) -> io::Result<()> {
        let ok = if ip.is_ipv4() { self.ip4() } else { self.ip6() };
        if ok {
            Ok(())
        } else {
            Err(err(format!(
                "no route to {ip} (interface has no such family)"
            )))
        }
    }

    pub fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        self.wake();
    }

    fn orphan(&self, h: SocketHandle) {
        self.inner.lock().orphans.push(h);
        self.wake();
    }

    /// A TCP connection to `dst` through the tunnel.
    pub async fn connect(
        self: &Arc<Self>,
        dst: SocketAddr,
        timeout: Duration,
    ) -> io::Result<TcpStream> {
        self.routable(dst.ip())?;
        let mut s = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; TCP_BUF]),
            tcp::SocketBuffer::new(vec![0u8; TCP_BUF]),
        );
        s.set_nagle_enabled(false);
        s.set_keep_alive(Some(smoltcp::time::Duration::from_secs(60)));
        let h = {
            let mut g = self.inner.lock();
            let port = self.local_port();
            let Inner { iface, sockets, .. } = &mut *g;
            s.connect(iface.context(), IpEndpoint::from(dst), port)
                .map_err(err)?;
            sockets.add(s)
        };
        self.wake();
        let stream = TcpStream {
            stack: self.clone(),
            h,
        };
        let est = tokio::time::timeout(
            timeout,
            poll_fn(|cx| {
                let mut g = self.inner.lock();
                let s = g.sockets.get_mut::<tcp::Socket>(h);
                match s.state() {
                    tcp::State::Established => Poll::Ready(Ok(())),
                    tcp::State::SynSent | tcp::State::SynReceived => {
                        s.register_send_waker(cx.waker());
                        Poll::Pending
                    }
                    _ => Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "wg: connection refused",
                    ))),
                }
            }),
        )
        .await;
        match est {
            Ok(Ok(())) => Ok(stream),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("wg: dial tcp {dst}: i/o timeout"),
            )),
        }
    }

    /// Accepts one TCP connection on `port` (a tunnel's far end, in tests and for ingress).
    pub async fn accept(self: &Arc<Self>, port: u16) -> io::Result<TcpStream> {
        let mut s = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; TCP_BUF]),
            tcp::SocketBuffer::new(vec![0u8; TCP_BUF]),
        );
        s.listen(port).map_err(err)?;
        let h = self.inner.lock().sockets.add(s);
        let stream = TcpStream {
            stack: self.clone(),
            h,
        };
        poll_fn(|cx| {
            let mut g = self.inner.lock();
            let s = g.sockets.get_mut::<tcp::Socket>(h);
            if s.state() == tcp::State::Established {
                Poll::Ready(())
            } else {
                s.register_recv_waker(cx.waker());
                Poll::Pending
            }
        })
        .await;
        Ok(stream)
    }

    /// A UDP socket bound to `port` (unconnected).
    pub fn udp_on(self: &Arc<Self>, port: u16) -> io::Result<UdpSock> {
        let mut u = self.udp(None)?;
        let mut g = self.inner.lock();
        let s = g.sockets.get_mut::<udp::Socket>(u.h);
        s.close();
        s.bind(port).map_err(err)?;
        u.port = port;
        drop(g);
        Ok(u)
    }

    /// A UDP socket through the tunnel (connected to `peer` when given).
    pub fn udp(self: &Arc<Self>, peer: Option<SocketAddr>) -> io::Result<UdpSock> {
        if let Some(p) = peer {
            self.routable(p.ip())?;
        }
        let meta = || vec![udp::PacketMetadata::EMPTY; UDP_PACKETS];
        let mut s = udp::Socket::new(
            udp::PacketBuffer::new(meta(), vec![0u8; 64 * 1024]),
            udp::PacketBuffer::new(meta(), vec![0u8; 64 * 1024]),
        );
        let port = self.local_port();
        s.bind(port).map_err(err)?;
        let h = self.inner.lock().sockets.add(s);
        Ok(UdpSock {
            stack: self.clone(),
            h,
            peer,
            port,
        })
    }

    /// An ICMP echo probe through the tunnel.
    pub fn icmp(self: &Arc<Self>, dst: IpAddr) -> io::Result<IcmpProbe> {
        self.routable(dst)?;
        let meta = || vec![icmp::PacketMetadata::EMPTY; 8];
        let mut s = icmp::Socket::new(
            icmp::PacketBuffer::new(meta(), vec![0u8; 8 * 1500]),
            icmp::PacketBuffer::new(meta(), vec![0u8; 8 * 1500]),
        );
        let ident = (crate::new_handle() as u16) | 1;
        s.bind(icmp::Endpoint::Ident(ident)).map_err(err)?;
        let h = self.inner.lock().sockets.add(s);
        let src = if dst.is_ipv4() {
            self.addr4
        } else {
            self.addr6
        };
        Ok(IcmpProbe {
            stack: self.clone(),
            h,
            ident,
            src,
        })
    }
}

impl Drop for Stack {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Relaxed);
        self.kick.notify_one(); // ends the poll loop
    }
}

/// A TCP connection through the tunnel.
pub struct TcpStream {
    stack: Arc<Stack>,
    h: SocketHandle,
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        let r = {
            let mut g = me.stack.inner.lock();
            let s = g.sockets.get_mut::<tcp::Socket>(me.h);
            if s.can_recv() {
                match s.recv_slice(buf.initialize_unfilled()) {
                    Ok(n) => {
                        buf.advance(n);
                        Poll::Ready(Ok(()))
                    }
                    Err(e) => Poll::Ready(Err(err(e))),
                }
            } else if !s.may_recv() {
                Poll::Ready(Ok(())) // EOF
            } else {
                s.register_recv_waker(cx.waker());
                Poll::Pending
            }
        };
        if r.is_ready() {
            me.stack.wake(); // window update
        }
        r
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, b: &[u8]) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        let r = {
            let mut g = me.stack.inner.lock();
            let s = g.sockets.get_mut::<tcp::Socket>(me.h);
            if !s.may_send() {
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "wg: connection closed",
                )))
            } else if s.can_send() {
                Poll::Ready(s.send_slice(b).map_err(err))
            } else {
                s.register_send_waker(cx.waker());
                Poll::Pending
            }
        };
        if r.is_ready() {
            me.stack.wake();
        }
        r
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        me.stack
            .inner
            .lock()
            .sockets
            .get_mut::<tcp::Socket>(me.h)
            .close();
        me.stack.wake();
        Poll::Ready(Ok(()))
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        self.stack
            .inner
            .lock()
            .sockets
            .get_mut::<tcp::Socket>(self.h)
            .close();
        self.stack.orphan(self.h);
    }
}

/// A UDP socket through the tunnel.
pub struct UdpSock {
    stack: Arc<Stack>,
    h: SocketHandle,
    peer: Option<SocketAddr>,
    port: u16,
}

impl UdpSock {
    async fn send_inner(&self, b: &[u8], to: SocketAddr) -> io::Result<usize> {
        let to = SocketAddr::new(to.ip().to_canonical(), to.port()); // v4-mapped from dual-stack callers
        self.stack.routable(to.ip())?;
        poll_fn(|cx| {
            let mut g = self.stack.inner.lock();
            let s = g.sockets.get_mut::<udp::Socket>(self.h);
            if s.can_send() {
                Poll::Ready(
                    s.send_slice(b, IpEndpoint::from(to))
                        .map(|_| b.len())
                        .map_err(err),
                )
            } else {
                s.register_send_waker(cx.waker());
                Poll::Pending
            }
        })
        .await
        .inspect(|_| self.stack.wake())
    }
    async fn recv_inner(&self, out: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        poll_fn(|cx| {
            let mut g = self.stack.inner.lock();
            let s = g.sockets.get_mut::<udp::Socket>(self.h);
            loop {
                if !s.can_recv() {
                    s.register_recv_waker(cx.waker());
                    return Poll::Pending;
                }
                match s.recv_slice(out) {
                    Ok((n, m)) => {
                        let from = SocketAddr::new(IpAddr::from(m.endpoint.addr), m.endpoint.port);
                        // a connected socket only takes its peer's datagrams
                        if self.peer.is_some_and(|p| p != from) {
                            continue;
                        }
                        return Poll::Ready(Ok((n, from)));
                    }
                    Err(e) => return Poll::Ready(Err(err(e))),
                }
            }
        })
        .await
    }
}

impl Datagram for UdpSock {
    fn send<'a>(&'a self, b: &'a [u8]) -> Fut<'a, io::Result<usize>> {
        Box::pin(async move {
            let to = self
                .peer
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))?;
            self.send_inner(b, to).await
        })
    }
    fn recv<'a>(&'a self, b: &'a mut [u8]) -> Fut<'a, io::Result<usize>> {
        Box::pin(async move { self.recv_inner(b).await.map(|(n, _)| n) })
    }
    fn send_to<'a>(&'a self, b: &'a [u8], to: SocketAddr) -> Fut<'a, io::Result<usize>> {
        Box::pin(self.send_inner(b, to))
    }
    fn recv_from<'a>(&'a self, b: &'a mut [u8]) -> Fut<'a, io::Result<(usize, SocketAddr)>> {
        Box::pin(self.recv_inner(b))
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        let ip = self
            .stack
            .addr4
            .or(self.stack.addr6)
            .ok_or_else(|| err("no address"))?;
        Ok(SocketAddr::new(ip, self.port))
    }
}

impl Drop for UdpSock {
    fn drop(&mut self) {
        self.stack.orphan(self.h);
    }
}

/// Internet checksum over `parts`.
fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    for p in parts {
        let (pairs, rest) = p.as_chunks::<2>();
        for c in pairs {
            sum += u16::from_be_bytes(*c) as u32;
        }
        if let [last] = rest {
            sum += (*last as u32) << 8;
        }
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// An ICMP echo probe through the tunnel (like a kernel ping socket: the identifier becomes the probe's own and
/// checksums are filled in).
pub struct IcmpProbe {
    stack: Arc<Stack>,
    h: SocketHandle,
    ident: u16,
    src: Option<IpAddr>,
}

impl IcmpProbe {
    fn prepare(&self, b: &[u8], dst: IpAddr) -> io::Result<Vec<u8>> {
        if b.len() < 8 {
            return Err(err("short icmp message"));
        }
        let mut m = b.to_vec();
        m[4..6].copy_from_slice(&self.ident.to_be_bytes());
        m[2] = 0;
        m[3] = 0;
        let ck = match (dst, self.src) {
            (IpAddr::V4(_), _) => checksum(&[&m]),
            (IpAddr::V6(d), Some(IpAddr::V6(s))) => {
                let len = (m.len() as u32).to_be_bytes();
                checksum(&[&s.octets(), &d.octets(), &len, &[0, 0, 0, 58], &m])
            }
            _ => return Err(err("no source address for icmp")),
        };
        m[2..4].copy_from_slice(&ck.to_be_bytes());
        Ok(m)
    }
}

impl Datagram for IcmpProbe {
    fn send<'a>(&'a self, _: &'a [u8]) -> Fut<'a, io::Result<usize>> {
        Box::pin(async { Err(io::Error::from(io::ErrorKind::NotConnected)) })
    }
    fn recv<'a>(&'a self, b: &'a mut [u8]) -> Fut<'a, io::Result<usize>> {
        Box::pin(async move { self.recv_from(b).await.map(|(n, _)| n) })
    }
    fn send_to<'a>(&'a self, b: &'a [u8], to: SocketAddr) -> Fut<'a, io::Result<usize>> {
        Box::pin(async move {
            let m = self.prepare(b, to.ip())?;
            {
                let mut g = self.stack.inner.lock();
                g.sockets
                    .get_mut::<icmp::Socket>(self.h)
                    .send_slice(&m, IpAddress::from(to.ip()))
                    .map_err(err)?;
            }
            self.stack.wake();
            Ok(b.len())
        })
    }
    fn recv_from<'a>(&'a self, b: &'a mut [u8]) -> Fut<'a, io::Result<(usize, SocketAddr)>> {
        Box::pin(poll_fn(move |cx| {
            let mut g = self.stack.inner.lock();
            let s = g.sockets.get_mut::<icmp::Socket>(self.h);
            if !s.can_recv() {
                s.register_recv_waker(cx.waker());
                return Poll::Pending;
            }
            Poll::Ready(
                s.recv_slice(b)
                    .map(|(n, a)| (n, SocketAddr::new(IpAddr::from(a), 0)))
                    .map_err(err),
            )
        }))
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.src
            .map(|ip| SocketAddr::new(ip, 0))
            .ok_or_else(|| err("no address"))
    }
}

impl Drop for IcmpProbe {
    fn drop(&mut self) {
        self.stack.orphan(self.h);
    }
}

/// Packets bytes for gotatun.
pub fn to_bytes(p: Vec<u8>) -> BytesMut {
    BytesMut::from(&p[..])
}
