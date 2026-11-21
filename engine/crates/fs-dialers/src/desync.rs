// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/dialers/split_and_desync.go

//! `SplitDesync`: the first segment is preceded by a decoy that middleboxes see but the server does not. The
//! decoy (an HTTP POST) is sent with `sendfile` from a memfd page and a TTL low enough to expire before the server
//! (found by a UDP traceroute whose ICMP "time exceeded" errors are read off the socket's error queue). Then the
//! page is overwritten with the real bytes and the TTL restored: the kernel's retransmission of that segment carries
//! the real data. The measured TTL is cached per address for 30 s; with no usable TTL (at most 3 hops) the
//! connection is left as it is. Linux only; elsewhere a plain connection.

use crate::{Protector, TcpConn};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
const PROBE_SIZE: usize = 8;
#[cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
const DEFAULT_TTL: u32 = 64;
#[cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
const DESYNC_PAYLOAD: &[u8] =
    b"POST / HTTP/1.1\r\nHost: 10.0.0.1\r\nContent-Type: application/octet-stream\r\nContent-Length: 9999999\r\n\r\n";
#[cfg_attr(not(any(target_os = "linux", target_os = "android")), allow(dead_code))]
const DESYNC_MAX_TTL: u32 = 20;
const DESYNC_NOOP_TTL: u32 = 3;
const DESYNC_CACHE_TTL: Duration = Duration::from_secs(30);

static TTLS: Mutex<Option<HashMap<IpAddr, (u32, Instant)>>> = Mutex::new(None);
static DECOYS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Decoys sent so far (diagnostics, tests).
pub fn decoys() -> u64 {
    DECOYS.load(std::sync::atomic::Ordering::Relaxed)
}

/// The cached desync TTL for `ip` (diagnostics, tests).
pub fn ttl_of(ip: IpAddr) -> Option<u32> {
    cached_ttl(ip)
}

fn cached_ttl(ip: IpAddr) -> Option<u32> {
    let g = TTLS.lock().unwrap_or_else(|e| e.into_inner());
    g.as_ref()?
        .get(&ip)
        .filter(|(_, exp)| *exp > Instant::now())
        .map(|(t, _)| *t)
}

fn cache_ttl(ip: IpAddr, ttl: u32) {
    let mut g = TTLS.lock().unwrap_or_else(|e| e.into_inner());
    let m = g.get_or_insert_with(HashMap::new);
    if m.len() >= 1024 {
        let now = Instant::now();
        m.retain(|_, (_, e)| *e > now);
    }
    m.insert(ip, (ttl, Instant::now() + DESYNC_CACHE_TTL));
}

/// firestack `dialWithSplitAndDesync`.
pub async fn dial(
    p: &Protector,
    who: &str,
    dst: SocketAddr,
    timeout: Duration,
) -> io::Result<TcpConn> {
    if let Some(ttl) = cached_ttl(dst.ip()) {
        let s = p.dial_tcp(who, dst, timeout).await?;
        return Ok(imp::wrap(s, ttl));
    }
    let (s, ttl) = imp::with_traceroute(p, who, dst, timeout).await?;
    cache_ttl(dst.ip(), ttl);
    Ok(imp::wrap(s, ttl))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod imp {
    use super::*;
    use socket2::SockRef;
    use std::os::fd::AsRawFd;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio::net::{TcpStream, UdpSocket};

    pub fn wrap(s: TcpStream, ttl: u32) -> TcpConn {
        TcpConn::Dyn(Box::new(Desync {
            s,
            ttl,
            used: ttl <= DESYNC_NOOP_TTL,
        }))
    }

    fn set_hops(s: SockRef<'_>, v6: bool, ttl: u32) -> io::Result<()> {
        if v6 {
            s.set_unicast_hops_v6(ttl)
        } else {
            s.set_ttl_v4(ttl)
        }
    }

    fn setsockopt_int(fd: i32, level: i32, opt: i32, v: i32) -> io::Result<()> {
        // SAFETY: a valid fd and a pointer to a live int of the passed size.
        let r = unsafe {
            libc::setsockopt(
                fd,
                level,
                opt,
                &v as *const i32 as *const libc::c_void,
                size_of::<i32>() as u32,
            )
        };
        if r == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// firestack `tracert`: UDP probes with TTLs 2..=20 to ports `base + ttl`, errors queued on the socket.
    async fn tracert(p: &Protector, who: &str, dst: IpAddr, base: u16) -> io::Result<UdpSocket> {
        let v6 = dst.is_ipv6();
        let u = p.announce_udp(who, v6).await?;
        if v6 {
            setsockopt_int(u.as_raw_fd(), libc::IPPROTO_IPV6, libc::IPV6_RECVERR, 1)?;
        } else {
            setsockopt_int(u.as_raw_fd(), libc::IPPROTO_IP, libc::IP_RECVERR, 1)?;
        }
        let mut msg = [0u8; PROBE_SIZE];
        for ttl in 2..=DESYNC_MAX_TTL {
            for b in msg.iter_mut() {
                *b = crate::split::rand_below(256) as u8;
            }
            set_hops(SockRef::from(&u), v6, ttl)?;
            u.send_to(&msg, SocketAddr::new(dst, base + ttl as u16))
                .await?;
        }
        Ok(u)
    }

    /// One queued error: the probe's destination port, when it was an ICMP time-exceeded (v4: type 11 code 0;
    /// v6: type 3 code 0).
    fn read_errqueue(fd: i32, v6: bool) -> Option<Option<u16>> {
        let mut data = [0u8; PROBE_SIZE];
        let mut cbuf = [0u8; 512];
        // SAFETY: zeroed C structs, pointing at live buffers of the stated sizes.
        unsafe {
            let mut name: libc::sockaddr_storage = std::mem::zeroed();
            let mut iov = libc::iovec {
                iov_base: data.as_mut_ptr() as *mut libc::c_void,
                iov_len: data.len(),
            };
            let mut m: libc::msghdr = std::mem::zeroed();
            m.msg_name = &mut name as *mut _ as *mut libc::c_void;
            m.msg_namelen = size_of::<libc::sockaddr_storage>() as u32;
            m.msg_iov = &mut iov;
            m.msg_iovlen = 1;
            m.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
            m.msg_controllen = cbuf.len() as _;
            if libc::recvmsg(fd, &mut m, libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT) < 0 {
                return None;
            }
            let (lvl, typ, origin, icmp_type) = if v6 {
                (
                    libc::IPPROTO_IPV6,
                    libc::IPV6_RECVERR,
                    libc::SO_EE_ORIGIN_ICMP6,
                    3,
                )
            } else {
                (
                    libc::IPPROTO_IP,
                    libc::IP_RECVERR,
                    libc::SO_EE_ORIGIN_ICMP,
                    11,
                )
            };
            let mut exceeded = false;
            let mut c = libc::CMSG_FIRSTHDR(&m);
            while !c.is_null() {
                if (*c).cmsg_level == lvl && (*c).cmsg_type == typ {
                    let ee = &*(libc::CMSG_DATA(c) as *const libc::sock_extended_err);
                    if ee.ee_origin == origin && ee.ee_type == icmp_type && ee.ee_code == 0 {
                        exceeded = true;
                    }
                }
                c = libc::CMSG_NXTHDR(&m, c);
            }
            if !exceeded {
                return Some(None);
            }
            let port = if v6 {
                u16::from_be((*(&name as *const _ as *const libc::sockaddr_in6)).sin6_port)
            } else {
                u16::from_be((*(&name as *const _ as *const libc::sockaddr_in)).sin_port)
            };
            Some(Some(port))
        }
    }

    /// firestack `desyncWithTraceroute`: the connection and the largest TTL that expired on the way.
    pub async fn with_traceroute(
        p: &Protector,
        who: &str,
        dst: SocketAddr,
        timeout: Duration,
    ) -> io::Result<(TcpStream, u32)> {
        let base = 1 + crate::split::rand_below((65535 - DESYNC_MAX_TTL) as u64) as u16;
        let u = tracert(p, who, dst.ip(), base).await.ok();
        // the TCP handshake gives the ICMP errors time to arrive
        let s = p.dial_tcp(who, dst, timeout).await?;
        let mut ttl = DESYNC_NOOP_TTL;
        if let Some(u) = &u {
            for _ in 0..DESYNC_MAX_TTL - 1 {
                match read_errqueue(u.as_raw_fd(), dst.is_ipv6()) {
                    None => break,
                    Some(None) => continue,
                    Some(Some(port)) => {
                        let t = port.wrapping_sub(base) as u32;
                        if t <= DESYNC_MAX_TTL {
                            ttl = ttl.max(t);
                        }
                    }
                }
            }
        }
        Ok((s, ttl))
    }

    /// firestack `overwriteSplitter`.
    struct Desync {
        s: TcpStream,
        ttl: u32,
        used: bool,
    }

    impl Desync {
        /// The decoy, then the real bytes in its page: returns how much of `b` is on its way.
        fn overwrite(&mut self, b: &[u8]) -> io::Result<usize> {
            let n = DESYNC_PAYLOAD.len();
            let v6 = self.s.peer_addr().map(|a| a.is_ipv6()).unwrap_or(false);
            let fd = self.s.as_raw_fd();
            // SAFETY: plain syscalls on owned fds; the mapping is `n` bytes and unmapped before return.
            unsafe {
                let mfd = libc::syscall(libc::SYS_memfd_create, c"haar".as_ptr(), 0) as i32;
                if mfd < 0 {
                    return Err(io::Error::last_os_error());
                }
                let close = |r| {
                    libc::close(mfd);
                    r
                };
                if libc::ftruncate(mfd, n as libc::off_t) != 0 {
                    return close(Err(io::Error::last_os_error()));
                }
                let p = libc::mmap(
                    std::ptr::null_mut(),
                    n,
                    libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    mfd,
                    0,
                );
                if p == libc::MAP_FAILED {
                    return close(Err(io::Error::last_os_error()));
                }
                let page = std::slice::from_raw_parts_mut(p as *mut u8, n);
                page.copy_from_slice(DESYNC_PAYLOAD);
                let r = (|| {
                    set_hops(SockRef::from(&self.s), v6, self.ttl)?;
                    let mut off: libc::off_t = 0;
                    let sent = libc::sendfile(fd, mfd, &mut off, n);
                    if sent < 0 {
                        let e = io::Error::last_os_error();
                        set_hops(SockRef::from(&self.s), v6, DEFAULT_TTL)?;
                        return Err(e);
                    }
                    std::thread::sleep(Duration::from_micros(3));
                    page.copy_from_slice(&b[..n]);
                    set_hops(SockRef::from(&self.s), v6, DEFAULT_TTL)?;
                    Ok(sent as usize)
                })();
                libc::munmap(p, n);
                close(r)
            }
        }
    }

    impl AsyncRead for Desync {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.s).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for Desync {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            b: &[u8],
        ) -> Poll<io::Result<usize>> {
            if !self.used && !b.is_empty() {
                self.used = true;
                if b.len() > DESYNC_PAYLOAD.len() {
                    match self.overwrite(b) {
                        Ok(n) if n > 0 => {
                            DECOYS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            return Poll::Ready(Ok(n)); // the rest follows as usual
                        }
                        _ => {} // no decoy (send buffer full, no memfd): an ordinary write
                    }
                }
            }
            Pin::new(&mut self.s).poll_write(cx, b)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.s).poll_flush(cx)
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.s).poll_shutdown(cx)
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
mod imp {
    use super::*;
    use tokio::net::TcpStream;

    pub fn wrap(s: TcpStream, _ttl: u32) -> TcpConn {
        TcpConn::Sock(s)
    }

    pub async fn with_traceroute(
        p: &Protector,
        who: &str,
        dst: SocketAddr,
        timeout: Duration,
    ) -> io::Result<(TcpStream, u32)> {
        Ok((p.dial_tcp(who, dst, timeout).await?, DESYNC_NOOP_TTL))
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// The decoy mechanics (memfd, sendfile at a low TTL, overwrite, TTL restore) over loopback, where nothing
    /// expires: the server gets the decoy or, if the page was overwritten before it read, the real bytes; then the
    /// rest of the hello, in order.
    #[tokio::test]
    async fn decoy_then_the_hello() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            let (mut s, _) = l.accept().await.unwrap();
            let mut b = vec![0u8; 300];
            s.read_exact(&mut b).await.unwrap();
            b
        });
        cache_ttl(a.ip(), 5);
        let p = Protector::new(Arc::new(fs_core::bridge::AllowAllBridge));
        let mut c = dial(&p, "Exit", a, Duration::from_secs(5)).await.unwrap();
        let hello: Vec<u8> = (0..300).map(|i| (i % 251) as u8).collect();
        let before = decoys();
        c.write_all(&hello).await.unwrap();
        let got = srv.await.unwrap();
        assert_eq!(decoys(), before + 1, "a decoy went out");
        let n = DESYNC_PAYLOAD.len();
        assert!(got[..n] == *DESYNC_PAYLOAD || got[..n] == hello[..n]);
        assert_eq!(got[n..], hello[n..]);
    }
}
