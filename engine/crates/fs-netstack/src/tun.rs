// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:tunnel/tunnel.go (maybeDup)

//! Raw-IP TUN fd (non-blocking, async) and a swappable link around it.

use parking_lot::RwLock;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::sync::watch;

/// An owned, non-blocking TUN fd.
pub struct Tun {
    fd: AsyncFd<OwnedFd>,
    mtu: i32,
}

impl Tun {
    /// Takes `fd` as given (ownership transferred) or a `F_DUPFD_CLOEXEC` duplicate of it (firestack `maybeDup`:
    /// dup unless the engine owns the fd, i.e. `Settings.dupTunFd(false)`).
    pub fn from_fd(fd: RawFd, mtu: i32, dup: bool) -> io::Result<Tun> {
        let fd = if dup {
            // SAFETY: fcntl on a caller-provided fd; returns a new fd we own.
            let n = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            n
        } else {
            fd
        };
        // SAFETY: `fd` is a valid open descriptor that we now own.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        let flags = unsafe { libc::fcntl(owned.as_raw_fd(), libc::F_GETFL) };
        if flags < 0
            || unsafe { libc::fcntl(owned.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) }
                < 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the AsyncFd takes ownership of `owned`; the fd stays open for as long as it is registered and is
        // deregistered (on drop) before being closed.
        let fd = unsafe {
            AsyncFd::register_with_interest(owned, Interest::READABLE | Interest::WRITABLE)?
        };
        Ok(Tun { fd, mtu })
    }

    async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut g = self.fd.readable().await?;
            match g.try_io(|f| {
                // SAFETY: reading into a valid buffer from an owned fd.
                let n = unsafe {
                    libc::read(f.get_ref().as_raw_fd(), buf.as_mut_ptr().cast(), buf.len())
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(r) => return r,
                Err(_would_block) => continue,
            }
        }
    }

    async fn write(&self, pkt: &[u8]) -> io::Result<usize> {
        loop {
            let mut g = self.fd.writable().await?;
            match g.try_io(|f| {
                // SAFETY: writing a valid buffer to an owned fd.
                let n =
                    unsafe { libc::write(f.get_ref().as_raw_fd(), pkt.as_ptr().cast(), pkt.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(r) => return r,
                Err(_would_block) => continue,
            }
        }
    }
}

/// The current TUN device; can be swapped (new fd) or unlinked (closed) while the stack keeps running.
pub struct Link {
    cur: RwLock<Option<Arc<Tun>>>,
    gen_tx: watch::Sender<u64>,
    mtu: AtomicI32,
    shut: AtomicBool,
}

impl Link {
    pub fn new(t: Tun) -> Link {
        let mtu = t.mtu;
        Link {
            cur: RwLock::new(Some(Arc::new(t))),
            gen_tx: watch::channel(0).0,
            mtu: AtomicI32::new(mtu),
            shut: AtomicBool::new(false),
        }
    }

    fn current(&self) -> Option<Arc<Tun>> {
        self.cur.read().clone()
    }

    pub async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut gen_rx = self.gen_tx.subscribe();
        let Some(t) = self.current() else {
            return Err(io::Error::from(io::ErrorKind::NotConnected));
        };
        tokio::select! {
            r = t.read(buf) => r,
            _ = gen_rx.changed() => Err(io::Error::from(io::ErrorKind::Interrupted)),
        }
    }

    pub async fn write(&self, pkt: &[u8]) -> io::Result<usize> {
        match self.current() {
            Some(t) => t.write(pkt).await,
            None => Err(io::Error::from(io::ErrorKind::NotConnected)),
        }
    }

    /// Waits until a new fd is linked; false if the link was shut down.
    pub async fn wait_swapped(&self) -> bool {
        let mut rx = self.gen_tx.subscribe();
        loop {
            if self.shut.load(Ordering::SeqCst) {
                return false;
            }
            if self.current().is_some() {
                // linked, but reads failed: back off briefly to avoid spinning on a broken fd
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                return !self.shut.load(Ordering::SeqCst);
            }
            if rx.changed().await.is_err() {
                return false;
            }
        }
    }

    pub fn swap(&self, t: Tun) {
        self.mtu.store(t.mtu, Ordering::SeqCst);
        *self.cur.write() = Some(Arc::new(t));
        self.gen_tx.send_modify(|g| *g += 1);
    }

    pub fn unlink(&self) {
        *self.cur.write() = None;
        self.gen_tx.send_modify(|g| *g += 1);
    }

    pub fn shutdown(&self) {
        self.shut.store(true, Ordering::SeqCst);
        self.unlink();
    }

    pub fn is_linked(&self) -> bool {
        self.cur.read().is_some()
    }

    pub fn mtu(&self) -> i32 {
        if self.is_linked() {
            self.mtu.load(Ordering::SeqCst)
        } else {
            -1
        }
    }

    pub fn set_mtu(&self, m: i32) {
        self.mtu.store(m, Ordering::SeqCst);
    }
}
