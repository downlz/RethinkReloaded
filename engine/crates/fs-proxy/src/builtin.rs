// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/ipn/exit.go
// Derived-From: celzero/firestack@d3d530ea3e:intra/ipn/base.go
// Derived-From: celzero/firestack@d3d530ea3e:intra/ipn/ground.go
// Derived-From: celzero/firestack@d3d530ea3e:intra/ipn/auto.go (with RPN excluded: Exit only)

//! The built-in proxies: `Exit` and `Base` (and Kotlin's config-less proxies) dial directly through protected
//! sockets, owned by `Exit` or `Base`; `Block` refuses everything; `Auto` picks a healthy remote proxy, which with
//! RPN excluded leaves `Exit` (or nothing in remote-only mode).

use crate::{AUTO, Result, healthy, new_handle};
use crate::{
    BASE, BLOCK, END, EXIT, Gw, INTERNET, NOOP, Proxy, RouterStats, SharedProxy, TKO, TOK, TUP,
};
use fs_core::settings;
use fs_dialers::{Fut, Protector, TcpConn, UdpConn};
use parking_lot::Mutex;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

const FAKE_EXIT_ADDR: &str = "127.0.0.127:1337";
const FAKE_BASE_ADDR: &str = "127.8.4.5:3690";

/// firestack `localDialStatus`: OK after a good dial, KO after a failed one (never over END / paused).
fn dial_status<T>(status: &AtomicI32, r: &io::Result<T>) {
    let cur = status.load(Ordering::Relaxed);
    if cur == END || cur == crate::TPU {
        return;
    }
    let _ = status.compare_exchange(
        cur,
        if r.is_ok() { TOK } else { TKO },
        Ordering::Relaxed,
        Ordering::Relaxed,
    );
}

fn stopped() -> io::Error {
    io::Error::other("proxy: stopped")
}

/// A proxy that dials directly through protected sockets (firestack `exit` / `base`).
pub struct Direct {
    id: String,
    /// owner the sockets are protected as (Exit or Base)
    who: &'static str,
    addr: String,
    hdl: u64,
    status: AtomicI32,
    gw: Gw,
    protector: Protector,
    /// Base may hop through another proxy
    via: Mutex<Option<Weak<dyn Proxy>>>,
}

impl Direct {
    pub fn exit(protector: Protector) -> Arc<Self> {
        Self::new(EXIT, EXIT, FAKE_EXIT_ADDR, protector)
    }
    pub fn base(protector: Protector) -> Arc<Self> {
        Self::new(BASE, BASE, FAKE_BASE_ADDR, protector)
    }
    /// firestack `NewExitProxyWithID`: an untracked Exit (`Intra.controlledRouter`); a random id when empty.
    pub fn exit_with_id(id: &str, addr: &str, protector: Protector) -> Arc<Self> {
        let id = if id.is_empty() {
            format!(
                "{:08x}",
                new_handle() as u32 ^ std::process::id().rotate_left(16)
            )
        } else {
            id.to_string()
        };
        let addr = if addr.is_empty() {
            FAKE_EXIT_ADDR
        } else {
            addr
        };
        Self::new(&id, EXIT, addr, protector)
    }
    /// firestack `NewBasicProxy`: a config-less proxy, dialing like Base.
    pub fn basic(id: &str, protector: Protector) -> Arc<Self> {
        Self::new(id, BASE, FAKE_BASE_ADDR, protector)
    }
    fn new(id: &str, who: &'static str, addr: &str, protector: Protector) -> Arc<Self> {
        Arc::new(Direct {
            id: id.to_string(),
            who,
            addr: addr.to_string(),
            hdl: new_handle(),
            status: AtomicI32::new(TUP),
            gw: Gw::new(false, false),
            protector,
            via: Mutex::new(None),
        })
    }
    fn via_proxy(&self) -> Option<SharedProxy> {
        self.via.lock().as_ref().and_then(Weak::upgrade)
    }
    fn check(&self) -> io::Result<()> {
        crate::candial(self.status.load(Ordering::Relaxed)).map_err(io::Error::other)
    }
}

impl Proxy for Direct {
    fn id(&self) -> &str {
        &self.id
    }
    fn typ(&self) -> &str {
        INTERNET
    }
    fn addr(&self) -> String {
        self.gw.lastaddr().unwrap_or_else(|| self.addr.clone())
    }
    fn status(&self) -> i32 {
        self.status.load(Ordering::Relaxed)
    }
    fn handle(&self) -> u64 {
        self.hdl
    }
    fn dial_tcp<'a>(&'a self, dst: SocketAddr, timeout: Duration) -> Fut<'a, io::Result<TcpConn>> {
        Box::pin(async move {
            self.check()?;
            if let Some(v) = self.via_proxy() {
                return v.dial_tcp(dst, timeout).await;
            }
            // firestack localDialStrat: split / desync / retry to public HTTPS and DoT servers
            let r = self.protector.split_dial_tcp(self.who, dst, timeout).await;
            dial_status(&self.status, &r);
            if let Ok(TcpConn::Sock(s)) = &r
                && let Ok(l) = s.local_addr()
            {
                self.gw.set_lastaddr(l.to_string());
            }
            r
        })
    }
    fn dial_udp<'a>(&'a self, dst: SocketAddr) -> Fut<'a, io::Result<UdpConn>> {
        Box::pin(async move {
            self.check()?;
            if let Some(v) = self.via_proxy() {
                return v.dial_udp(dst).await;
            }
            let r = self.protector.dial_udp(self.who, dst).await;
            dial_status(&self.status, &r);
            r.map(UdpConn::from)
        })
    }
    fn announce_udp<'a>(&'a self, v6: bool) -> Fut<'a, io::Result<UdpConn>> {
        Box::pin(async move {
            self.check()?;
            if let Some(v) = self.via_proxy() {
                return v.announce_udp(v6).await;
            }
            let r = self.protector.announce_udp(self.who, v6).await;
            dial_status(&self.status, &r);
            r.map(UdpConn::from)
        })
    }
    fn probe_icmp<'a>(&'a self, dst: IpAddr) -> Fut<'a, io::Result<UdpConn>> {
        Box::pin(async move {
            self.check()?;
            let r = self.protector.probe_icmp(self.who, dst).await;
            dial_status(&self.status, &r);
            r.map(UdpConn::from)
        })
    }
    fn ip4(&self) -> bool {
        self.gw.ip4()
    }
    fn ip6(&self) -> bool {
        self.gw.ip6()
    }
    fn stat(&self) -> RouterStats {
        self.gw.stat()
    }
    fn contains(&self, _who: &str, ipp: &str) -> bool {
        self.gw.contains(ipp)
    }
    fn is_self(&self, ip: &str) -> bool {
        self.gw.is_self(ip)
    }
    fn reaches(&self, csv: &str) -> bool {
        self.gw.reaches(csv)
    }
    fn via(&self) -> Option<SharedProxy> {
        if self.who == BASE {
            self.via_proxy()
        } else {
            None
        }
    }
    /// Only Base-like proxies hop (firestack `base.Hop`); Exit never does.
    fn hop(&self, via: Option<SharedProxy>, dryrun: bool) -> Result<()> {
        if self.who != BASE {
            return Err("proxy: nop".into());
        }
        if let Some(v) = &via
            && v.id() == self.id
        {
            return Err("proxy: hop looping back onto hop".into());
        }
        if !dryrun {
            *self.via.lock() = via.as_ref().map(Arc::downgrade);
        }
        Ok(())
    }
    fn stop(&self) {
        self.status.store(END, Ordering::Relaxed);
    }
    fn set_since(&self, ms: i64) {
        self.gw.set_since(ms);
    }
}

/// firestack `ground` (`Block`): routes nothing, dials nothing.
pub struct Ground {
    hdl: u64,
    gw: Gw,
}

impl Ground {
    pub fn new() -> Arc<Self> {
        Arc::new(Ground {
            hdl: new_handle(),
            gw: Gw::new(true, true),
        })
    }
}

fn refused() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionRefused,
        "proxy: blocked or no response",
    )
}

impl Proxy for Ground {
    fn id(&self) -> &str {
        BLOCK
    }
    fn typ(&self) -> &str {
        NOOP
    }
    fn addr(&self) -> String {
        "[::]:0".into()
    }
    fn status(&self) -> i32 {
        TKO
    }
    fn handle(&self) -> u64 {
        self.hdl
    }
    fn dial_tcp<'a>(&'a self, _: SocketAddr, _: Duration) -> Fut<'a, io::Result<TcpConn>> {
        Box::pin(async { Err(refused()) })
    }
    fn dial_udp<'a>(&'a self, _: SocketAddr) -> Fut<'a, io::Result<UdpConn>> {
        Box::pin(async { Err(refused()) })
    }
    fn announce_udp<'a>(&'a self, _: bool) -> Fut<'a, io::Result<UdpConn>> {
        Box::pin(async { Err(refused()) })
    }
    fn probe_icmp<'a>(&'a self, _: IpAddr) -> Fut<'a, io::Result<UdpConn>> {
        Box::pin(async { Err(refused()) })
    }
    fn can_announce(&self) -> bool {
        false
    }
    fn ip4(&self) -> bool {
        false
    }
    fn ip6(&self) -> bool {
        false
    }
    fn stat(&self) -> RouterStats {
        self.gw.stat()
    }
    fn contains(&self, _: &str, ipp: &str) -> bool {
        self.gw.contains(ipp)
    }
    fn is_self(&self, _: &str) -> bool {
        false
    }
    fn reaches(&self, csv: &str) -> bool {
        self.gw.reaches(csv)
    }
    fn stop(&self) {}
}

/// firestack `auto`: the first healthy of Exit, Rpn64 and WIN; with RPN excluded, Exit (nothing in remote-only
/// mode, where local proxies do not count).
pub struct Auto {
    hdl: u64,
    status: AtomicI32,
    gw: Gw,
    exit: Weak<dyn Proxy>,
}

impl Auto {
    pub fn new(exit: &SharedProxy) -> Arc<Self> {
        Arc::new(Auto {
            hdl: new_handle(),
            status: AtomicI32::new(TUP),
            gw: Gw::new(false, false),
            exit: Arc::downgrade(exit),
        })
    }
    fn pick(&self) -> io::Result<SharedProxy> {
        crate::candial(self.status.load(Ordering::Relaxed)).map_err(io::Error::other)?;
        if settings::AUTO_MODE.load(Ordering::Relaxed) == settings::AUTO_MODE_REMOTE {
            return Err(io::Error::other("proxy: none healthy")); // Exit is local
        }
        let exit = self.exit.upgrade().ok_or_else(stopped)?;
        // fail open: Exit even when not healthy
        let _ = healthy(&exit);
        Ok(exit)
    }
}

impl Proxy for Auto {
    fn id(&self) -> &str {
        AUTO
    }
    fn typ(&self) -> &str {
        crate::RPN
    }
    fn addr(&self) -> String {
        self.exit.upgrade().map(|e| e.addr()).unwrap_or_default()
    }
    fn status(&self) -> i32 {
        self.status.load(Ordering::Relaxed)
    }
    fn handle(&self) -> u64 {
        self.hdl
    }
    fn dial_tcp<'a>(&'a self, dst: SocketAddr, timeout: Duration) -> Fut<'a, io::Result<TcpConn>> {
        Box::pin(async move {
            let r = self.pick()?.dial_tcp(dst, timeout).await;
            dial_status(&self.status, &r);
            r
        })
    }
    fn dial_udp<'a>(&'a self, dst: SocketAddr) -> Fut<'a, io::Result<UdpConn>> {
        Box::pin(async move { self.pick()?.dial_udp(dst).await })
    }
    fn announce_udp<'a>(&'a self, v6: bool) -> Fut<'a, io::Result<UdpConn>> {
        Box::pin(async move { self.pick()?.announce_udp(v6).await })
    }
    fn probe_icmp<'a>(&'a self, dst: IpAddr) -> Fut<'a, io::Result<UdpConn>> {
        Box::pin(async move { self.pick()?.probe_icmp(dst).await })
    }
    fn ip4(&self) -> bool {
        self.gw.ip4()
    }
    fn ip6(&self) -> bool {
        self.gw.ip6()
    }
    fn stat(&self) -> RouterStats {
        self.exit.upgrade().map(|e| e.stat()).unwrap_or_default()
    }
    fn contains(&self, _: &str, ipp: &str) -> bool {
        self.gw.contains(ipp)
    }
    fn is_self(&self, ip: &str) -> bool {
        self.exit.upgrade().is_some_and(|e| e.is_self(ip))
    }
    fn reaches(&self, csv: &str) -> bool {
        self.gw.reaches(csv)
    }
    fn stop(&self) {
        self.status.store(END, Ordering::Relaxed);
    }
}
