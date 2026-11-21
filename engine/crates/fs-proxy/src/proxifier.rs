// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/ipn/proxies.go (proxifier: add, remove, ProxyTo, pins, stall,
//               ProxyFor, events, RefreshProxies, router aggregation)
// Derived-From: celzero/firestack@d3d530ea3e:intra/core/expiringmap.go (stall hit counts)

//! The proxy registry (firestack `proxifier`). Flows ask [`Proxifier::proxy_to`] for one of Kotlin's chosen
//! proxy ids: a remembered choice (pinned per uid and destination for 10 min) when it still routes the destination,
//! else the first healthy remote proxy that routes it, else an unhealthy one, else a local one. Missing proxies are
//! waited for once (Kotlin may be adding them); failing destinations stall the flow briefly.

use crate::builtin::{Auto, Direct, Ground};
use crate::{AUTO, BASE, BLOCK, END, EXIT, RouterStats, SharedProxy, TNT, TPU};
use crate::{acc_stats, cant_proxy_h3, healthy, immutable, is_internal, is_wellknown, local, noop};
use fs_core::bridge::ProxyListener;
use fs_dialers::{Dial, Fut, Protector, TcpConn, UdpConn};
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::hash::Hash;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// firestack `pintimeout`
const PIN_TIMEOUT: Duration = Duration::from_secs(600);
/// firestack `maxFailingPinTrackTTl`
const STALL_TRACK: Duration = Duration::from_secs(30);
/// firestack `maxStallPeriodSec`
const MAX_STALL_SECS: u32 = 10;
/// firestack `minWaitPeriodSec`
const MIN_WAIT_SECS: u32 = 2;
const PIN_CAPACITY: usize = 4096;
const EVENTS: usize = 32;

pub const ERR_CIRCULAR: &str = "proxy: circular route";
pub const ERR_NOT_FOUND: &str = "proxy: not found";

/// Entries that expire (firestack `ExpMap` hit counting and `Sieve` pins).
struct ExpMap<K, V> {
    m: Mutex<HashMap<K, (V, Instant, u32)>>,
}

impl<K: Eq + Hash + Clone, V: Clone + Default> ExpMap<K, V> {
    fn new() -> Self {
        ExpMap {
            m: Mutex::new(HashMap::new()),
        }
    }
    fn trim(m: &mut HashMap<K, (V, Instant, u32)>) {
        if m.len() >= PIN_CAPACITY {
            let now = Instant::now();
            m.retain(|_, (_, e, _)| *e > now);
            if m.len() >= PIN_CAPACITY {
                m.clear();
            }
        }
    }
    /// firestack `ExpMap.Get`: hit count, which grows while the entry lives (0 for new or expired entries)
    fn hits(&self, k: &K) -> u32 {
        let mut m = self.m.lock();
        let now = Instant::now();
        match m.get_mut(k) {
            None => {
                Self::trim(&mut m);
                m.insert(k.clone(), (V::default(), now, 0));
                0
            }
            Some((_, exp, hits)) => {
                if now > *exp {
                    *hits = 0;
                } else {
                    *hits += 1;
                }
                *hits
            }
        }
    }
    /// firestack `ExpMap.Set`: keeps the hit count, extends the expiry
    fn touch(&self, k: &K, ttl: Duration) {
        let mut m = self.m.lock();
        let exp = Instant::now() + ttl;
        match m.get_mut(k) {
            Some(e) => e.1 = exp,
            None => {
                Self::trim(&mut m);
                m.insert(k.clone(), (V::default(), exp, 0));
            }
        }
    }
    fn put(&self, k: K, v: V, ttl: Duration) {
        let mut m = self.m.lock();
        Self::trim(&mut m);
        m.insert(k, (v, Instant::now() + ttl, 0));
    }
    fn get(&self, k: &K) -> Option<V> {
        let m = self.m.lock();
        m.get(k)
            .filter(|(_, e, _)| *e > Instant::now())
            .map(|(v, _, _)| v.clone())
    }
    fn del(&self, k: &K) {
        self.m.lock().remove(k);
    }
    fn clear(&self) -> usize {
        let mut m = self.m.lock();
        let n = m.len();
        m.clear();
        n
    }
}

#[derive(Clone, Copy, Debug)]
#[allow(dead_code)] // Update: WireGuard config updates (Phase 2, step 3)
enum Event {
    Add,
    Remove,
    Stop,
    Update,
}

/// Link properties the proxies adapt to (firestack `LinkProps`).
#[derive(Clone, Debug, Default)]
pub struct LinkProps {
    pub l3: String,
    pub mtu: i64,
}

pub struct Proxifier {
    p: RwLock<HashMap<String, SharedProxy>>,
    exit: SharedProxy,
    base: SharedProxy,
    ground: SharedProxy,
    auto: SharedProxy,
    protector: Protector,
    /// hop -> [origin ids]
    hp: Mutex<HashMap<String, Vec<String>>>,
    lp: Mutex<LinkProps>,
    staller: ExpMap<String, ()>,
    ip_pins: ExpMap<SocketAddr, String>,
    uid_pins: ExpMap<(String, SocketAddr), String>,
    events: mpsc::Sender<(Event, String, String)>,
    listener: Arc<dyn ProxyListener>,
    resolver: RwLock<Option<crate::upstream::HostResolver>>,
}

fn hdlstr(p: &SharedProxy) -> String {
    format!("{:x}", p.handle())
}

impl Proxifier {
    /// firestack `NewProxifier`; spawns the event dispatcher on the current runtime.
    pub fn new(
        l3: &str,
        mtu: i64,
        protector: Protector,
        listener: Arc<dyn ProxyListener>,
    ) -> Arc<Self> {
        let (tx, mut rx) = mpsc::channel::<(Event, String, String)>(EVENTS);
        let exit: SharedProxy = Direct::exit(protector.clone());
        let base: SharedProxy = Direct::base(protector.clone());
        let ground: SharedProxy = Ground::new();
        let auto: SharedProxy = Auto::new(&exit);
        let px = Arc::new(Proxifier {
            p: RwLock::new(HashMap::new()),
            exit,
            base,
            ground,
            auto,
            protector,
            hp: Mutex::new(HashMap::new()),
            lp: Mutex::new(LinkProps { l3: l3.into(), mtu }),
            staller: ExpMap::new(),
            ip_pins: ExpMap::new(),
            uid_pins: ExpMap::new(),
            events: tx,
            listener: listener.clone(),
            resolver: RwLock::new(None),
        });
        tokio::spawn(async move {
            while let Some((ev, id, hdl)) = rx.recv().await {
                match ev {
                    Event::Add => listener.on_proxy_added(id, hdl),
                    Event::Remove => listener.on_proxy_removed(id, hdl),
                    Event::Stop => listener.on_proxy_stopped(id, hdl),
                    Event::Update => listener.on_proxy_updated(id, hdl),
                }
            }
        });
        for p in [
            px.exit.clone(),
            px.base.clone(),
            px.ground.clone(),
            px.auto.clone(),
        ] {
            px.add(p);
        }
        px
    }

    pub fn protector(&self) -> &Protector {
        &self.protector
    }

    /// Resolves proxy hostnames (the engine's resolver).
    pub fn set_host_resolver(&self, r: crate::upstream::HostResolver) {
        *self.resolver.write() = Some(r);
    }

    pub fn host_resolver(&self) -> Option<crate::upstream::HostResolver> {
        self.resolver.read().clone()
    }

    pub fn link_props(&self) -> LinkProps {
        self.lp.lock().clone()
    }

    fn queue(&self, ev: Event, id: &str, hdl: String) {
        // dropped when full, as firestack
        let _ = self.events.try_send((ev, id.to_string(), hdl));
    }

    /// firestack `add`: registers `p` (replacing and stopping an older proxy of the same id; immutable ids take
    /// only their own kind) and announces it.
    pub fn add(&self, p: SharedProxy) -> bool {
        let id = p.id().to_string();
        if immutable(&id) {
            let expected = match id.as_str() {
                EXIT => &self.exit,
                BASE => &self.base,
                BLOCK => &self.ground,
                AUTO => &self.auto,
                _ => return false,
            };
            if expected.handle() != p.handle() {
                return false;
            }
        }
        let old = self.p.write().insert(id.clone(), p.clone());
        self.queue(Event::Add, &id, hdlstr(&p));
        if let Some(old) = old
            && old.handle() != p.handle()
        {
            if old.status() == TPU {
                p.pause();
            }
            p.set_since(old.stat().since);
            if let Some(v) = old.via() {
                let _ = self.hop(v.id(), &id, false);
            }
            old.stop();
        }
        true
    }

    /// firestack `RemoveProxy`: internal proxies are not removable (only stopped when forced).
    pub fn remove_proxy(&self, id: &str) -> bool {
        self.remove(id, false)
    }

    fn remove(&self, id: &str, force: bool) -> bool {
        if is_internal(id) && !force {
            return false;
        }
        let perma = immutable(id);
        let p = {
            let mut m = self.p.write();
            if perma {
                m.get(id).cloned()
            } else {
                m.remove(id)
            }
        };
        let Some(p) = p else { return false };
        self.unmap_hop_from(id);
        p.stop();
        self.queue(
            if perma { Event::Stop } else { Event::Remove },
            id,
            hdlstr(&p),
        );
        true
    }

    /// firestack `proxyFor`: the registered proxy (pings or refreshes it when idle).
    pub fn proxy_for(&self, id: &str) -> Result<SharedProxy, String> {
        if id.is_empty() {
            return Err("proxy: missing proxy id".into());
        }
        let p = match id {
            EXIT => Some(self.exit.clone()),
            BASE => Some(self.base.clone()),
            BLOCK => Some(self.ground.clone()),
            AUTO => Some(self.auto.clone()),
            _ => self.p.read().get(id).cloned(),
        };
        let p = p.ok_or_else(|| ERR_NOT_FOUND.to_string())?;
        let _ = healthy(&p);
        Ok(p)
    }

    /// firestack `ProxyFor`: waits up to 2 s for a well-known proxy Kotlin may still be adding.
    pub async fn proxy_for_wait(&self, id: &str) -> Result<SharedProxy, String> {
        let start = Instant::now();
        match self.proxy_for(id) {
            Err(e) if e == ERR_NOT_FOUND && is_wellknown(id) => {
                let wait =
                    Duration::from_secs(MIN_WAIT_SECS as u64).saturating_sub(start.elapsed());
                tokio::time::sleep(wait).await;
                self.proxy_for(id)
            }
            r => r,
        }
    }

    pub fn has_proxy(&self, id: &str) -> bool {
        self.proxy_for(id).is_ok()
    }

    /// firestack `stall`: 1-3 s for the first failures of a key, then its hit count (up to 10 s).
    async fn stall(&self, k: &str) -> u32 {
        let k = k.to_string();
        let n = self.staller.hits(&k);
        let secs = if n <= 3 {
            1 + (crate::new_handle() % 3) as u32
        } else {
            n
        };
        self.staller.touch(&k, STALL_TRACK);
        let secs = secs.min(MAX_STALL_SECS);
        if secs > 0 {
            tokio::time::sleep(Duration::from_secs(secs as u64)).await;
        }
        secs
    }

    fn pin(&self, uid: &str, ipp: SocketAddr, p: &SharedProxy) -> Result<(), String> {
        healthy(p)?;
        self.uid_pins
            .put((uid.to_string(), ipp), p.id().to_string(), PIN_TIMEOUT);
        self.ip_pins.put(ipp, p.id().to_string(), PIN_TIMEOUT);
        Ok(())
    }

    fn pin_id(
        &self,
        uid: &str,
        ipp: SocketAddr,
        id: &str,
    ) -> (Option<SharedProxy>, Result<(), String>) {
        match self.proxy_for(id) {
            Ok(p) => {
                let r = self.pin(uid, ipp, &p);
                (Some(p), r)
            }
            Err(e) => (None, Err(e)),
        }
    }

    fn delpin(&self, uid: &str, ipp: SocketAddr) {
        self.uid_pins.del(&(uid.to_string(), ipp));
        self.ip_pins.del(&ipp);
    }

    fn getpin(&self, uid: &str, ipp: SocketAddr) -> Option<String> {
        self.uid_pins
            .get(&(uid.to_string(), ipp))
            .or_else(|| self.ip_pins.get(&ipp))
    }

    /// firestack `ProxyTo`: the proxy among `pids` for `uid` to reach `ipp` over `proto`.
    pub async fn proxy_to(
        &self,
        who: &str,
        ipp: SocketAddr,
        proto: &str,
        uid: &str,
        my_uid: &str,
        pids: &[String],
    ) -> Result<SharedProxy, String> {
        let e = |err: &str| format!("{err} for {uid} to {proto}:{ipp} among {pids:?}");
        if pids.is_empty() || pids[0].is_empty() {
            return Err(e("proxy: missing proxy id"));
        }
        let ippstr = ipp.to_string();
        let ipstr = ipp.ip().to_string();
        let maybe_h3 = proto == "udp" && ipp.port() == 443;
        let canth3 = |p: &SharedProxy| uid != my_uid && maybe_h3 && cant_proxy_h3(p.id());
        let mut total_stall = 0u32;

        if pids.len() == 1 {
            let mut waited = false;
            loop {
                let (p, r) = self.pin_id(uid, ipp, &pids[0]);
                match p {
                    None if !waited => {
                        waited = true;
                        let s = self.stall(&format!("{uid}{ippstr}")).await;
                        if s < MIN_WAIT_SECS {
                            tokio::time::sleep(Duration::from_secs((MIN_WAIT_SECS - s) as u64))
                                .await;
                        }
                        continue;
                    }
                    None => return Err(e(&r.err().unwrap_or_else(|| ERR_NOT_FOUND.into()))),
                    Some(p) => {
                        if p.is_self(&ipstr) {
                            self.delpin(uid, ipp);
                            return Err(ERR_CIRCULAR.into());
                        }
                        if !p.contains(who, &ippstr) {
                            self.delpin(uid, ipp);
                            return Err(e("proxy: no route to host"));
                        }
                        if canth3(&p) {
                            self.delpin(uid, ipp);
                            return Err(e("proxy: h3 not supported"));
                        }
                        if p.status() == TNT {
                            self.stall(&format!("{uid}{ippstr}")).await;
                        }
                        return Ok(p); // even if unhealthy: the caller can tell why it fails
                    }
                }
            }
        }

        let (mut circular, mut notok, mut noh3) =
            (0usize, Vec::<SharedProxy>::new(), Vec::<SharedProxy>::new());
        let (mut notokids, mut missing, mut noroute, mut ended, mut paused, mut noh3ids) =
            (0usize, Vec::<String>::new(), 0usize, 0usize, 0usize, 0usize);
        let mut loproxies: Vec<String> = Vec::new();
        let mut lopinned = String::new();

        let pinned = self.getpin(uid, ipp);
        let mut pinnedpid = pinned.clone().unwrap_or_default();
        let chosen = pinned.as_ref().is_some_and(|p| pids.contains(p));
        if pinned.is_some() && chosen && local(&pinnedpid) {
            lopinned = pinnedpid.clone(); // remote proxies win over a local pin
        } else if pinned.is_some() && chosen {
            let (p, r) = self.pin_id(uid, ipp, &pinnedpid);
            match (p, r) {
                (Some(p), Ok(())) => {
                    if p.is_self(&ipstr) {
                        circular += 1;
                        self.delpin(uid, ipp);
                    } else if canth3(&p) {
                        noh3ids += 1;
                        noh3.push(p);
                        self.delpin(uid, ipp);
                    } else if p.contains(who, &ippstr) {
                        return Ok(p);
                    } else {
                        noroute += 1;
                        self.delpin(uid, ipp);
                    }
                }
                (Some(p), Err(_)) => {
                    notokids += 1;
                    notok.push(p);
                }
                (None, _) => missing.push(pinnedpid.clone()),
            }
            pinnedpid.clear(); // considered again below
        } else if pinned.is_some() && !chosen {
            self.delpin(uid, ipp);
            pinnedpid.clear();
        }
        if !lopinned.is_empty() {
            loproxies.push(lopinned.clone());
        }

        let mut candidates: Vec<String> = pids.to_vec();
        let mut waited = false;
        loop {
            for pid in &candidates {
                if !pinnedpid.is_empty() && *pid == pinnedpid {
                    continue;
                }
                if local(pid) {
                    if *pid != lopinned {
                        loproxies.push(pid.clone());
                    }
                    continue;
                }
                let Ok(p) = self.proxy_for(pid) else {
                    missing.push(pid.clone());
                    continue;
                };
                match p.status() {
                    TPU => {
                        paused += 1;
                        continue;
                    }
                    END => {
                        ended += 1;
                        continue;
                    }
                    _ => {}
                }
                if noop(p.typ()) {
                    loproxies.push(pid.clone());
                    continue;
                }
                if p.is_self(&ipstr) {
                    circular += 1;
                    continue;
                }
                if p.contains(who, &ippstr) {
                    if canth3(&p) {
                        noh3ids += 1;
                        noh3.push(p);
                        continue;
                    }
                    if self.pin(uid, ipp, &p).is_ok() {
                        return Ok(p);
                    }
                    notokids += 1;
                    notok.push(p);
                } else {
                    noroute += 1;
                }
            }
            if !notok.is_empty() || !noh3.is_empty() {
                if total_stall < MIN_WAIT_SECS {
                    total_stall += self.stall(&format!("{uid}{ippstr}")).await;
                }
                if !notok.is_empty() {
                    let i = (crate::new_handle() as usize) % notok.len();
                    return Ok(notok[i].clone());
                }
                for p in &noh3 {
                    if self.pin(uid, ipp, p).is_ok() {
                        return Ok(p.clone());
                    }
                }
            }
            if !missing.is_empty() && !waited {
                waited = true;
                if total_stall < MIN_WAIT_SECS {
                    total_stall += self.stall(&format!("{uid}{ippstr}")).await;
                }
                candidates = std::mem::take(&mut missing);
                continue;
            }
            break;
        }
        for pid in &loproxies {
            if let (Some(p), _) = self.pin_id(uid, ipp, pid) {
                return Ok(p);
            }
            missing.push(pid.clone());
        }
        Err(if notokids > 0 {
            e("proxy: none healthy")
        } else if !missing.is_empty() {
            e(ERR_NOT_FOUND)
        } else if noroute > 0 {
            e("proxy: no route to host")
        } else if ended > 0 {
            e("proxy: stopped")
        } else if paused > 0 {
            e("proxy: paused")
        } else if noh3ids > 0 {
            e("proxy: h3 not supported")
        } else if circular > 0 {
            ERR_CIRCULAR.into()
        } else {
            e("proxy: all down")
        })
    }

    /// firestack `RefreshProxies`: clears pins, refreshes every proxy (in the background); returns their ids.
    pub fn refresh_proxies(&self) -> String {
        self.uid_pins.clear();
        self.ip_pins.clear();
        let all: Vec<SharedProxy> = self.p.read().values().cloned().collect();
        let ids: Vec<String> = all.iter().map(|p| p.id().to_string()).collect();
        for p in all {
            tokio::task::spawn_blocking(move || {
                let _ = p.refresh();
            });
        }
        ids.join(",")
    }

    pub fn live_proxies(&self) -> String {
        self.p.read().keys().cloned().collect::<Vec<_>>().join(",")
    }

    /// firestack `RefreshProto`: new link properties for the proxies that adapt to them.
    pub fn refresh_proto(&self, l3: &str, mtu: i64) {
        let mut lp = self.lp.lock();
        if !l3.is_empty() {
            lp.l3 = l3.into();
        }
        if mtu > 0 {
            lp.mtu = mtu;
        }
    }

    /// firestack `stopProxies`
    pub fn stop_proxies(&self) {
        self.hp.lock().clear();
        let all: Vec<SharedProxy> = self.p.write().drain().map(|(_, p)| p).collect();
        for p in all {
            p.stop();
        }
        self.staller.clear();
        self.ip_pins.clear();
        self.uid_pins.clear();
        self.listener.on_proxies_stopped();
    }

    // ---- hops (firestack Hop / TestHop / mapHop)

    /// firestack `hop(via, origin, dryrun)`: routes `origin` through `via` (empty `via` unhops).
    pub fn hop(&self, via: &str, origin: &str, dryrun: bool) -> Result<(), String> {
        let o = self.proxy_for(origin)?;
        if via.is_empty() {
            let r = o.hop(None, dryrun);
            if !dryrun {
                self.unmap_hop_from(origin);
            }
            return r;
        }
        if via == origin {
            return Err("proxy: hop looping back onto hop".into());
        }
        let v = self.proxy_for(via)?;
        if v.via().is_some() {
            return Err("proxy: hop must not be hopping".into());
        }
        o.hop(Some(v), dryrun)?;
        if !dryrun {
            self.unmap_hop_from(origin);
            self.hp
                .lock()
                .entry(via.to_string())
                .or_default()
                .push(origin.to_string());
        }
        Ok(())
    }

    /// firestack `TestHop`: "" when `origin` can hop through `via`, else why not.
    pub fn test_hop(&self, via: &str, origin: &str) -> String {
        self.hop(via, origin, true).err().unwrap_or_default()
    }

    fn unmap_hop_from(&self, origin: &str) {
        let mut hp = self.hp.lock();
        for v in hp.values_mut() {
            v.retain(|o| o != origin);
        }
        hp.retain(|_, v| !v.is_empty());
    }

    // ---- router (firestack proxifier as x.Router)

    fn remotes(&self) -> Vec<SharedProxy> {
        self.p
            .read()
            .values()
            .filter(|p| !local(p.id()) && !noop(p.typ()))
            .cloned()
            .collect()
    }

    pub fn router_ip4(&self) -> bool {
        let n = self.p.read().len();
        self.remotes().iter().all(|p| p.ip4()) && n > 0
    }
    pub fn router_ip6(&self) -> bool {
        let n = self.p.read().len();
        self.remotes().iter().all(|p| p.ip6()) && n > 0
    }
    /// smallest MTU across remote proxies that are not hopping (`None` when unknown)
    pub fn router_mtu(&self) -> Option<i64> {
        let mut out = crate::MAXMTU;
        let mut only4 = false;
        let mut minmtu = crate::MIN_MTU6;
        for p in self.remotes() {
            only4 = only4 || (p.ip4() && !p.ip6());
            if only4 && minmtu > crate::MIN_MTU4 {
                minmtu = crate::MIN_MTU4;
            }
            if p.via().is_some() {
                continue;
            }
            if let Some(m) = p.mtu() {
                out = out.min(m.max(minmtu));
            }
        }
        (out != crate::MAXMTU && out != crate::NOMTU).then_some(out)
    }
    pub fn router_stat(&self) -> RouterStats {
        let mut s = RouterStats::default();
        for p in self.p.read().values() {
            if local(p.id()) || is_internal(p.id()) || noop(p.typ()) {
                continue;
            }
            s = acc_stats(&s, &p.stat());
        }
        s
    }
    pub fn router_contains(&self, who: &str, prefix: &str) -> bool {
        self.remotes().iter().any(|p| p.contains(who, prefix))
    }
    pub fn router_reaches(&self, csv: &str) -> bool {
        self.p.read().values().any(|p| p.reaches(csv))
    }
    pub fn router_self(&self, ip: &str) -> bool {
        !ip.is_empty() && self.p.read().values().any(|p| p.is_self(ip))
    }
}

/// Transports and other internal dialers dial through a proxy by its id.
impl Dial for Proxifier {
    fn dial_tcp<'a>(
        &'a self,
        who: &'a str,
        dst: SocketAddr,
        timeout: Duration,
    ) -> Fut<'a, io::Result<TcpConn>> {
        Box::pin(async move {
            let p = self.proxy_for_wait(who).await.map_err(io::Error::other)?;
            p.dial_tcp(dst, timeout).await
        })
    }
    fn dial_udp<'a>(&'a self, who: &'a str, dst: SocketAddr) -> Fut<'a, io::Result<UdpConn>> {
        Box::pin(async move {
            let p = self.proxy_for_wait(who).await.map_err(io::Error::other)?;
            p.dial_udp(dst).await
        })
    }
    fn announce_udp<'a>(&'a self, who: &'a str, v6: bool) -> Fut<'a, io::Result<UdpConn>> {
        Box::pin(async move {
            let p = self.proxy_for_wait(who).await.map_err(io::Error::other)?;
            p.announce_udp(v6).await
        })
    }
    fn probe_icmp<'a>(&'a self, who: &'a str, dst: IpAddr) -> Fut<'a, io::Result<UdpConn>> {
        Box::pin(async move {
            let p = self.proxy_for_wait(who).await.map_err(io::Error::other)?;
            p.probe_icmp(dst).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fs_core::bridge::AllowAllBridge;

    fn px() -> Arc<Proxifier> {
        let b = Arc::new(AllowAllBridge);
        Proxifier::new("46", 1500, Protector::new(b.clone()), b)
    }

    #[tokio::test]
    async fn builtins_and_selection() {
        let px = px();
        assert!(
            px.has_proxy(EXIT) && px.has_proxy(BASE) && px.has_proxy(BLOCK) && px.has_proxy(AUTO)
        );
        assert!(!px.remove_proxy(EXIT), "internal proxies are not removable");
        let dst: SocketAddr = "93.184.215.14:443".parse().unwrap();
        let p = px
            .proxy_to("c1", dst, "tcp", "10123", "1000", &["Exit".into()])
            .await
            .unwrap();
        assert_eq!(p.id(), EXIT);
        // a config-less proxy routes everything, and remote proxies win over local ones
        assert!(px.add(Direct::basic("socksy", px.protector().clone())));
        let p = px
            .proxy_to(
                "c2",
                dst,
                "tcp",
                "10123",
                "1000",
                &["Exit".into(), "socksy".into()],
            )
            .await
            .unwrap();
        assert_eq!(p.id(), "socksy");
        assert!(px.live_proxies().contains("socksy"));
        assert!(px.remove_proxy("socksy"));
        assert!(!px.has_proxy("socksy"));
        // local proxies are tried in the order given (firestack): Block first here
        let p = px
            .proxy_to(
                "c3",
                dst,
                "tcp",
                "1",
                "1000",
                &["Block".into(), "Exit".into()],
            )
            .await
            .unwrap();
        assert_eq!(p.id(), BLOCK);
        assert!(px.router_mtu().is_none());
    }

    #[tokio::test]
    async fn stall_counts_up() {
        let px = px();
        let m: ExpMap<String, ()> = ExpMap::new();
        assert_eq!(m.hits(&"k".to_string()), 0);
        m.touch(&"k".to_string(), Duration::from_secs(30));
        assert_eq!(m.hits(&"k".to_string()), 1);
        assert_eq!(m.hits(&"k".to_string()), 2);
        drop(px);
    }
}
