// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/dnsx/alg.go (dnsgateway, xips, xdomains, algans, register,
//               take4/take6, gen4/gen6, X, PTR, RDNSBL, resolv, fromInternalCache, onStopped)

//! The DNS gateway (firestack `dnsgateway`): it remembers, per (tid, uid), which addresses and names each answer
//! carried, so flows can be mapped back to domains (`PTR`), real addresses (`X`) and blocklists (`RDNSBL`).
//!
//! With translation (ALG, `Resolver.translate(true, …)`) A/AAAA answers and SVCB/HTTPS ip hints are rewritten to
//! stable per-domain addresses in 100.64.0.0/10 and 64:ff9b:1:da19:100::/80 (consistent hashing of the qname),
//! and flows to those addresses are dialed to the real ones. Without translation the same tables are kept (hot
//! for a later switch) and serve as the IP -> domain map. A/AAAA queries are also answered from the registered
//! real addresses while they are fresh (the gateway's internal cache).
//!
//! Not ported: DNS64/NAT64 (Phase 3), so nothing is un-NAT64'd.

use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// 2 min extension of a translation on every use
pub const TTL2M: Duration = Duration::from_secs(120);
/// minimum life of a translation (close to transport timeouts)
pub const TTL8S: Duration = Duration::from_secs(8);
const STALE_THRES: Duration = Duration::from_secs(24 * 3600);
const VACCUM_INTERVAL: Duration = Duration::from_secs(120);
const MAX_ITER: usize = 100;
const KEY4: &str = ":a";
const KEY6: &str = ":aaaa";
/// tid wildcard (firestack `notransport`; `NoDNS` is the empty string)
pub const NOTRANSPORT: &str = "NoTransport";
pub const UNKNOWN_UID: &str = "-1";
const RFC8215A: [u16; 5] = [0x64, 0xff9b, 0x1, 0xda19, 0x100];

fn none_tid(tid: &str) -> bool {
    tid.is_empty() || tid == NOTRANSPORT
}

/// `BlockAll` / `CacheBlockAll` (firestack `skipInternalCache`)
pub fn is_block_all(tid: &str) -> bool {
    tid == fs_dns::ids::BLOCK_ALL
        || tid.strip_prefix(fs_dns::ids::CACHE_PREFIX) == Some(fs_dns::ids::BLOCK_ALL)
}

/// Flattens, keeping the first occurrence (firestack `core.CopyUniq`).
fn copy_uniq<T: PartialEq + Clone>(lists: &[&[T]]) -> Vec<T> {
    let mut out: Vec<T> = Vec::new();
    for l in lists {
        for x in *l {
            if !out.contains(x) {
                out.push(x.clone());
            }
        }
    }
    out
}

fn fresh_of(ttl: Option<Instant>) -> (Duration, bool) {
    match ttl {
        Some(t) => {
            let now = Instant::now();
            if t > now {
                (t - now, true)
            } else {
                (Duration::ZERO, false)
            }
        }
        None => (Duration::ZERO, false),
    }
}

/// Go `a.After(b)` on optional instants (zero = None).
fn after(a: Option<Instant>, b: Option<Instant>) -> bool {
    match (a, b) {
        (None, b) => b.is_none(),
        (Some(_), None) => true,
        (Some(a), Some(b)) => a > b,
    }
}

fn within_stale(dob: Option<Instant>) -> bool {
    dob.is_some_and(|d| d.elapsed() <= STALE_THRES)
}

/// Values of type `T` with a ttl and a birth time (firestack `expaddr` / `expdomains`).
#[derive(Clone, Debug)]
struct Exp<T> {
    v: Vec<T>,
    ttl: Option<Instant>,
    dob: Option<Instant>,
}

impl<T> Default for Exp<T> {
    fn default() -> Self {
        Exp {
            v: Vec::new(),
            ttl: None,
            dob: None,
        }
    }
}

impl<T: Clone + PartialEq> Exp<T> {
    fn fresh(&self) -> bool {
        fresh_of(self.ttl).1
    }
    /// `alive`: only while fresh
    fn get(&self, alive: bool) -> Vec<T> {
        if !alive || self.fresh() {
            self.v.clone()
        } else {
            Vec::new()
        }
    }
}

/// youngest first
fn by_dob<T>(xs: &mut [&Exp<T>]) {
    xs.sort_by(|a, b| {
        if after(a.dob, b.dob) && !after(b.dob, a.dob) {
            std::cmp::Ordering::Less
        } else if after(b.dob, a.dob) && !after(a.dob, b.dob) {
            std::cmp::Ordering::Greater
        } else {
            std::cmp::Ordering::Equal
        }
    });
}

/// moves `v` into `past` under `k` (merging while within the stale threshold)
fn relegate<T: Clone + PartialEq>(past: &mut HashMap<String, Exp<T>>, k: &str, v: &Exp<T>) {
    match past.get_mut(k) {
        Some(cur) if within_stale(cur.dob) => {
            cur.v = copy_uniq(&[&cur.v, &v.v]);
            if after(v.dob, cur.dob) && v.dob.is_some() {
                cur.dob = v.dob;
            }
        }
        _ => {
            past.insert(
                k.to_string(),
                Exp {
                    v: copy_uniq(&[&v.v]),
                    ttl: v.ttl,
                    dob: v.dob,
                },
            );
        }
    }
}

fn vaccum<T>(past: &mut HashMap<String, Exp<T>>, last: &mut Option<Instant>) {
    if last.is_some_and(|l| l.elapsed() < VACCUM_INTERVAL) {
        return;
    }
    let stale: Vec<String> = past
        .iter()
        .take(MAX_ITER)
        .filter(|(_, v)| !within_stale(v.dob))
        .map(|(k, _)| k.clone())
        .collect();
    for k in stale {
        past.remove(&k);
    }
    *last = Some(Instant::now());
}

/// merges `qv` into the entry `pv` (firestack `merge`, per key)
fn merge_one<T: Clone + PartialEq>(
    pmap: &mut HashMap<String, Exp<T>>,
    past: Option<&mut HashMap<String, Exp<T>>>,
    k: &str,
    qv: &Exp<T>,
) {
    let pv = pmap.get(k).cloned().unwrap_or_default();
    if !pv.fresh() {
        if let Some(past) = past
            && !pv.v.is_empty()
            && within_stale(pv.dob)
        {
            relegate(past, k, &pv);
        }
        pmap.insert(k.to_string(), qv.clone());
        return;
    }
    let (v, dob) = if !after(pv.dob, qv.dob) {
        (copy_uniq(&[&qv.get(true), &pv.get(true)]), qv.dob)
    } else {
        (copy_uniq(&[&pv.get(true), &qv.get(true)]), pv.dob)
    };
    if let Some(past) = past
        && !qv.v.is_empty()
        && within_stale(qv.dob)
    {
        relegate(past, k, qv);
    }
    let ttl = if !after(pv.ttl, qv.ttl) {
        qv.ttl
    } else {
        pv.ttl
    };
    pmap.insert(k.to_string(), Exp { v, ttl, dob });
}

/// Addresses of an answer: primary by tid, secondary by tid+uid (firestack `xips`).
#[derive(Default, Debug)]
pub struct Xips {
    pri: HashMap<String, Exp<IpAddr>>,
    aux: HashMap<String, Exp<IpAddr>>,
    past: HashMap<String, Exp<IpAddr>>,
    last_vaccum: Option<Instant>,
}

fn uid_or_unknown(uid: &str) -> &str {
    if uid.is_empty() { UNKNOWN_UID } else { uid }
}

impl Xips {
    fn new(tid: &str, uid: &str, pri: Vec<IpAddr>, sec: Vec<IpAddr>, ttl: Instant) -> Self {
        let mut x = Xips::default();
        let now = Some(Instant::now());
        if !pri.is_empty() {
            x.pri.insert(
                tid.to_string(),
                Exp {
                    v: pri,
                    ttl: Some(ttl),
                    dob: now,
                },
            );
        }
        if !sec.is_empty() {
            x.aux.insert(
                format!("{tid}{}", uid_or_unknown(uid)),
                Exp {
                    v: sec,
                    ttl: Some(ttl),
                    dob: now,
                },
            );
        }
        x
    }

    fn allips(&self, sec: bool, alive: bool) -> Vec<IpAddr> {
        let g = if sec { &self.aux } else { &self.pri };
        let mut vs: Vec<&Exp<IpAddr>> = g.values().collect();
        by_dob(&mut vs);
        let mut out: Vec<IpAddr> = vs.iter().flat_map(|v| v.get(alive)).collect();
        if !alive && !sec {
            let mut ps: Vec<&Exp<IpAddr>> = self.past.values().collect();
            by_dob(&mut ps);
            for v in ps {
                if within_stale(v.dob) {
                    out = copy_uniq(&[&out, &v.v]);
                }
            }
        }
        out
    }

    fn ips_for(&self, tid: &str, uid: &str, sec: bool, alive: bool) -> Vec<IpAddr> {
        let uid = uid_or_unknown(uid);
        if !sec && none_tid(tid) {
            return self.allips(false, alive);
        }
        if sec {
            if none_tid(tid) {
                let mut out = Vec::new();
                for (k, v) in &self.aux {
                    if k.ends_with(uid) {
                        out.extend(v.get(alive));
                    }
                }
                return out;
            }
            return self
                .aux
                .get(&format!("{tid}{uid}"))
                .map(|v| v.get(alive))
                .unwrap_or_default();
        }
        self.pri.get(tid).map(|v| v.get(alive)).unwrap_or_default()
    }

    /// secondary answer had a block (0.0.0.0 / ::) for this uid
    fn zz(&self, uid: &str) -> bool {
        self.ips_for(NOTRANSPORT, uid, true, true)
            .iter()
            .any(|ip| ip.is_unspecified())
    }

    /// all primary addresses, plus the unspecified ones when the uid's secondary answer was a block
    fn realips(&self, uid: &str, alive: bool) -> Vec<IpAddr> {
        let mut pri = self.allips(false, alive);
        if self.zz(uid) {
            pri.push(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
            pri.push(IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        }
        pri
    }

    fn realips_for(&self, tid: &str, uid: &str, alive: bool) -> Vec<IpAddr> {
        self.ips_for(tid, uid, false, alive)
    }

    fn secips_for(&self, tid: &str, uid: &str) -> Vec<IpAddr> {
        self.ips_for(tid, uid, true, true)
    }

    /// every primary and secondary address (for the realip -> answer map)
    fn each(&self) -> Vec<IpAddr> {
        let mut v = self.allips(false, false);
        v.extend(self.allips(true, false));
        v
    }

    fn rmv(&mut self, tid: &str) -> bool {
        if none_tid(tid) {
            return false;
        }
        let mut n = 0;
        if let Some(x) = self.pri.get(tid).cloned()
            && x.fresh()
        {
            n += 1;
            let mut x = x;
            x.ttl = Some(Instant::now());
            self.pri.insert(tid.to_string(), x.clone());
            relegate(&mut self.past, tid, &x);
        }
        for (k, v) in self.aux.iter_mut() {
            if v.fresh() && k.starts_with(tid) {
                n += 1;
                v.ttl = Some(Instant::now());
            }
        }
        if n > 0 {
            vaccum(&mut self.past, &mut self.last_vaccum);
        }
        n > 0
    }

    fn merge(&mut self, q: &Xips) {
        for (k, qv) in &q.pri {
            merge_one(&mut self.pri, Some(&mut self.past), k, qv);
        }
        for (k, qv) in &q.aux {
            merge_one(&mut self.aux, None, k, qv);
        }
        vaccum(&mut self.past, &mut self.last_vaccum);
    }
}

/// Names of an answer per tid+uid (firestack `xdomains`).
#[derive(Default, Debug)]
pub struct Xdomains {
    pri: HashMap<String, Exp<String>>,
    past: HashMap<String, Exp<String>>,
    last_vaccum: Option<Instant>,
}

impl Xdomains {
    fn new(tid: &str, uid: &str, pri: Vec<String>, ttl: Instant) -> Self {
        let mut x = Xdomains::default();
        if !pri.is_empty() {
            x.pri.insert(
                format!("{tid}{}", uid_or_unknown(uid)),
                Exp {
                    v: pri,
                    ttl: Some(ttl),
                    dob: Some(Instant::now()),
                },
            );
        }
        x
    }

    fn domains_for(&self, tid: &str, uid: &str, alive: bool) -> Vec<String> {
        let uid = uid_or_unknown(uid);
        let key = format!("{tid}{uid}");
        let mut out: Vec<String> = Vec::new();
        if none_tid(tid) {
            let mut vs: Vec<&Exp<String>> = self
                .pri
                .iter()
                .filter(|(k, _)| k.ends_with(uid))
                .map(|(_, v)| v)
                .collect();
            by_dob(&mut vs);
            for v in vs {
                out.extend(v.get(alive));
            }
            if !alive {
                let mut ps: Vec<&Exp<String>> = self
                    .past
                    .iter()
                    .filter(|(k, _)| k.ends_with(uid))
                    .map(|(_, v)| v)
                    .collect();
                by_dob(&mut ps);
                for v in ps {
                    if within_stale(v.dob) {
                        out = copy_uniq(&[&out, &v.v]);
                    }
                }
            }
        } else {
            if let Some(v) = self.pri.get(&key) {
                out = v.get(alive);
            }
            if !alive
                && let Some(v) = self.past.get(&key)
                && within_stale(v.dob)
            {
                out = copy_uniq(&[&out, &v.v]);
            }
        }
        out
    }

    fn rmv(&mut self, tid: &str) -> bool {
        if none_tid(tid) {
            return false;
        }
        let mut n = 0;
        let keys: Vec<String> = self
            .pri
            .keys()
            .filter(|k| k.starts_with(tid))
            .cloned()
            .collect();
        for k in keys {
            let v = self.pri.get_mut(&k).unwrap();
            if v.fresh() {
                n += 1;
                v.ttl = Some(Instant::now());
                let v = v.clone();
                relegate(&mut self.past, &k, &v);
            }
        }
        if n > 0 {
            vaccum(&mut self.past, &mut self.last_vaccum);
        }
        n > 0
    }

    fn merge(&mut self, q: &Xdomains) {
        for (k, qv) in &q.pri {
            merge_one(&mut self.pri, Some(&mut self.past), k, qv);
        }
        vaccum(&mut self.past, &mut self.last_vaccum);
    }
}

/// What the gateway knows about one answer (firestack `baseans`).
#[derive(Debug)]
pub struct BaseAns {
    ips: Xips,
    domains: Xdomains,
    blocklists: String,
    /// life of the translation; extended by 2 min on every use
    ttl: Option<Instant>,
}

impl BaseAns {
    fn fresh(&self) -> (Duration, bool) {
        fresh_of(self.ttl)
    }
    /// firestack `algans.extend`
    fn extend(&mut self, by: Duration) {
        match self.ttl {
            Some(t) if t > Instant::now() => self.ttl = Some(t + by),
            _ => self.ttl = Some(Instant::now() + by),
        }
    }
    /// firestack `algans.merge`: `b` into `self`
    fn merge(&mut self, b: &BaseAns) {
        self.ips.merge(&b.ips);
        self.domains.merge(&b.domains);
        self.blocklists = b.blocklists.clone();
        if after(b.ttl, self.ttl) && b.ttl != self.ttl {
            self.ttl = b.ttl;
        }
    }
}

type Base = Arc<Mutex<BaseAns>>;

struct AlgAns {
    algip: IpAddr,
    base: Base,
}

#[derive(Default)]
struct State {
    /// qname + ":a0" / ":aaaa0" -> translation
    alg: HashMap<String, AlgAns>,
    /// algip -> answer
    nat: HashMap<IpAddr, Base>,
    /// realip -> answers (several names may share an address)
    ptr: HashMap<IpAddr, Vec<Base>>,
}

/// The secondary transport's view of a query (firestack `secans`).
#[derive(Clone, Debug, Default)]
pub struct SecAns {
    pub ips: Vec<IpAddr>,
    pub blocklists: String,
    pub blocked_target: String,
    pub upstream_blocks: bool,
    pub msg: String,
    /// derived from the primary answer (no secondary transport)
    pub pri: bool,
}

/// Which addresses `resolv` returns.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IpType {
    Alg,
    Real,
    Secondary,
}

/// The DNS gateway.
pub struct Gateway {
    st: RwLock<State>,
    /// translate answers (ALG)
    pub(crate) modify: AtomicBool,
    /// enforce split tunnelling through the Fixed transport
    fix: AtomicBool,
    /// per-app split tunnelling seen (keys per uid)
    split: AtomicBool,
    fake: Vec<SocketAddr>,
    /// this process' uid (firestack `protect.MyUid`)
    pub(crate) my_uid: String,
}

/// FNV-1a 64
fn fnv64a(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// xor-folded FNV to 22 bits
pub fn hash22(s: &str) -> u32 {
    let v = fnv64a(s);
    (((v >> 22) as u32) ^ (v as u32)) & 0x3F_FFFF
}

/// xor-folded FNV to 48 bits
pub fn hash48(s: &str) -> u64 {
    let v = fnv64a(s);
    ((v >> 48) ^ v) & 0xFFFF_FFFF_FFFF
}

/// firestack `gen4Locked`: 100.64.0.0/10 address for key `k` and `salt`.
pub fn gen4(k: &str, salt: usize) -> IpAddr {
    let v = hash22(&format!("{salt}{k}"));
    IpAddr::V4(Ipv4Addr::new(
        100,
        64 + (v >> 16) as u8,
        (v >> 8) as u8,
        v as u8,
    ))
}

/// firestack `gen6Locked`: 64:ff9b:1:da19:100::/80 address for key `k` and `hop`.
pub fn gen6(k: &str, hop: usize) -> IpAddr {
    let v = hash48(&format!("{hop}{k}"));
    IpAddr::V6(Ipv6Addr::new(
        RFC8215A[0],
        RFC8215A[1],
        RFC8215A[2],
        RFC8215A[3],
        RFC8215A[4],
        (v >> 32) as u16,
        (v >> 16) as u16,
        v as u16,
    ))
}

/// Go `netip.Addr.IsGlobalUnicast`
fn go_global_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            !(v.is_unspecified()
                || v.is_loopback()
                || v.is_multicast()
                || v.is_link_local()
                || v.is_broadcast())
        }
        IpAddr::V6(v) => {
            !(v.is_unspecified()
                || v.is_loopback()
                || v.is_multicast()
                || (v.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}

fn v4only(ips: &[IpAddr]) -> Vec<IpAddr> {
    ips.iter().filter(|i| i.is_ipv4()).copied().collect()
}
fn v6only(ips: &[IpAddr]) -> Vec<IpAddr> {
    ips.iter().filter(|i| i.is_ipv6()).copied().collect()
}

fn unmap(ip: IpAddr) -> IpAddr {
    ip.to_canonical()
}

impl Gateway {
    pub fn new(fake: Vec<SocketAddr>) -> Self {
        Gateway {
            st: RwLock::new(State::default()),
            modify: AtomicBool::new(false),
            fix: AtomicBool::new(false),
            split: AtomicBool::new(false),
            fake,
            my_uid: own_uid(),
        }
    }

    /// firestack `translate(tr, fix)`
    pub fn translate(&self, tr: bool, fix: bool) {
        self.modify.store(tr, Ordering::Relaxed);
        self.fix.store(fix, Ordering::Relaxed);
    }

    /// this process' uid (firestack `protect.MyUid`)
    pub fn my_uid(&self) -> &str {
        &self.my_uid
    }

    pub fn translating(&self) -> bool {
        self.modify.load(Ordering::Relaxed)
    }

    pub fn split_tunnel(&self) {
        self.split.store(true, Ordering::Relaxed);
    }

    pub fn splitting(&self) -> bool {
        self.split.load(Ordering::Relaxed)
    }

    /// Fixed answers need translation, per-app split tunnelling and `fix`.
    pub fn fixed_transport(&self) -> bool {
        self.translating() && self.splitting() && self.fix.load(Ordering::Relaxed)
    }

    /// firestack `stop`: forgets everything.
    pub fn clear(&self) {
        *self.st.write() = State::default();
    }

    /// firestack `onStopped`: expires what transport `tid` answered.
    pub fn on_stopped(&self, tid: &str) {
        if tid.is_empty() {
            return;
        }
        let bases: Vec<Base> = self
            .st
            .read()
            .alg
            .values()
            .map(|a| a.base.clone())
            .collect();
        for b in bases {
            let mut b = b.lock();
            b.ips.rmv(tid);
            b.domains.rmv(tid);
        }
    }

    fn take(st: &mut State, q: &str, v6: bool) -> Option<IpAddr> {
        let k = format!("{q}{}0", if v6 { KEY6 } else { KEY4 });
        if let Some(ans) = st.alg.get(&k) {
            if ans.algip.is_ipv6() == v6 {
                ans.base.lock().extend(TTL2M);
                return Some(ans.algip);
            }
            // wrong family (should not happen): drop the entry and generate a new one
            let ans = st.alg.remove(&k).unwrap();
            st.nat.remove(&ans.algip);
            let ips = ans.base.lock().ips.each();
            for ip in ips {
                ptr_remove(st, ip, &ans.base);
            }
        }
        for i in 0..MAX_ITER {
            let ip = if v6 { gen6(&k, i) } else { gen4(&k, i) };
            if !v6 && !go_global_unicast(ip) {
                continue;
            }
            if !st.nat.contains_key(&ip) {
                return Some(ip);
            }
        }
        None
    }

    /// firestack `take4Locked` / `take6Locked` under the write lock, for the answer path.
    pub fn with_state<R>(&self, f: impl FnOnce(&mut GwTxn) -> R) -> R {
        let mut st = self.st.write();
        let mut txn = GwTxn { st: &mut st };
        f(&mut txn)
    }

    /// firestack `X`: real addresses for a flow's destination (an ALG address, or a real one), and whether it was
    /// a translation. An empty list for a known (but expired) translation tells the caller to re-resolve.
    pub fn x(&self, maybe_alg: IpAddr, uid: &str, tids: &[&str]) -> (Vec<IpAddr>, bool) {
        let uid = if self.splitting() { uid } else { UNKNOWN_UID };
        let usestale = !self.translating();
        let st = self.st.read();
        self.x_locked(&st, maybe_alg, !usestale, uid, tids)
    }

    fn x_locked(
        &self,
        st: &State,
        maybe_alg: IpAddr,
        alive: bool,
        uid: &str,
        tids: &[&str],
    ) -> (Vec<IpAddr>, bool) {
        let unmapped = unmap(maybe_alg);
        if self.fake.iter().any(|f| f.ip() == unmapped) {
            return (vec![maybe_alg], false);
        }
        let didnot = tids.iter().any(|t| is_block_all(t)) || uid == self.my_uid;
        let (mut realips, mut undid_alg, mut undid_ptr) = (Vec::new(), false, false);
        if !didnot {
            if let Some(b) = st.nat.get(&unmapped) {
                undid_alg = true;
                let b = b.lock();
                if tids.is_empty() {
                    realips = b.ips.realips(uid, alive);
                } else {
                    for t in tids {
                        realips.extend(b.ips.realips_for(t, uid, alive));
                    }
                }
            } else if let Some(list) = st.ptr.get(&unmapped).filter(|l| !l.is_empty()) {
                undid_ptr = true;
                for b in list {
                    let b = b.lock();
                    if tids.is_empty() {
                        realips.extend(b.ips.realips(uid, alive));
                    } else {
                        for t in tids {
                            realips.extend(b.ips.realips_for(t, uid, alive));
                        }
                    }
                }
            }
        }
        if realips.is_empty() {
            if undid_alg || undid_ptr {
                return (realips, undid_alg);
            }
            return (vec![unmapped], undid_alg);
        }
        (copy_uniq(&[&realips]), undid_alg)
    }

    /// firestack `PTR`: names for a flow's destination; `force` also consults the realip map in ALG mode.
    /// Returns (csv, whether the realip map was allowed).
    pub fn ptr(&self, maybe_alg: IpAddr, uid: &str, tid: &str, force: bool) -> (String, bool) {
        let uid = if self.splitting() { uid } else { UNKNOWN_UID };
        let useptr = !self.translating() || force;
        let st = self.st.read();
        (
            ptr_locked(&st, maybe_alg, uid, tid, useptr).join(","),
            useptr,
        )
    }

    /// firestack `RDNSBL`: blocklists recorded with the answer behind a destination.
    pub fn rdnsbl(&self, maybe_alg: IpAddr) -> String {
        let useptr = !self.translating();
        let st = self.st.read();
        let unmapped = unmap(maybe_alg);
        if let Some(b) = st.nat.get(&unmapped) {
            return b.lock().blocklists.clone();
        }
        if useptr && let Some(list) = st.ptr.get(&unmapped) {
            return list
                .iter()
                .map(|b| b.lock().blocklists.clone())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(",");
        }
        String::new()
    }

    /// firestack `resolvLocked` (A and AAAA halves): addresses for `domain` by kind, the shortest remaining life.
    pub fn resolv(
        &self,
        domain: &str,
        typ: IpType,
        tid: &str,
        uid: &str,
    ) -> (Vec<IpAddr>, Vec<IpAddr>, Option<Duration>) {
        let st = self.st.read();
        let mut until: Option<Duration> = None;
        let mut halves = [Vec::new(), Vec::new()];
        for (h, key) in [KEY4, KEY6].iter().enumerate() {
            let Some(ans) = st.alg.get(&format!("{domain}{key}0")) else {
                continue;
            };
            let b = ans.base.lock();
            let (life, fresh) = b.fresh();
            if !fresh {
                continue;
            }
            let ips = match typ {
                IpType::Alg => vec![ans.algip],
                IpType::Real => b.ips.realips_for(tid, uid, true),
                IpType::Secondary => b.ips.secips_for(tid, uid),
            };
            halves[h] = if typ == IpType::Alg {
                ips
            } else if h == 0 {
                v4only(&ips)
            } else {
                v6only(&ips)
            };
            until = Some(until.map_or(life, |u| u.min(life)));
        }
        let [a, b] = halves;
        (a, b, until)
    }
}

/// The gateway's state under its write lock, for one answer.
pub struct GwTxn<'a> {
    st: &'a mut State,
}

impl GwTxn<'_> {
    pub fn take4(&mut self, q: &str) -> Option<IpAddr> {
        Gateway::take(self.st, q, false)
    }
    pub fn take6(&mut self, q: &str) -> Option<IpAddr> {
        Gateway::take(self.st, q, true)
    }

    /// firestack `registerLocked`: qname -> (algip, answer), algip -> answer, each realip -> answer.
    #[allow(clippy::too_many_arguments)]
    pub fn register(
        &mut self,
        q: &str,
        tid: &str,
        uid: &str,
        algip4: Option<IpAddr>,
        algip6: Option<IpAddr>,
        realips: &[IpAddr],
        ansttl: Duration,
        targets: &[String],
        sec: &SecAns,
    ) -> bool {
        if none_tid(tid) || (algip4.is_none() && algip6.is_none()) {
            return false;
        }
        let now = Instant::now();
        let ttl = ansttl.max(TTL8S);
        let algttl = now + TTL2M.max(ttl);
        let xipsttl = now + ttl;
        let mk = |ips: Vec<IpAddr>, secs: Vec<IpAddr>| BaseAns {
            ips: Xips::new(tid, uid, ips, secs, xipsttl),
            domains: Xdomains::new(tid, uid, targets.to_vec(), xipsttl),
            blocklists: sec.blocklists.clone(),
            ttl: Some(algttl),
        };
        let mut did = false;
        for (ip, v6) in [(algip4, false), (algip6, true)] {
            let Some(ip) = ip else { continue };
            let k = format!("{q}{}0", if v6 { KEY6 } else { KEY4 });
            let fresh = if v6 {
                mk(v6only(realips), v6only(&sec.ips))
            } else {
                mk(v4only(realips), v4only(&sec.ips))
            };
            let base = match self.st.alg.get(&k) {
                Some(prev) => {
                    prev.base.lock().merge(&fresh);
                    prev.base.clone()
                }
                None => {
                    let base = Arc::new(Mutex::new(fresh));
                    self.st.alg.insert(
                        k,
                        AlgAns {
                            algip: ip,
                            base: base.clone(),
                        },
                    );
                    self.st.nat.insert(ip, base.clone());
                    base
                }
            };
            let ips = base.lock().ips.each();
            for rip in ips {
                let e = self.st.ptr.entry(rip).or_default();
                if !e.iter().any(|b| Arc::ptr_eq(b, &base)) {
                    e.push(base.clone());
                }
            }
            did = true;
        }
        did
    }
}

fn ptr_remove(st: &mut State, ip: IpAddr, target: &Base) {
    if let Some(list) = st.ptr.get_mut(&ip) {
        list.retain(|b| !Arc::ptr_eq(b, target));
        if list.is_empty() {
            st.ptr.remove(&ip);
        }
    }
}

fn ptr_locked(st: &State, maybe_alg: IpAddr, uid: &str, tid: &str, useptr: bool) -> Vec<String> {
    let unmapped = unmap(maybe_alg);
    let uid = uid_or_unknown(uid);
    let tid = if tid.is_empty() { NOTRANSPORT } else { tid };
    let mut domains: Vec<String> = Vec::new();
    if let Some(b) = st.nat.get(&unmapped) {
        domains = b.lock().domains.domains_for(tid, uid, true);
    }
    if useptr
        && domains.is_empty()
        && let Some(list) = st.ptr.get(&unmapped)
    {
        for b in list {
            domains.extend(b.lock().domains.domains_for(tid, uid, true));
        }
        if domains.is_empty() {
            for b in list {
                domains.extend(b.lock().domains.domains_for(tid, uid, false));
            }
        }
    }
    copy_uniq(&[&domains])
}

/// this process' uid, as a string (firestack `protect.MyUid`)
fn own_uid() -> String {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe extern "C" {
        fn getuid() -> u32;
    }
    unsafe { getuid() }.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn hashes_are_fnv_folds() {
        // FNV-1a 64 of "" and "a" (reference values)
        assert_eq!(fnv64a(""), 0xcbf29ce484222325);
        assert_eq!(fnv64a("a"), 0xaf63dc4c8601ec8c);
        let a = gen4("example.com:a0", 0);
        assert!(
            matches!(a, IpAddr::V4(v) if v.octets()[0] == 100 && (64..128).contains(&v.octets()[1]))
        );
        let b = gen6("example.com:aaaa0", 0);
        assert!(b.to_string().starts_with("64:ff9b:1:da19:100:"));
    }

    #[test]
    fn register_translate_and_undo() {
        let g = Gateway::new(vec!["10.111.222.3:53".parse().unwrap()]);
        g.translate(true, false);
        let real = [
            ip("93.184.215.14"),
            ip("2606:2800:21f:cb07:6820:80da:af6b:8b2c"),
        ];
        let sec = SecAns::default();
        let (a4, a6) = g.with_state(|t| {
            let a4 = t.take4("example.com").unwrap();
            let a6 = t.take6("example.com").unwrap();
            let targets = vec!["example.com".to_string(), "edge.example.net".to_string()];
            assert!(t.register(
                "example.com",
                "Preferred",
                "-1",
                Some(a4),
                Some(a6),
                &real,
                Duration::from_secs(60),
                &targets,
                &sec
            ));
            (a4, a6)
        });
        assert_eq!(
            g.with_state(|t| t.take4("example.com")),
            Some(a4),
            "stable per domain"
        );
        assert_eq!(g.x(a4, "-1", &[]), (vec![real[0]], true));
        assert_eq!(g.x(a6, "-1", &["Preferred"]), (vec![real[1]], true));
        assert_eq!(
            g.x(a6, "-1", &["Other"]),
            (vec![], true),
            "known translation, nothing for that tid"
        );
        assert_eq!(g.ptr(a4, "-1", "", false).0, "example.com,edge.example.net");
        // a real address maps back through the realip table only when allowed
        assert_eq!(g.ptr(real[0], "-1", "", false), (String::new(), false));
        assert_eq!(
            g.ptr(real[0], "-1", "", true).0,
            "example.com,edge.example.net"
        );
        assert_eq!(g.x(ip("1.2.3.4"), "-1", &[]), (vec![ip("1.2.3.4")], false));
        assert_eq!(
            g.x(ip("10.111.222.3"), "-1", &[]),
            (vec![ip("10.111.222.3")], false)
        );
        let (r4, r6, until) = g.resolv("example.com", IpType::Real, "Preferred", "-1");
        assert_eq!((r4, r6), (vec![real[0]], vec![real[1]]));
        assert!(until.unwrap() > Duration::from_secs(50));
        g.on_stopped("Preferred");
        assert_eq!(
            g.x(a4, "-1", &[]),
            (vec![], true),
            "expired with its transport"
        );
        // without translation the realip table serves PTR, and stale addresses still count
        g.translate(false, false);
        assert_eq!(g.x(a4, "-1", &[]), (vec![real[0]], true));
        assert_eq!(
            g.ptr(real[0], "-1", "", false).0,
            "example.com,edge.example.net"
        );
    }

    #[test]
    fn secondary_blocks_show_as_unspecified() {
        let g = Gateway::new(vec![]);
        g.translate(true, false);
        let sec = SecAns {
            ips: vec![ip("0.0.0.0"), ip("::")],
            blocklists: "privacy:x".into(),
            ..Default::default()
        };
        let a4 = g.with_state(|t| {
            let a4 = t.take4("ads.example").unwrap();
            t.register(
                "ads.example",
                "Preferred",
                "-1",
                Some(a4),
                None,
                &[ip("1.1.1.1")],
                Duration::ZERO,
                &[],
                &sec,
            );
            a4
        });
        let (ips, undid) = g.x(a4, "-1", &[]);
        assert!(undid && ips.contains(&ip("1.1.1.1")) && ips.contains(&ip("0.0.0.0")));
        assert_eq!(g.rdnsbl(a4), "privacy:x");
    }
}
