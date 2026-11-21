// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/dnsx/transport.go (forward, determineTransport, preferences)
// Derived-From: celzero/firestack@d3d530ea3e:intra/dnsx/overrides.go (fake DNS addresses, isDns)
// Derived-From: celzero/firestack@d3d530ea3e:intra/dnsx/bootstrap.go (Default transport, internal lookups)

//! Resolver: registry of transports by id, cache, and the per-query policy dance with Kotlin:
//! `onQuery` (3 s) → transport choice from `TIDCSV` → cache → upstream → `onUpstreamAnswer` (15 s, may redirect
//! once) → cache store → `onResponse`. On upstream failure the client gets no reply (firestack semantics).

use crate::alg::{self, Gateway, IpType, SecAns};
use crate::cache::{self, Caches, Summ, TCache};
use fs_blocklist::stamp::{Mode, Rdns};
use fs_core::bridge::{DnsListener, DnsOpts, DnsSummary, dns_status};
use fs_core::settings;
use fs_dns::ids;
use fs_dns::msg;
use fs_dns::transport::Transport;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::{RData, RecordType};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const ON_QUERY_TIMEOUT: Duration = Duration::from_secs(3);
pub const ON_UPSTREAM_ANSWER_TIMEOUT: Duration = Duration::from_secs(15);
pub const ORIGIN_TUNNEL: &str = "tunnel";
/// firestack `errNop`
const NO_ERROR: &str = "no error";
/// `dns.RcodeBadTime`, reported when a transport is in hangover
const RCODE_BADTIME: i64 = 18;

fn unix_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub struct Resolver {
    transports: RwLock<HashMap<String, Arc<dyn Transport>>>,
    caches: Arc<Caches>,
    rdnsl: RwLock<Option<Arc<fs_blocklist::RdnsLocal>>>,
    rdnsr: RwLock<Option<Arc<Rdns>>>,
    listener: Arc<dyn DnsListener>,
    fakedns: Vec<SocketAddr>,
    gw: Arc<Gateway>,
}

impl Resolver {
    /// `fakedns` is the csv of `ip:port` addresses apps send DNS to (firestack requires ports).
    pub fn new(fakedns_csv: &str, listener: Arc<dyn DnsListener>) -> Self {
        let fakedns: Vec<SocketAddr> = fakedns_csv
            .split(',')
            .filter_map(|s| s.trim().parse::<SocketAddr>().ok())
            .collect();
        Resolver {
            transports: RwLock::new(HashMap::new()),
            caches: Arc::new(Caches::default()),
            rdnsl: RwLock::new(None),
            rdnsr: RwLock::new(None),
            listener,
            gw: Arc::new(Gateway::new(fakedns.clone())),
            fakedns,
        }
    }

    pub fn fakedns(&self) -> &[SocketAddr] {
        &self.fakedns
    }

    /// firestack `isDns`: does `dst` address the resolver? (DNSModeIP: exact fake DNS ip:port; DNSModePort: any :53)
    pub fn is_dns_addr(&self, dst: SocketAddr) -> bool {
        match settings::DNS_MODE.load(Ordering::Relaxed) {
            settings::DNS_MODE_IP => self
                .fakedns
                .iter()
                .any(|f| f.ip() == dst.ip() && f.port() == dst.port()),
            settings::DNS_MODE_PORT => dst.port() == 53,
            _ => false,
        }
    }

    /// Adds or replaces a transport; notifies Kotlin (`onDNSAdded`).
    pub fn add(&self, t: Arc<dyn Transport>) -> bool {
        let id = t.id().to_string();
        self.transports.write().insert(id.clone(), t);
        self.caches.drop_tid(&id); // firestack recreates the caching transport
        self.listener.on_dns_added(id);
        true
    }

    pub fn remove(&self, id: &str) -> bool {
        let removed = self.transports.write().remove(id).is_some();
        self.caches.drop_tid(id);
        // firestack onStopped: what the transport (and its cache) answered expires
        self.gw.on_stopped(id);
        self.gw.on_stopped(&format!("{}{id}", ids::CACHE_PREFIX));
        if removed {
            self.listener.on_dns_removed(id.to_string());
        }
        removed
    }

    pub fn get(&self, id: &str) -> Option<Arc<dyn Transport>> {
        self.transports.read().get(id).cloned()
    }

    pub fn live_transports(&self) -> String {
        let mut ids: Vec<String> = self.transports.read().keys().cloned().collect();
        ids.sort();
        ids.join(",")
    }

    pub fn clear_cache(&self) {
        self.caches.clear();
    }

    pub fn stop_all(&self) {
        self.transports.write().clear();
        self.caches.clear();
        self.gw.clear();
        self.listener.on_dns_stopped();
    }

    /// firestack `determineTransport`, reduced to the Phase 1 transports.
    fn determine(&self, tid: &str) -> Option<Arc<dyn Transport>> {
        let fallback = || {
            if settings::DEFAULT_DNS_AS_FALLBACK.load(Ordering::Relaxed) {
                self.get(ids::DEFAULT)
            } else {
                None
            }
        };
        match tid {
            ids::DEFAULT | "CacheDefault" | ids::BOOTSTRAP => self.get(ids::DEFAULT),
            ids::SYSTEM => self
                .get(ids::SYSTEM)
                .or_else(|| self.get(ids::GOOS))
                .or_else(fallback),
            ids::BLOCK_FREE => self
                .get(ids::BLOCK_FREE)
                .or_else(|| self.get(ids::PREFERRED))
                .or_else(fallback),
            other => self.get(other).or_else(fallback),
        }
    }
}

/// Outcome of one resolution run.
enum Step {
    /// no answer for the client
    None,
    /// answer for the client (translated with ALG) and the real addresses (Kotlin's `onUpstreamAnswer` follows)
    Answer(Vec<u8>, String),
    /// final answer (blocked by on-device blocklists)
    Final(Vec<u8>),
}

/// One entry of `TIDCSV`: `[Cache]<tid>[:pid1[:pid2]]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pref {
    pub cache: bool,
    pub tid: String,
    pub pids: Vec<String>,
}

pub fn parse_tidcsv(csv: &str) -> Vec<Pref> {
    csv.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|e| {
            let mut parts = e.split(':');
            let mut tid = parts.next().unwrap_or_default().to_string();
            let cache = tid.starts_with(ids::CACHE_PREFIX) && tid.len() > ids::CACHE_PREFIX.len();
            if cache {
                tid = tid[ids::CACHE_PREFIX.len()..].to_string();
            }
            Pref {
                cache,
                tid,
                pids: parts.filter(|p| !p.is_empty()).map(String::from).collect(),
            }
        })
        .collect()
}

/// firestack `parseAllTidOpts`: tids as written (`Cache` prefix kept) and their pid csv.
fn parse_all_tid_opts(csv: &str) -> (Vec<String>, HashMap<String, String>) {
    let mut tids = Vec::new();
    let mut pids = HashMap::new();
    for v in csv.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let mut parts = v.split(':');
        let tid = parts.next().unwrap_or_default().to_string();
        if tid.is_empty() {
            continue;
        }
        let p: Vec<&str> = parts.filter(|p| !p.is_empty()).collect();
        if !p.is_empty() {
            pids.insert(tid.clone(), p.join(","));
        }
        tids.push(tid);
    }
    (tids, pids)
}

/// firestack `parseAllIPOpts`: preset answers; only those matching an A/AAAA question's family (all of them for
/// HTTPS/SVCB, whose hints get substituted).
fn parse_all_ip_opts(qtype: u16, csv: &str) -> Vec<IpAddr> {
    let ips: Vec<IpAddr> = csv
        .split(',')
        .map(str::trim)
        .filter_map(|s| s.parse::<IpAddr>().ok())
        .collect();
    if ips.is_empty() {
        return ips;
    }
    match qtype {
        1 => ips
            .into_iter()
            .filter(|i| i.to_canonical().is_ipv4())
            .map(|i| i.to_canonical())
            .collect(),
        28 => ips
            .into_iter()
            .filter(|i| !i.to_canonical().is_ipv4())
            .collect(),
        64 | 65 => ips,
        _ => Vec::new(),
    }
}

fn strip_ct(id: &str) -> (bool, &str) {
    match id.strip_prefix(ids::CACHE_PREFIX) {
        Some(rest) if !rest.is_empty() => (true, rest),
        _ => (false, id),
    }
}

/// firestack `isTransportID`
fn is_id(want: &str, id: &str) -> bool {
    strip_ct(id).1 == want
}

const EXIT: &str = "Exit";
const BASE: &str = "Base";

/// firestack `overrideProxyIfNeeded`
fn override_proxy(pid: &str, ids_: &[&str]) -> String {
    for id in ids_ {
        match strip_ct(id).1 {
            ids::GOOS | LOCAL => return EXIT.into(),
            ids::SYSTEM | PRESET => return BASE.into(),
            ids::DEFAULT | ids::BOOTSTRAP => {
                return if settings::LOOPINGBACK.load(Ordering::Relaxed) {
                    pid.into()
                } else {
                    BASE.into()
                };
            }
            _ => {}
        }
    }
    pid.into()
}

/// Phase 1 dials only Base and Exit; other proxies (WireGuard, SOCKS5, …) arrive in Phase 2 and use Base.
fn dial_pid(pidcsv: &str) -> String {
    match pidcsv.split(',').next().map(str::trim) {
        Some(EXIT) => EXIT.into(),
        _ => BASE.into(),
    }
}

const LOCAL: &str = "mdns";
const PRESET: &str = "Preset";
pub const ORIGIN_INTERNAL: &str = "self";
/// firestack `fixedRealIPs`: answers for the Fixed transport (192.88.99.114, 2002:f13d:1:da19:192:88:99:114)
const FIXED_REAL_IPS: [IpAddr; 2] = [
    IpAddr::V4(std::net::Ipv4Addr::new(192, 88, 99, 114)),
    IpAddr::V6(std::net::Ipv6Addr::new(
        0x2002, 0xf13d, 0x1, 0xda19, 0x192, 0x88, 0x99, 0x114,
    )),
];

/// The transports chosen for a query (firestack `preferencesFrom`).
#[derive(Debug, Default, Clone)]
struct Prefs {
    id1: String,
    id2: String,
    pid: String,
    spid: String,
    ips: Vec<IpAddr>,
    noblock: bool,
}

/// A chosen transport, possibly through its cache.
#[derive(Clone)]
struct Tr {
    t: Arc<dyn Transport>,
    cached: bool,
}

impl Tr {
    /// firestack `idstr`: `Cache<id>` for cached transports
    fn id(&self) -> String {
        if self.cached {
            format!("{}{}", ids::CACHE_PREFIX, self.t.id())
        } else {
            self.t.id().to_string()
        }
    }
}

fn idstr(t: Option<&Tr>) -> String {
    t.map(Tr::id).unwrap_or_else(|| alg::NOTRANSPORT.into())
}

/// Cheap randomness: a randomly keyed hash.
fn rand_index(n: usize) -> usize {
    use std::hash::BuildHasher;
    (std::collections::hash_map::RandomState::new().hash_one(Instant::now()) % n as u64) as usize
}

/// On-device and remote blocklists, as of the start of a query.
#[derive(Clone)]
struct Blocks {
    l: Option<Arc<fs_blocklist::RdnsLocal>>,
    r: Option<Arc<Rdns>>,
}

impl Blocks {
    /// firestack `blockQ`: refused answer and blocklist names when on-device blocklists block the query; skipped
    /// for block-free transports.
    fn block_q(&self, tids: &[&str], qmsg: &Message) -> Option<(Vec<u8>, String)> {
        if tids.iter().any(|t| skip_block(t)) {
            return None;
        }
        let rl = self.l.as_ref()?;
        if !rl.rdns.on_device_block() {
            return None;
        }
        let names: Vec<String> = qmsg.queries.iter().map(|q| q.name().to_ascii()).collect();
        let lists = rl
            .block_query(&names, msg::qtype(qmsg))
            .ok()
            .filter(|l| !l.is_empty())?;
        let ans = msg::refused_response(qmsg).and_then(|m| msg::pack(&m))?;
        Some((ans, lists))
    }

    /// firestack `blockA`: (blocked answer, blocked target, blocklist names).
    fn block_a(
        &self,
        tids: &[&str],
        qmsg: &Message,
        ans: &Message,
        stamp: &str,
    ) -> (Option<Vec<u8>>, String, String) {
        let none = (None, String::new(), String::new());
        if !stamp.is_empty()
            && let Some(br) = &self.r
            && let Ok(names) = br.stamp_to_names(stamp)
        {
            return (None, String::new(), names); // the upstream blocked it
        }
        if tids.iter().any(|t| skip_block(t)) {
            return none;
        }
        let Some(rl) = &self.l else { return none };
        if !rl.rdns.on_device_block() {
            return none;
        }
        let qname = ans
            .queries
            .first()
            .map(|q| q.name().to_ascii())
            .unwrap_or_default();
        let targets: Vec<String> = ans
            .answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::CNAME(c) => Some(c.0.to_ascii()),
                RData::SVCB(s) if s.svc_priority == 0 => Some(s.target_name.to_ascii()),
                RData::HTTPS(h) if h.svc_priority == 0 => Some(h.target_name.to_ascii()),
                _ => None,
            })
            .collect();
        match rl.block_answer(&qname, ans.answers.len(), &targets) {
            Ok((target, names)) if !names.is_empty() => {
                match msg::refused_response(qmsg).and_then(|m| msg::pack(&m)) {
                    Some(b) => (Some(b), target, names),
                    None => (None, target, names),
                }
            }
            _ => none,
        }
    }
}

/// firestack `fromInternalCache`: an A/AAAA answer from the addresses the gateway registered for this tid (and
/// uid) while they are fresh.
fn from_internal_cache(
    gw: &Gateway,
    tid: &str,
    uid: &str,
    q: &Message,
    typ: IpType,
) -> Option<Message> {
    if alg::is_block_all(tid) || (typ == IpType::Real && msg::has_do_bit(q)) {
        return None;
    }
    let qt = msg::qtype(q);
    if qt != 1 && qt != 28 {
        return None;
    }
    let (ip4s, ip6s, until) = gw.resolv(&msg::qname(q), typ, tid, uid);
    let ips = if qt == 1 { ip4s } else { ip6s };
    if ips.is_empty() {
        return None;
    }
    let ttl = until
        .map(|u| u.as_secs() as u32)
        .unwrap_or(alg::TTL8S.as_secs() as u32);
    msg::aquada_for_query(q, ttl, &ips)
}

/// What a query needs to reach a transport (directly or via its cache) outside the resolver's borrow.
#[derive(Clone)]
struct Req {
    caches: Arc<Caches>,
}

impl Req {
    /// firestack `Req`: the answer of `tr` (via its cache when cached), filling `smm`.
    async fn send(
        &self,
        tr: &Tr,
        qmsg: &Message,
        q: &[u8],
        pid: &str,
        smm: &mut DnsSummary,
    ) -> Option<Vec<u8>> {
        smm.id = tr.id();
        if tr.cached {
            query_cached(&self.caches, &tr.t, qmsg, q, pid, smm).await
        } else {
            query_direct(&tr.t, q, pid, smm).await
        }
    }
}

/// firestack `querySecondary`: what the secondary transport (or, without one, the primary answer) says about the
/// query: blocks (0.0.0.0 / ::), blocklists, and its addresses.
#[allow(clippy::too_many_arguments)]
async fn query_secondary(
    req: Req,
    blocks: Blocks,
    gw: Arc<Gateway>,
    t2: Option<Tr>,
    uid: String,
    spid: String,
    qmsg: Message,
    q: Vec<u8>,
    primary: Option<Message>,
) -> SecAns {
    let mut res = SecAns::default();
    if !matches!(msg::qtype(&qmsg), 1 | 28 | 64 | 65) {
        res.msg = "req at least one answer".into();
        return res;
    }
    let t2id = idstr(t2.as_ref());
    let t2ids: Vec<&str> = t2.as_ref().map(|_| t2id.as_str()).into_iter().collect();
    if let Some((ans, lists)) = blocks.block_q(&t2ids, &qmsg) {
        if let Some(m) = msg::parse(&ans) {
            res.ips.extend(msg::a_answers(&m));
            res.ips.extend(msg::aaaa_answers(&m));
        }
        res.blocklists = lists;
        return res;
    }
    let r = match &t2 {
        None => {
            res.pri = true;
            primary
        }
        Some(tr) => match from_internal_cache(&gw, &t2id, &uid, &qmsg, IpType::Secondary) {
            Some(m) => Some(m),
            None => {
                let mut s = DnsSummary::default();
                let a = req.send(tr, &qmsg, &q, &spid, &mut s).await;
                res.blocklists = s.blocklists;
                a.and_then(|a| msg::parse(&a))
            }
        },
    };
    let Some(r) = r.filter(msg::has_answers) else {
        res.msg = "req at least one answer".into();
        return res;
    };
    let (blocked, target, names) = blocks.block_a(&t2ids, &qmsg, &r, &res.blocklists);
    if !names.is_empty() {
        res.blocklists = names;
        res.blocked_target = target;
    }
    let zero = [
        IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
    ];
    if blocked.is_some() {
        res.ips.extend(zero);
    } else if msg::aquada_unspecified(&r) {
        res.upstream_blocks = true;
        res.ips.extend(zero);
    } else {
        res.ips.extend(msg::answer_ips(&r));
        res.ips.extend(msg::ip_hints(&r, false));
        res.ips.extend(msg::ip_hints(&r, true));
    }
    res
}

/// The transport's answer, parsed.
async fn ask(
    req: &Req,
    t1: &Tr,
    qmsg: &Message,
    q: &[u8],
    pid: &str,
    smm: &mut DnsSummary,
) -> Option<Message> {
    req.send(t1, qmsg, q, pid, smm)
        .await
        .and_then(|a| msg::parse(&a))
}

/// firestack `withPresetSummary`
fn with_preset_summary(smm: &mut DnsSummary, req_sent: bool, fixed: bool) {
    let id = if fixed { ids::FIXED } else { PRESET };
    smm.id = id.into();
    smm.typ = id.into();
    if !req_sent {
        smm.latency = 0.0;
        smm.status = dns_status::COMPLETE;
        smm.server = "127.5.3.9".into();
    }
    smm.blocklists.clear();
    smm.blocked_target.clear();
    smm.pid.clear();
    smm.rpid.clear();
}

/// Gateway errors (firestack `errAlg*`): with translation requested the client gets no answer.
#[derive(Debug, PartialEq, Eq)]
enum GwErr {
    NoAnswer,
    Alg,
}

impl Resolver {
    fn tr(&self, id: &str) -> Option<Tr> {
        if id.is_empty() {
            return None;
        }
        let (cached, plain) = strip_ct(id);
        self.determine(plain).map(|t| Tr { t, cached })
    }

    /// firestack `chooseOne`: one of the listed tids. The port picks at random among those whose transport is
    /// healthy (else among the present ones); firestack also ranks remote/recovered/proxied transports first.
    fn choose_one(&self, xs: &[String]) -> String {
        match xs.len() {
            0 => return String::new(),
            1 => return xs[0].clone(),
            _ => {}
        }
        let present: Vec<(&String, i32)> = xs
            .iter()
            .filter_map(|id| self.get(strip_ct(id).1).map(|t| (id, t.status())))
            .collect();
        let healthy: Vec<&String> = present
            .iter()
            .filter(|(_, s)| matches!(*s, dns_status::START | dns_status::COMPLETE))
            .map(|(id, _)| *id)
            .collect();
        let pool: Vec<&String> = if healthy.is_empty() {
            present.iter().map(|(id, _)| *id).collect()
        } else {
            healthy
        };
        if pool.is_empty() {
            return String::new();
        }
        pool[rand_index(pool.len())].clone()
    }

    /// firestack `preferencesFrom` (tunnel queries: no pre-chosen tids; undelegated/mDNS overrides not ported).
    fn preferences(&self, qtype: u16, opts: &DnsOpts) -> Prefs {
        let (x, t1pids) = parse_all_tid_opts(&opts.tidcsv);
        let (xx, t2pids) = parse_all_tid_opts(&opts.tidseccsv);
        let mut p = Prefs {
            ips: parse_all_ip_opts(qtype, &opts.ipcsv),
            noblock: opts.noblock,
            ..Default::default()
        };
        if !x.is_empty() {
            p.id1 = self.choose_one(&x);
            p.id2 = self.choose_one(&xx);
        }
        let any = |v: &[String], want: &str| v.iter().any(|i| is_id(want, i));
        if any(&x, ids::FIXED) || any(&xx, ids::FIXED) {
            if !is_id(ids::FIXED, &p.id1) {
                p.id2 = std::mem::replace(&mut p.id1, ids::FIXED.into());
            }
            if is_id(ids::FIXED, &p.id1) {
                p.id1 = ids::FIXED.into(); // Fixed has no cache
            }
            if p.id2.is_empty() {
                p.id2 = ids::PREFERRED.into();
            }
        }
        if !p.ips.is_empty() {
            p.noblock = true; // presets are never blocked
            p.id2.clear();
        }
        if is_id(LOCAL, &p.id1) || is_id(LOCAL, &p.id2) {
            p.id1 = LOCAL.into();
            p.id2.clear();
        }
        let ipblock = p.ips.iter().any(|i| i.is_unspecified());
        let trblock = is_id(ids::BLOCK_ALL, &p.id1) || is_id(ids::BLOCK_ALL, &p.id2);
        let reqblock = any(&x, ids::BLOCK_ALL) || any(&xx, ids::BLOCK_ALL);
        if is_id(ids::BLOCK_FREE, &p.id1) || is_id(ids::BLOCK_FREE, &p.id2) {
            p.noblock = true;
        } else if ipblock || trblock || reqblock {
            p.id1 = ids::BLOCK_ALL.into();
            p.id2.clear();
        }
        let ids2 = [p.id1.as_str(), p.id2.as_str()];
        p.pid = match (t1pids.get(&p.id1), t1pids.get(&p.id2)) {
            (Some(pid), _) if !pid.is_empty() => override_proxy(pid, &ids2),
            (_, Some(pid)) if !pid.is_empty() && p.id1 != p.id2 => override_proxy(pid, &ids2),
            _ => BASE.into(),
        };
        p.spid = match t2pids.get(&p.id2) {
            Some(pid) if !pid.is_empty() => override_proxy(pid, &ids2),
            _ => BASE.into(),
        };
        p
    }

    fn blocks(&self) -> Blocks {
        Blocks {
            l: self.rdnsl.read().clone(),
            r: self.rdnsr.read().clone(),
        }
    }

    fn req(&self) -> Req {
        Req {
            caches: self.caches.clone(),
        }
    }

    /// Answers a query received on the fake DNS address (`origin` = "tunnel"), or an internal one ("self").
    /// `None` means: send nothing.
    pub async fn forward(&self, q: &[u8], origin: &str, fid: &str, uid: &str) -> Option<Vec<u8>> {
        // firestack Serve: a query from an app uid means per-app split tunnelling is in effect
        if origin == ORIGIN_TUNNEL && !matches!(uid, "" | "0" | "-1" | "1051") {
            self.gw.split_tunnel();
        }
        let start = Instant::now();
        let mut smm = DnsSummary {
            fid: fid.to_string(),
            origin: origin.to_string(),
            start: unix_millis(),
            uid: uid.to_string(),
            status: dns_status::START,
            msg: NO_ERROR.into(),
            ..Default::default()
        };
        let Some(qmsg) = msg::parse(q) else {
            smm.status = dns_status::BAD_QUERY;
            smm.msg = "dns: unparsable query".into();
            self.listener.on_response(smm);
            return None;
        };
        // firestack hands Kotlin the normalized name (no trailing dot, lowercase)
        let qname = msg::qname(&qmsg);
        let qtype = msg::qtype(&qmsg);
        smm.qname = qname.clone();
        smm.targets = qname.clone();
        smm.qtype = qtype as i64;
        smm.do_bit = msg::has_do_bit(&qmsg);

        let opts = tokio::time::timeout(
            ON_QUERY_TIMEOUT,
            self.listener.on_query(
                origin.to_string(),
                uid.to_string(),
                qname.clone(),
                qtype as i64,
            ),
        )
        .await
        .ok()
        .flatten();
        let Some(mut opts) = opts else {
            smm.status = dns_status::CLIENT_ERROR;
            smm.msg = "dns: no opts (onQuery)".into();
            smm.latency = start.elapsed().as_secs_f64();
            self.listener.on_response(smm);
            return None;
        };
        if uid == alg::UNKNOWN_UID && !opts.uid.is_empty() {
            smm.uid = opts.uid.clone(); // firestack: the preferences' uid stands in for an unknown one
        }

        let mut answer = None;
        let base = smm.clone();
        for run in 1..=2 {
            smm = base.clone();
            let (ans, ipcsv) = match self
                .forward_once(&qmsg, q, &opts, &mut smm, start, origin, uid)
                .await
            {
                Step::None => break,
                Step::Final(a) => {
                    // blocked by on-device blocklists: no onUpstreamAnswer (firestack)
                    answer = Some(a);
                    break;
                }
                Step::Answer(a, ipcsv) => (a, ipcsv),
            };
            if run == 1 {
                let next = tokio::time::timeout(
                    ON_UPSTREAM_ANSWER_TIMEOUT,
                    self.listener.on_upstream_answer(
                        origin.to_string(),
                        smm.clone(),
                        opts.clone(),
                        ipcsv,
                    ),
                )
                .await;
                match next {
                    Ok(Some(n)) if !n.tidcsv.is_empty() && n.tidcsv != opts.tidcsv => {
                        opts = n; // Kotlin redirected the query to another transport: run once more
                        continue;
                    }
                    Ok(_) => {}
                    Err(_) => {
                        smm.status = dns_status::CLIENT_ERROR;
                        smm.msg = "dns: onUpstreamAnswer timeout".into();
                        smm.id = "NoDNS".into();
                        self.listener.on_response(smm);
                        return None;
                    }
                }
            }
            answer = Some(ans);
            break;
        }
        self.listener.on_response(smm);
        answer
    }

    /// One run of firestack `forwardInner`: preferences, on-device blocklists on the query, the gateway (primary
    /// and secondary transports, presets, translation), then blocklists on the answer.
    #[allow(clippy::too_many_arguments)]
    async fn forward_once(
        &self,
        qmsg: &Message,
        q: &[u8],
        opts: &DnsOpts,
        smm: &mut DnsSummary,
        start: Instant,
        origin: &str,
        uid: &str,
    ) -> Step {
        let p = self.preferences(msg::qtype(qmsg), opts);
        let mut t1 = self.tr(&p.id1);
        let mut t2 = self.tr(&p.id2);
        if t1.is_none() {
            if t2.is_none() {
                smm.status = dns_status::TRANSPORT_ERROR;
                smm.msg = format!("{};{};no such transport", p.id1, p.id2);
                smm.latency = start.elapsed().as_secs_f64();
                return Step::None;
            }
            t1 = t2.take();
        }
        let t1r = t1.clone().unwrap();
        smm.typ = t1r.t.typ().to_string();
        smm.id = t1r.id();
        let (id1, id2) = (t1r.id(), idstr(t2.as_ref()));
        let tids: Vec<&str> = std::iter::once(id1.as_str())
            .chain(t2.as_ref().map(|_| id2.as_str()))
            .collect();

        let blocks = self.blocks();
        if let Some((ans, lists)) = blocks.block_q(&tids, qmsg) {
            if p.noblock {
                smm.blocklists = lists; // report only
            } else {
                smm.latency = start.elapsed().as_secs_f64();
                smm.status = dns_status::COMPLETE;
                smm.blocklists = lists;
                smm.blocked_target = msg::qname(qmsg);
                smm.rdata = msg::interesting_rdata(msg::parse(&ans).as_ref());
                smm.msg = NO_ERROR.into();
                return Step::Final(ans);
            }
        }

        let r = self
            .gw_q(
                t1,
                t2.clone(),
                p.ips.clone(),
                origin,
                &p.pid,
                &p.spid,
                uid,
                qmsg,
                q,
                smm,
            )
            .await;
        if smm.latency <= 0.0 {
            smm.latency = start.elapsed().as_secs_f64();
        }
        let (nonalg, algd) = match r {
            Ok(x) => x,
            Err(e) => {
                if e == GwErr::Alg {
                    smm.status = dns_status::NO_RESPONSE;
                } else if smm.status == dns_status::START {
                    smm.status = dns_status::INTERNAL_ERROR;
                }
                return Step::None;
            }
        };
        let ans1 = algd.as_ref().unwrap_or(&nonalg);
        smm.targets = {
            let mut seen: Vec<String> = Vec::new();
            for r in &ans1.answers {
                let n = r.name.to_ascii();
                if !n.is_empty() && !seen.contains(&n) {
                    seen.push(n);
                }
            }
            seen.join(",")
        };

        let (blocked, target, names) = blocks.block_a(&tids, qmsg, &nonalg, &smm.blocklists);
        if !names.is_empty() {
            smm.blocklists = names;
            smm.blocked_target = target;
        }
        if smm.msg.is_empty() {
            smm.msg = NO_ERROR.into();
        }
        if !p.noblock
            && let Some(b) = blocked
        {
            let bm = msg::parse(&b);
            smm.rttl = bm.as_ref().map(|m| msg::max_ttl(m) as i64).unwrap_or(0);
            smm.rcode = 0;
            smm.rdata = msg::interesting_rdata(bm.as_ref());
            smm.status = dns_status::COMPLETE;
            return Step::Final(b);
        }
        let realips = msg::answer_ips(&nonalg)
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",");
        match msg::pack(ans1) {
            Some(out) => Step::Answer(out, realips),
            None => Step::None,
        }
    }

    /// firestack `dnsgateway.q`: the primary answer (an internal-cache hit, a preset/Fixed synthesis or the
    /// transport's), the secondary view, and with translation the rewritten answer. Returns (untranslated,
    /// translated).
    #[allow(clippy::too_many_arguments)]
    async fn gw_q(
        &self,
        t1: Option<Tr>,
        t2: Option<Tr>,
        mut preset: Vec<IpAddr>,
        origin: &str,
        pid: &str,
        spid: &str,
        uid: &str,
        qmsg: &Message,
        q: &[u8],
        smm: &mut DnsSummary,
    ) -> Result<(Message, Option<Message>), GwErr> {
        let gw = &self.gw;
        let (mut t1, mut t2) = (t1, t2);
        let fromtun = origin == ORIGIN_TUNNEL;
        let uidself = uid == gw.my_uid;
        let usepreset = !preset.is_empty();
        let mut modify = !uidself && fromtun && gw.translating();
        let discarduid = !gw.splitting();
        let id1 = idstr(t1.as_ref());
        let id2 = idstr(t2.as_ref());
        let hasblock = alg::is_block_all(&id1) || alg::is_block_all(&id2);
        let hasfixed = is_id(ids::FIXED, &id1);
        let usefixed = !usepreset && modify && hasfixed;
        let mut dontalg = usepreset || hasblock;
        let synth = usepreset || usefixed;
        smm.do_bit = msg::has_do_bit(qmsg);
        let uid = if discarduid { alg::UNKNOWN_UID } else { uid };
        if hasfixed && !usefixed {
            t1 = t2.clone();
        } else if usefixed {
            dontalg = false;
            preset = FIXED_REAL_IPS.to_vec();
            modify = true;
            t1 = t2.clone();
        }
        let Some(t1) = t1 else {
            return Err(GwErr::NoAnswer);
        };
        if synth {
            t2 = None;
        }
        let req = self.req();
        let blocks = self.blocks();
        // the secondary runs alongside the primary; firestack does not wait for it when the answer is not alg'd
        let sec = t2.clone().map(|t2| {
            tokio::spawn(query_secondary(
                req.clone(),
                blocks.clone(),
                gw.clone(),
                Some(t2),
                uid.to_string(),
                spid.to_string(),
                qmsg.clone(),
                q.to_vec(),
                None,
            ))
        });

        let ansin = if synth {
            self.synthesize_or_query(&req, &preset, &t1, qmsg, q, pid, smm, usefixed)
                .await
        } else if let Some(m) = from_internal_cache(gw, &t1.id(), uid, qmsg, IpType::Real) {
            smm.id = t1.id();
            smm.server = t1.t.addr();
            smm.rdata = msg::interesting_rdata(Some(&m));
            smm.rcode = u16::from(m.metadata.response_code) as i64;
            smm.rttl = msg::max_ttl(&m) as i64;
            smm.status = dns_status::COMPLETE;
            smm.cached = true;
            Some(m)
        } else {
            req.send(&t1, qmsg, q, &dial_pid(pid), smm)
                .await
                .and_then(|a| msg::parse(&a))
        };
        let Some(ansin) = ansin else {
            return Err(GwErr::NoAnswer);
        };
        let rgood = ansin.metadata.response_code == ResponseCode::NoError;
        if !rgood {
            return Ok((ansin, None));
        }
        smm.ad = false; // firestack: AD only when the DNS64 answer is authenticated too (no DNS64 yet)
        let qname = msg::qname(&ansin);
        let hasq = matches!(msg::qtype(&ansin), 1 | 28 | 64 | 65);
        let hasans = msg::has_answers(&ansin);
        let ans0000 = msg::aquada_unspecified(&ansin);
        if ans0000 {
            smm.blocked_target = qname.clone();
            smm.upstream_blocks = true;
        }
        if !hasq || !hasans || ans0000 || dontalg {
            return Ok((ansin, None));
        }

        let a6 = msg::aaaa_answers(&ansin);
        let a4 = msg::a_answers(&ansin);
        let hints4 = msg::ip_hints(&ansin, false);
        let hints6 = msg::ip_hints(&ansin, true);
        let targets = msg::targets(&ansin);
        let mut secres = match sec {
            Some(h) => tokio::time::timeout(Duration::from_secs(15), h)
                .await
                .ok()
                .and_then(|r| r.ok())
                .unwrap_or_default(),
            None => {
                query_secondary(
                    req.clone(),
                    blocks.clone(),
                    gw.clone(),
                    None,
                    uid.to_string(),
                    spid.to_string(),
                    qmsg.clone(),
                    q.to_vec(),
                    Some(ansin.clone()),
                )
                .await
            }
        };
        smm.blocklists = secres.blocklists.clone();
        smm.blocked_target = secres.blocked_target.clone();
        smm.upstream_blocks = secres.upstream_blocks || smm.upstream_blocks;
        let ansttl = Duration::from_secs(msg::max_ttl(&ansin) as u64);
        let tid = smm.id.clone();

        let res = gw.with_state(|t| {
            let mut realip: Vec<IpAddr> = Vec::new();
            let (mut a6s, mut a4s, mut h4, mut h6) = (None, None, None, None);
            if !a6.is_empty() {
                realip.extend(&a6);
                a6s = Some(t.take6(&qname).ok_or(GwErr::Alg)?);
            }
            if !a4.is_empty() {
                realip.extend(&a4);
                a4s = Some(t.take4(&qname).ok_or(GwErr::Alg)?);
            }
            if !hints4.is_empty() {
                realip.extend(&hints4);
                h4 = Some(match a4s {
                    Some(x) => x,
                    None => t.take4(&qname).ok_or(GwErr::Alg)?,
                });
            }
            if !hints6.is_empty() {
                realip.extend(&hints6);
                h6 = Some(match a6s {
                    Some(x) => x,
                    None => t.take6(&qname).ok_or(GwErr::Alg)?,
                });
            }
            let mut ansmod = msg::copy_ans(&ansin);
            let (mut ok4, mut ok6, mut must) = (false, false, usefixed);
            if let Some(ip) = h4 {
                ok4 |= msg::subst_svcb_hints(&mut ansmod, false, ip, msg::ANS_TTL);
                must = true;
            }
            if let Some(ip) = h6 {
                ok6 |= msg::subst_svcb_hints(&mut ansmod, true, ip, msg::ANS_TTL);
                must = true;
            }
            if let Some(ip) = a4s {
                ok4 |= msg::subst_addr_records(&mut ansmod, ip, msg::ANS_TTL);
                must = true;
            }
            if let Some(ip) = a6s {
                ok6 |= msg::subst_addr_records(&mut ansmod, ip, msg::ANS_TTL);
                must = true;
            }
            if !ok4 && !ok6 {
                return if must { Err(GwErr::Alg) } else { Ok(None) };
            }
            if usefixed {
                realip.clear(); // the "real" addresses are the fixed ones
                secres.ips.clear();
            }
            let algip4 = a4s.or(h4);
            let algip6 = a6s.or(h6);
            // always registered (a hot cache for when translation is switched on, and the IP -> name map)
            let ok = t.register(
                &qname, &tid, uid, algip4, algip6, &realip, ansttl, &targets, &secres,
            );
            Ok(Some((ansmod, ok)))
        });
        match res {
            Ok(Some((mut ansmod, ok))) if modify => {
                msg::bust_android_cache(&mut ansmod);
                if ok {
                    Ok((ansin, Some(ansmod)))
                } else {
                    Err(GwErr::Alg)
                }
            }
            Ok(_) => Ok((ansin, None)),
            // alg errors only matter when translation was asked for
            Err(e) if modify => Err(e),
            Err(_) => Ok((ansin, None)),
        }
    }

    /// firestack `synthesizeOrQuery`: A/AAAA answers from preset (or Fixed) addresses, HTTPS/SVCB answers with
    /// their hints replaced; otherwise the transport's answer.
    #[allow(clippy::too_many_arguments)]
    async fn synthesize_or_query(
        &self,
        req: &Req,
        preset: &[IpAddr],
        t1: &Tr,
        qmsg: &Message,
        q: &[u8],
        pid: &str,
        smm: &mut DnsSummary,
        fixed: bool,
    ) -> Option<Message> {
        let qt = msg::qtype(qmsg);
        let pid = dial_pid(pid);
        if preset.is_empty() {
            return ask(req, t1, qmsg, q, &pid, smm).await;
        }
        match qt {
            1 | 28 => match msg::aquada_for_query(qmsg, msg::ANS_TTL, preset) {
                None => ask(req, t1, qmsg, q, &pid, smm).await,
                Some(ans) => {
                    with_preset_summary(smm, false, fixed);
                    smm.id = PRESET.into();
                    smm.rcode = 0;
                    smm.rdata = msg::interesting_rdata(Some(&ans));
                    smm.rttl = msg::max_ttl(&ans) as i64;
                    Some(ans)
                }
            },
            64 | 65 => {
                let mut ans = ask(req, t1, qmsg, q, &pid, smm).await?;
                let v4 = preset
                    .iter()
                    .find(|i| i.to_canonical().is_ipv4())
                    .map(|i| i.to_canonical());
                let v6 = preset.iter().find(|i| !i.to_canonical().is_ipv4()).copied();
                if let Some(ip) = v4 {
                    msg::subst_svcb_hints(&mut ans, false, ip, msg::ANS_TTL);
                }
                if let Some(ip) = v6 {
                    msg::subst_svcb_hints(&mut ans, true, ip, msg::ANS_TTL);
                }
                with_preset_summary(smm, true, fixed);
                smm.rcode = u16::from(ans.metadata.response_code) as i64;
                smm.rdata = msg::interesting_rdata(Some(&ans));
                smm.rttl = msg::max_ttl(&ans) as i64;
                Some(ans)
            }
            _ => ask(req, t1, qmsg, q, &pid, smm).await,
        }
    }

    /// firestack `Translate(tr, fix)`
    pub fn translate(&self, tr: bool, fix: bool) {
        self.gw.translate(tr, fix);
    }

    pub fn gateway(&self) -> &Arc<Gateway> {
        &self.gw
    }

    /// firestack `ResolveFor` (via ipmapper `LookupFor`): resolves `domain` for `uid` as an internal query
    /// (Kotlin's onQuery decides; never translated) and returns its addresses, A then AAAA.
    pub async fn resolve_for(&self, domain: &str, uid: &str) -> Vec<IpAddr> {
        let name = if domain.ends_with('.') {
            domain.to_string()
        } else {
            format!("{domain}.")
        };
        let mut out = Vec::new();
        for (i, qt) in [RecordType::A, RecordType::AAAA].into_iter().enumerate() {
            let Some(q) = msg::query(&name, qt, 0x6e00 + i as u16).and_then(|m| msg::pack(&m))
            else {
                continue;
            };
            let fid = format!("r{:x}", rand_index(usize::MAX));
            if let Some(a) = self.forward(&q, ORIGIN_INTERNAL, &fid, uid).await
                && let Some(m) = msg::parse(&a)
            {
                for ip in msg::answer_ips(&m) {
                    // undo translations (none for internal queries) and skip blocks
                    let (real, _) = self.gw.x(ip, uid, &[]);
                    out.extend(real.into_iter().filter(|r| !r.is_unspecified()));
                }
            }
        }
        out
    }

    /// firestack `SetRdnsLocal`: empty paths unset; on error the local blocklist is unset too.
    pub fn set_rdns_local(
        &self,
        td: &str,
        rd: &str,
        conf: &str,
        filetag: &str,
    ) -> Result<(), String> {
        if td.is_empty() || rd.is_empty() {
            *self.rdnsl.write() = None;
            return Ok(());
        }
        match fs_blocklist::RdnsLocal::new(td, rd, conf, filetag) {
            Ok(r) => {
                *self.rdnsl.write() = Some(Arc::new(r));
                Ok(())
            }
            Err(e) => {
                *self.rdnsl.write() = None;
                Err(e)
            }
        }
    }

    /// firestack `SetRdnsRemote`: empty path unsets.
    pub fn set_rdns_remote(&self, filetag: &str) -> Result<(), String> {
        if filetag.is_empty() {
            *self.rdnsr.write() = None;
            return Ok(());
        }
        match Rdns::from_filetag(std::path::Path::new(filetag), Mode::Remote) {
            Ok(r) => {
                *self.rdnsr.write() = Some(Arc::new(r));
                Ok(())
            }
            Err(e) => {
                *self.rdnsr.write() = None;
                Err(e)
            }
        }
    }

    /// The local blocklists' stamp object (shared: `setStamp` applies to lookups).
    pub fn rdns_local(&self) -> Option<Arc<Rdns>> {
        self.rdnsl.read().as_ref().map(|r| r.rdns.clone())
    }

    pub fn rdns_remote(&self) -> Option<Arc<Rdns>> {
        self.rdnsr.read().clone()
    }

    /// Internal lookup (no Kotlin callbacks, no cache): resolves `host` via the Default transport, A and AAAA.
    /// Used to find the IPs of DoH servers configured by hostname.
    pub async fn lookup_ip(&self, host: &str) -> Vec<IpAddr> {
        let Some(t) = self.get(ids::DEFAULT) else {
            return Vec::new();
        };
        let name = if host.ends_with('.') {
            host.to_string()
        } else {
            format!("{host}.")
        };
        let pid = if settings::LOOPINGBACK.load(Ordering::Relaxed) {
            "Exit"
        } else {
            "Base"
        };
        let mut out = Vec::new();
        for (i, qt) in [RecordType::A, RecordType::AAAA].into_iter().enumerate() {
            let Some(q) = msg::query(&name, qt, 0x5e00 + i as u16).and_then(|m| msg::pack(&m))
            else {
                continue;
            };
            if let Ok(a) = t.clone().query(q, pid.into()).await
                && let Some(m) = msg::parse(&a.msg)
            {
                out.extend(msg::answer_ips(&m));
            }
        }
        out
    }
}

/// firestack `skipBlock`: block-free and ALG transports never apply on-device blocklists; Default and Bootstrap
/// skip them when looping back (`canBlockDefault`).
fn skip_block(tid: &str) -> bool {
    let id = tid
        .strip_prefix(ids::CACHE_PREFIX)
        .filter(|s| !s.is_empty())
        .unwrap_or(tid);
    match id {
        ids::BLOCK_FREE | ids::ALG => true,
        ids::DEFAULT | ids::BOOTSTRAP => settings::LOOPINGBACK.load(Ordering::Relaxed),
        _ => false,
    }
}

/// Summary fields of an upstream answer (firestack transports fill these in `DNSSummary`).
fn summ_of(a: &fs_dns::transport::Answer, m: Option<&Message>) -> Summ {
    Summ {
        server: a.server.clone(),
        pid: a.pid.clone(),
        rdata: msg::interesting_rdata(m),
        ad: m.is_some_and(|m| m.metadata.authentic_data),
        rcode: m
            .map(|m| u16::from(m.metadata.response_code) as i64)
            .unwrap_or(0),
        rttl: m.map(|m| msg::max_ttl(m) as i64).unwrap_or(0),
        status: dns_status::COMPLETE,
        msg: String::new(),
        blocklists: a.blocklists.clone(),
        region: a.region.clone(),
        latency: a.latency.as_secs_f64(),
    }
}

/// firestack `fillSummary`: cached / upstream summary fields into the query's summary.
fn fill_summary(out: &mut DnsSummary, s: &Summ) {
    if out.server.is_empty() {
        out.server = s.server.clone();
    }
    if out.latency <= 0.0 {
        out.latency = s.latency;
    }
    if out.region.is_empty() {
        out.region = s.region.clone();
    }
    if !s.rdata.is_empty() {
        out.rdata = s.rdata.clone();
        out.ad = s.ad;
    }
    if !s.pid.is_empty() {
        out.pid = s.pid.clone();
    }
    out.rcode = s.rcode;
    out.rttl = s.rttl;
    out.status = s.status;
    out.blocklists = s.blocklists.clone();
    out.blocked_target = String::new();
    out.msg = s.msg.clone();
}

/// firestack `ctransport.fetch`: fresh cache hits are served as-is, stale ones with 15 s TTLs plus a background
/// refresh; misses go upstream through the barrier. Every answer is reported as cached (firestack).
async fn query_cached(
    caches: &Arc<Caches>,
    t: &Arc<dyn Transport>,
    qmsg: &Message,
    q: &[u8],
    pid: &str,
    smm: &mut DnsSummary,
) -> Option<Vec<u8>> {
    let (qname, qtype) = msg::question(qmsg).unwrap_or_default();
    let Some(key) = cache::key(&qname, qtype, smm.do_bit) else {
        return query_direct(t, q, pid, smm).await;
    };
    let tc = caches.get(t.id());
    if tc.transport_ok()
        && let Some(hit) = tc.fresh_copy(&key)
    {
        match as_response(qmsg, &hit.msg, hit.fresh) {
            Ok(r) => {
                if !hit.fresh {
                    let (tc, t, key, q, pid) = (
                        tc.clone(),
                        t.clone(),
                        key.clone(),
                        q.to_vec(),
                        pid.to_string(),
                    );
                    tokio::spawn(async move {
                        let _ = send_request(&tc, &t, &key, q, &pid).await;
                    });
                }
                fill_summary(smm, &hit.s);
                smm.latency = 0.0; // not the cached latency
                smm.cached = true;
                return Some(r);
            }
            Err(AsErr::Mismatch) => tc.remove(&key),
            Err(AsErr::StaleDnssec) => {}
        }
    }
    let (resp, s, hangover) = send_request(&tc, t, &key, q.to_vec(), pid).await;
    let resp = resp.and_then(|(m, fresh)| as_response(qmsg, &m, fresh).ok());
    fill_summary(smm, &s);
    if hangover {
        smm.msg = format!("{}; dns: no connectivity", s.msg);
        smm.rcode = RCODE_BADTIME;
        smm.status = dns_status::SEND_FAILED;
        smm.cached = true;
        return None;
    }
    smm.cached = true;
    resp
}

/// A query to a transport without its cache.
async fn query_direct(
    t: &Arc<dyn Transport>,
    q: &[u8],
    pid: &str,
    smm: &mut DnsSummary,
) -> Option<Vec<u8>> {
    match t.clone().query(q.to_vec(), pid.to_string()).await {
        Ok(a) => {
            let m = msg::parse(&a.msg);
            fill_summary(smm, &summ_of(&a, m.as_ref()));
            smm.latency = a.latency.as_secs_f64();
            Some(a.msg)
        }
        Err(e) => {
            smm.status = e.status;
            smm.msg = e.msg;
            smm.server = e.server;
            smm.pid = pid.to_string();
            None
        }
    }
}

/// firestack `sendRequest`: the upstream exchange through the barrier (stores cacheable answers), then the
/// cached copy is preferred. Returns (answer and whether it is fresh, its summary, in hangover).
async fn send_request(
    tc: &Arc<TCache>,
    t: &Arc<dyn Transport>,
    key: &str,
    q: Vec<u8>,
    pid: &str,
) -> (Option<(Arc<Vec<u8>>, bool)>, Summ, bool) {
    let (out, _) = tc
        .barrier(key, || {
            let (tc, t, key, pid) = (tc.clone(), t.clone(), key.to_string(), pid.to_string());
            async move {
                let r = t.clone().query(q, pid.clone()).await;
                tc.checkpoint(t.status() == dns_status::SEND_FAILED);
                match r {
                    Ok(a) => {
                        let m = msg::parse(&a.msg);
                        let s = summ_of(&a, m.as_ref());
                        let msg = Arc::new(a.msg);
                        if let Some(m) = &m {
                            let ok = m.metadata.response_code == ResponseCode::NoError;
                            if cache::cacheable(
                                &key,
                                ok,
                                m.metadata.truncation,
                                &msg::answer_ips(m),
                            ) {
                                tc.put(&key, msg.clone(), s.clone(), msg::max_ttl(m));
                            }
                        }
                        Ok((msg, s))
                    }
                    Err(e) => {
                        let s = Summ {
                            server: e.server.clone(),
                            pid,
                            status: e.status,
                            msg: e.msg.clone(),
                            ..Default::default()
                        };
                        Err((e, s))
                    }
                }
            }
        })
        .await;
    let hit = tc.fresh_copy(key);
    let hangover = !tc.transport_ok();
    match (hit, out) {
        (Some(h), _) => (Some((h.msg, h.fresh)), h.s, hangover),
        // uncacheable answers are not fresh either (firestack): TTLs drop to 15 s
        (None, Ok((m, s))) => (Some((m, false)), s, hangover),
        (None, Err((_, s))) => (None, s, hangover),
    }
}

enum AsErr {
    /// stale answers would alter the TTLs of a DNSSEC-authenticated answer
    StaleDnssec,
    /// cached answer does not match the query
    Mismatch,
}

/// firestack `asResponse`: the cached answer with the query's id and question (dns 0x20); stale answers get
/// TTL 15 s on their answer records.
fn as_response(q: &Message, cached: &[u8], fresh: bool) -> Result<Vec<u8>, AsErr> {
    let mut a = msg::parse(cached).ok_or(AsErr::Mismatch)?;
    if !fresh && a.metadata.authentic_data {
        return Err(AsErr::StaleDnssec);
    }
    let name = |m: &Message| {
        m.queries
            .first()
            .map(|x| fs_blocklist::normalize_qname(&x.name().to_ascii()))
    };
    if name(&a) != name(q) {
        return Err(AsErr::Mismatch);
    }
    a.metadata.id = q.metadata.id;
    a.queries = q.queries.clone();
    a.metadata.message_type = MessageType::Response;
    if !fresh {
        for r in a.answers.iter_mut() {
            r.ttl = cache::STALE_TTL;
        }
    }
    msg::pack(&a).ok_or(AsErr::Mismatch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fs_core::bridge::{BoxFuture, dns_status};
    use fs_dns::transport::{Answer, QueryError};
    use parking_lot::Mutex;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn tidcsv() {
        assert_eq!(
            parse_tidcsv("CachePreferred:Base")[0],
            Pref {
                cache: true,
                tid: "Preferred".into(),
                pids: vec!["Base".into()]
            }
        );
        assert_eq!(
            parse_tidcsv("BlockAll")[0],
            Pref {
                cache: false,
                tid: "BlockAll".into(),
                pids: vec![]
            }
        );
        assert_eq!(parse_tidcsv("Preferred:wg1:Exit,System")[1].tid, "System");
        assert!(parse_tidcsv("").is_empty());
    }

    #[derive(Default)]
    struct Fake {
        id: String,
        n: AtomicUsize,
        fail: bool,
        /// answer with a CNAME to this name first
        cname: Option<String>,
        /// x-nile-flags of the answer
        stamp: String,
        /// answer address (default 93.184.215.14)
        ip: Option<&'static str>,
    }
    impl Transport for Fake {
        fn id(&self) -> &str {
            &self.id
        }
        fn typ(&self) -> &str {
            "DNS-over-HTTPS"
        }
        fn addr(&self) -> String {
            "fake".into()
        }
        fn status(&self) -> i32 {
            dns_status::COMPLETE
        }
        fn p50(&self) -> i64 {
            1
        }
        fn query(
            self: Arc<Self>,
            q: Vec<u8>,
            pid: String,
        ) -> BoxFuture<Result<Answer, QueryError>> {
            self.n.fetch_add(1, Ordering::SeqCst);
            let fail = self.fail;
            let (cname, stamp) = (self.cname.clone(), self.stamp.clone());
            let ip = self.ip.unwrap_or("93.184.215.14");
            Box::pin(async move {
                if fail {
                    return Err(QueryError::new(dns_status::SEND_FAILED, "boom"));
                }
                let m = msg::parse(&q).unwrap();
                let mut r = msg::empty_response(&m);
                let mut name = m.queries[0].name().clone();
                if let Some(c) = cname {
                    let target = hickory_proto::rr::Name::from_ascii(&c).unwrap();
                    r.add_answer(hickory_proto::rr::Record::from_rdata(
                        name,
                        60,
                        RData::CNAME(hickory_proto::rr::rdata::CNAME(target.clone())),
                    ));
                    name = target;
                }
                r.add_answer(hickory_proto::rr::Record::from_rdata(
                    name,
                    60,
                    hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A(ip.parse().unwrap())),
                ));
                Ok(Answer {
                    msg: msg::pack(&r).unwrap(),
                    server: "fake".into(),
                    pid,
                    latency: Duration::from_millis(3),
                    blocklists: stamp,
                    ..Default::default()
                })
            })
        }
    }

    #[derive(Default)]
    struct Policy {
        tid: Mutex<String>,
        sec: Mutex<String>,
        ipcsv: Mutex<String>,
        redirect: Mutex<Option<String>>,
        responses: Mutex<Vec<DnsSummary>>,
        /// ipcsv seen by onUpstreamAnswer
        upstream_ips: Mutex<Vec<String>>,
    }
    impl DnsListener for Policy {
        fn on_query(
            &self,
            _: String,
            uid: String,
            _: String,
            _: i64,
        ) -> BoxFuture<Option<DnsOpts>> {
            let tid = self.tid.lock().clone();
            let (sec, ipcsv) = (self.sec.lock().clone(), self.ipcsv.lock().clone());
            Box::pin(async move {
                Some(DnsOpts {
                    uid,
                    tidcsv: tid,
                    tidseccsv: sec,
                    ipcsv,
                    ..Default::default()
                })
            })
        }
        fn on_upstream_answer(
            &self,
            _: String,
            _: DnsSummary,
            pref: DnsOpts,
            ipcsv: String,
        ) -> BoxFuture<Option<DnsOpts>> {
            self.upstream_ips.lock().push(ipcsv);
            let r = self.redirect.lock().take();
            Box::pin(async move {
                Some(DnsOpts {
                    tidcsv: r.unwrap_or(pref.tidcsv.clone()),
                    ..pref
                })
            })
        }
        fn on_response(&self, s: DnsSummary) {
            self.responses.lock().push(s);
        }
        fn on_dns_added(&self, _: String) {}
        fn on_dns_removed(&self, _: String) {}
        fn on_dns_stopped(&self) {}
    }

    fn q(name: &str, id: u16) -> Vec<u8> {
        msg::pack(&msg::query(name, RecordType::A, id).unwrap()).unwrap()
    }

    #[tokio::test]
    async fn forward_cache_redirect_and_failure() {
        let pol = Arc::new(Policy::default());
        *pol.tid.lock() = "CachePreferred:Base".into();
        let r = Resolver::new("10.111.222.3:53,[fd66:f83a:c650::3]:53", pol.clone());
        let pref = Arc::new(Fake {
            id: "Preferred".into(),
            ..Default::default()
        });
        r.add(pref.clone());
        r.add(Arc::new(fs_dns::dns53::BlockAll::default()));

        let a = r
            .forward(&q("example.com.", 7), ORIGIN_TUNNEL, "f1", "10123")
            .await
            .unwrap();
        assert_eq!(u16::from_be_bytes([a[0], a[1]]), 7);
        let b = r
            .forward(&q("Example.com.", 9), ORIGIN_TUNNEL, "f2", "10123")
            .await
            .unwrap();
        assert_eq!(
            u16::from_be_bytes([b[0], b[1]]),
            9,
            "cached answer gets the new query id"
        );
        assert_eq!(
            pref.n.load(Ordering::SeqCst),
            1,
            "second query served from cache"
        );
        {
            let res = pol.responses.lock();
            assert_eq!(
                (res[0].id.as_str(), res[0].status, res[0].rdata.as_str()),
                ("CachePreferred", 1, "93.184.215.14")
            );
            assert_eq!(
                (res[0].qname.as_str(), res[0].qtype, res[0].uid.as_str()),
                ("example.com", 1, "10123")
            );
            // firestack: everything through a cache is reported cached; hits take the time since the query
            assert!(res[0].cached && res[1].cached && res[1].latency > 0.0);
        }

        // Kotlin redirects the answer to BlockAll (e.g. a blocked ip): second run answers 0.0.0.0
        *pol.redirect.lock() = Some("BlockAll".into());
        let c = r
            .forward(&q("ads.example.", 11), ORIGIN_TUNNEL, "f3", "10123")
            .await
            .unwrap();
        let cm = msg::parse(&c).unwrap();
        assert_eq!(msg::interesting_rdata(Some(&cm)), "0.0.0.0");
        // firestack: a 0.0.0.0 answer is an upstream block of the (normalized) qname
        assert_eq!(
            pol.responses.lock().last().unwrap().blocked_target,
            "ads.example"
        );
        // queries from app uid 10123 turned on per-app keys: names are looked up for that uid
        let ptr = |ip: &str| r.gateway().ptr(ip.parse().unwrap(), "10123", "", false).0;
        // ads.example also resolved to this address on its first run (before the redirect), as in firestack
        assert_eq!(
            ptr("93.184.215.14"),
            "example.com,ads.example",
            "IP -> names through the gateway"
        );
        assert_eq!(ptr("0.0.0.0"), "", "blocked answers are not registered");

        // upstream failure: no reply, status reported
        r.add(Arc::new(Fake {
            id: "Preferred".into(),
            fail: true,
            ..Default::default()
        }));
        assert!(
            r.forward(&q("nocache.example.", 12), ORIGIN_TUNNEL, "f4", "1")
                .await
                .is_none()
        );
        assert_eq!(
            pol.responses.lock().last().unwrap().status,
            dns_status::SEND_FAILED
        );

        // unknown transport
        *pol.tid.lock() = "Nope".into();
        assert!(
            r.forward(&q("x.example.", 13), ORIGIN_TUNNEL, "f5", "1")
                .await
                .is_none()
        );
        assert_eq!(
            pol.responses.lock().last().unwrap().status,
            dns_status::TRANSPORT_ERROR
        );
    }

    #[tokio::test]
    async fn caches_are_per_transport_and_redirects_see_cached_answers() {
        let pol = Arc::new(Policy::default());
        let r = Resolver::new("10.111.222.3:53", pol.clone());
        let (a, b) = (
            Arc::new(Fake {
                id: "Preferred".into(),
                ..Default::default()
            }),
            Arc::new(Fake {
                id: "System".into(),
                ..Default::default()
            }),
        );
        r.add(a.clone());
        r.add(b.clone());
        *pol.tid.lock() = "CachePreferred".into();
        r.forward(&q("x.example.", 1), ORIGIN_TUNNEL, "f1", "1")
            .await
            .unwrap();
        *pol.tid.lock() = "CacheSystem".into();
        r.forward(&q("x.example.", 2), ORIGIN_TUNNEL, "f2", "1")
            .await
            .unwrap();
        assert_eq!(
            (a.n.load(Ordering::SeqCst), b.n.load(Ordering::SeqCst)),
            (1, 1)
        );
        // a cached answer still goes through onUpstreamAnswer, so Kotlin's IP rules apply to it
        *pol.redirect.lock() = Some("BlockAll".into());
        r.add(Arc::new(fs_dns::dns53::BlockAll::default()));
        let c = r
            .forward(&q("x.example.", 3), ORIGIN_TUNNEL, "f3", "1")
            .await
            .unwrap();
        assert_eq!(msg::interesting_rdata(msg::parse(&c).as_ref()), "0.0.0.0");
        assert_eq!(
            b.n.load(Ordering::SeqCst),
            1,
            "served from System's cache before the redirect"
        );
    }

    fn oracle_dir() -> std::path::PathBuf {
        let engine = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let pin = std::fs::read_to_string(engine.join("api/PIN")).unwrap();
        engine.join("testdata/oracle").join(pin.trim())
    }

    #[tokio::test]
    async fn remote_blockstamp_names() {
        let pol = Arc::new(Policy::default());
        *pol.tid.lock() = "Preferred".into();
        let r = Resolver::new("10.111.222.3:53", pol.clone());
        let ft = oracle_dir().join("rdns-filetag.json");
        r.set_rdns_remote(ft.to_str().unwrap()).unwrap();
        let rem = r.rdns_remote().unwrap();
        let stamp = rem
            .flags_to_stamp("1,17", fs_blocklist::stamp::EB64)
            .unwrap();
        // RethinkDNS sends x-nile-flags with the blocks it answers (0.0.0.0)
        r.add(Arc::new(Fake {
            id: "Preferred".into(),
            stamp: stamp.clone(),
            ip: Some("0.0.0.0"),
            ..Default::default()
        }));
        r.forward(&q("ads.example.", 1), ORIGIN_TUNNEL, "f1", "1")
            .await
            .unwrap();
        let s = pol.responses.lock().last().unwrap().clone();
        assert_eq!(s.blocklists, rem.stamp_to_names(&stamp).unwrap(), "{s:?}");
        assert!(s.blocklists.contains(':') && s.blocklists.contains(','));
        assert!(rem.set_stamp("x").is_err(), "remote mode has no stamp");
        r.set_rdns_remote("").unwrap();
        assert!(r.rdns_remote().is_none());
    }

    /// Needs the on-device trie (RR_BLOCKLIST_DIR, see fs-blocklist/tests/oracle.rs).
    #[tokio::test]
    async fn local_blocklists_block_queries_and_cloaked_answers() {
        let Some(dir) = std::env::var_os("RR_BLOCKLIST_DIR").map(std::path::PathBuf::from) else {
            eprintln!("skipped: RR_BLOCKLIST_DIR not set");
            return;
        };
        let j = |n: &str| dir.join(n).to_string_lossy().into_owned();
        let pol = Arc::new(Policy::default());
        *pol.tid.lock() = "CachePreferred".into();
        let r = Resolver::new("10.111.222.3:53", pol.clone());
        r.set_rdns_local(
            &j("td.txt"),
            &j("rd.txt"),
            &j("basicconfig.json"),
            &j("filetag.json"),
        )
        .unwrap();
        let rl = r.rdns_local().unwrap();
        let all: Vec<String> = (0..250).map(|i| i.to_string()).collect();
        let stamp = rl
            .flags_to_stamp(&all.join(","), fs_blocklist::stamp::EB32)
            .unwrap();
        rl.set_stamp(&stamp).unwrap();
        let up = Arc::new(Fake {
            id: "Preferred".into(),
            ..Default::default()
        });
        r.add(up.clone());

        let a = r
            .forward(&q("doubleclick.net.", 1), ORIGIN_TUNNEL, "f1", "1")
            .await
            .unwrap();
        assert_eq!(msg::interesting_rdata(msg::parse(&a).as_ref()), "0.0.0.0");
        let s = pol.responses.lock().last().unwrap().clone();
        assert_eq!(s.blocked_target, "doubleclick.net");
        assert!(!s.blocklists.is_empty());
        assert_eq!(
            up.n.load(Ordering::SeqCst),
            0,
            "blocked before going upstream"
        );

        // CNAME cloaking: the answer points at a blocked name
        r.add(Arc::new(Fake {
            id: "Preferred".into(),
            cname: Some("ad.doubleclick.net.".into()),
            ..Default::default()
        }));
        let a = r
            .forward(&q("en.wikipedia.org.", 2), ORIGIN_TUNNEL, "f2", "1")
            .await
            .unwrap();
        assert_eq!(msg::interesting_rdata(msg::parse(&a).as_ref()), "0.0.0.0");
        let s = pol.responses.lock().last().unwrap().clone();
        assert_eq!(s.blocked_target, "ad.doubleclick.net", "{s:?}");

        // BlockFree skips local blocklists
        r.add(Arc::new(Fake {
            id: "BlockFree".into(),
            ..Default::default()
        }));
        *pol.tid.lock() = "BlockFree".into();
        let a = r
            .forward(&q("doubleclick.net.", 3), ORIGIN_TUNNEL, "f3", "1")
            .await
            .unwrap();
        assert_eq!(
            msg::interesting_rdata(msg::parse(&a).as_ref()),
            "93.184.215.14"
        );
    }

    #[tokio::test]
    async fn alg_translates_presets_and_secondary_blocks() {
        let pol = Arc::new(Policy::default());
        *pol.tid.lock() = "Preferred".into();
        let r = Resolver::new("10.111.222.3:53", pol.clone());
        r.add(Arc::new(Fake {
            id: "Preferred".into(),
            ..Default::default()
        }));
        r.translate(true, false);
        let answer_ip = |a: &[u8]| msg::answer_ips(&msg::parse(a).unwrap())[0];

        // translated: the app sees a stable 100.64/10 address; Kotlin and the flow layer see the real one
        let a = r
            .forward(&q("example.com.", 1), ORIGIN_TUNNEL, "f1", "-1")
            .await
            .unwrap();
        let algip = answer_ip(&a);
        assert!(
            matches!(algip, IpAddr::V4(v) if v.octets()[0] == 100),
            "{algip}"
        );
        assert_eq!(
            msg::max_ttl(&msg::parse(&a).unwrap()),
            0,
            "ALG answers are not cached by Android"
        );
        assert_eq!(pol.upstream_ips.lock().last().unwrap(), "93.184.215.14");
        assert_eq!(
            r.gateway().x(algip, "-1", &[]),
            (vec!["93.184.215.14".parse().unwrap()], true)
        );
        assert_eq!(r.gateway().ptr(algip, "-1", "", false).0, "example.com");
        let again = r
            .forward(&q("example.com.", 2), ORIGIN_TUNNEL, "f2", "-1")
            .await
            .unwrap();
        assert_eq!(answer_ip(&again), algip, "same domain, same address");
        assert!(
            pol.responses.lock().last().unwrap().cached,
            "second answer from the gateway's internal cache"
        );

        // internal queries are never translated
        let i = r
            .forward(&q("example.com.", 3), ORIGIN_INTERNAL, "f3", "-1")
            .await
            .unwrap();
        assert_eq!(answer_ip(&i).to_string(), "93.184.215.14");

        // presets (IPCSV) are synthesized and not translated
        *pol.ipcsv.lock() = "203.0.113.7,2001:db8::7".into();
        let p = r
            .forward(&q("preset.example.", 4), ORIGIN_TUNNEL, "f4", "-1")
            .await
            .unwrap();
        assert_eq!(answer_ip(&p).to_string(), "203.0.113.7");
        assert_eq!(pol.responses.lock().last().unwrap().id, "Preset");
        pol.ipcsv.lock().clear();

        // a secondary transport that blocks marks the translation (0.0.0.0 among the real addresses)
        r.add(Arc::new(Fake {
            id: "Blocker".into(),
            ip: Some("0.0.0.0"),
            ..Default::default()
        }));
        *pol.sec.lock() = "Blocker".into();
        let b = r
            .forward(&q("tracker.example.", 5), ORIGIN_TUNNEL, "f5", "-1")
            .await
            .unwrap();
        let balg = answer_ip(&b);
        let (real, undid) = r.gateway().x(balg, "-1", &[]);
        assert!(
            undid && real.contains(&"0.0.0.0".parse().unwrap()),
            "{real:?}"
        );

        // translation off: real answers, and the IP -> name map keeps working
        r.translate(false, false);
        pol.sec.lock().clear();
        let n = r
            .forward(&q("plain.example.", 6), ORIGIN_TUNNEL, "f6", "-1")
            .await
            .unwrap();
        assert_eq!(answer_ip(&n).to_string(), "93.184.215.14");
        assert!(
            r.gateway()
                .ptr("93.184.215.14".parse().unwrap(), "-1", "", false)
                .0
                .contains("plain.example")
        );
    }

    #[test]
    fn fake_dns_matching() {
        let r = Resolver::new(
            "10.111.222.3:53,[fd66:f83a:c650::3]:53",
            Arc::new(Policy::default()),
        );
        settings::DNS_MODE.store(settings::DNS_MODE_IP, Ordering::SeqCst);
        assert!(r.is_dns_addr("10.111.222.3:53".parse().unwrap()));
        assert!(r.is_dns_addr("[fd66:f83a:c650::3]:53".parse().unwrap()));
        assert!(!r.is_dns_addr("1.1.1.1:53".parse().unwrap()));
    }
}
