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

/// Outcome of one resolution run.
enum Step {
    /// no answer for the client
    None,
    /// upstream answer (Kotlin's `onUpstreamAnswer` follows)
    Answer(Vec<u8>),
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

fn unix_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// ip -> (domains, most recent first; expiry)
type RdnsMap = HashMap<IpAddr, (Vec<String>, Instant)>;

/// How long an answered IP keeps pointing at its domain(s) (at least as long as cache entries live).
const RDNS_LIFE: Duration = Duration::from_secs(10 * 60);
const RDNS_CAPACITY: usize = 64 * 1024;
const RDNS_MAX_DOMAINS: usize = 8;

pub struct Resolver {
    transports: RwLock<HashMap<String, Arc<dyn Transport>>>,
    caches: Caches,
    rdnsl: RwLock<Option<Arc<fs_blocklist::RdnsLocal>>>,
    rdnsr: RwLock<Option<Arc<Rdns>>>,
    listener: Arc<dyn DnsListener>,
    fakedns: Vec<SocketAddr>,
    rdns: parking_lot::Mutex<RdnsMap>,
}

impl Resolver {
    /// `fakedns` is the csv of `ip:port` addresses apps send DNS to (firestack requires ports).
    pub fn new(fakedns_csv: &str, listener: Arc<dyn DnsListener>) -> Self {
        let fakedns = fakedns_csv
            .split(',')
            .filter_map(|s| s.trim().parse::<SocketAddr>().ok())
            .collect();
        Resolver {
            transports: RwLock::new(HashMap::new()),
            caches: Caches::default(),
            rdnsl: RwLock::new(None),
            rdnsr: RwLock::new(None),
            listener,
            fakedns,
            rdns: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    /// Domains that recently resolved to `ip` (csv, most recent first), as firestack's ALG gateway `PTR`
    /// with translation off: fed by every answer the resolver hands to apps.
    pub fn domains_for(&self, ip: IpAddr) -> String {
        let m = self.rdns.lock();
        match m.get(&ip) {
            Some((d, exp)) if *exp > Instant::now() => d.join(","),
            _ => String::new(),
        }
    }

    /// Records the A/AAAA answers of `ans` for `qname` (and CNAME targets) in the reverse map.
    fn remember(&self, qname: &str, ans: &[u8]) {
        let Some(m) = msg::parse(ans) else { return };
        let ips = msg::answer_ips(&m);
        if ips.is_empty() {
            return;
        }
        let ttl = Duration::from_secs(msg::max_ttl(&m) as u64);
        let exp = Instant::now() + RDNS_LIFE.max(ttl);
        let mut names = vec![qname.trim_end_matches('.').to_ascii_lowercase()];
        for r in &m.answers {
            if let hickory_proto::rr::RData::CNAME(c) = &r.data {
                let n = c.0.to_ascii().trim_end_matches('.').to_ascii_lowercase();
                if !names.contains(&n) {
                    names.push(n);
                }
            }
        }
        let mut map = self.rdns.lock();
        if map.len() >= RDNS_CAPACITY {
            let now = Instant::now();
            map.retain(|_, (_, e)| *e > now);
            if map.len() >= RDNS_CAPACITY {
                map.clear();
            }
        }
        for ip in ips {
            let e = map.entry(ip).or_insert_with(|| (Vec::new(), exp));
            for n in names.iter().rev() {
                e.0.retain(|x| x != n);
                e.0.insert(0, n.clone());
            }
            e.0.truncate(RDNS_MAX_DOMAINS);
            e.1 = exp;
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

    /// Proxy for a query: the first pid of the preference (default Base); Default/System/Goos always use Base
    /// (or Exit in loopback mode, so internal lookups never route back into the tunnel).
    fn pid_for(tid: &str, pref: &Pref) -> String {
        let loopback = settings::LOOPINGBACK.load(Ordering::Relaxed);
        if matches!(
            tid,
            ids::DEFAULT | ids::SYSTEM | ids::GOOS | ids::BOOTSTRAP | "CacheDefault"
        ) {
            return if loopback {
                "Exit".into()
            } else {
                "Base".into()
            };
        }
        // Phase 1 dials only Base/Exit; other proxies (WireGuard, SOCKS5, …) arrive in Phase 2
        match pref.pids.first().map(String::as_str) {
            Some("Exit") => "Exit".into(),
            _ => "Base".into(),
        }
    }

    /// Answers a query received on the fake DNS address (`origin` = "tunnel"). `None` means: send nothing.
    pub async fn forward(&self, q: &[u8], origin: &str, fid: &str, uid: &str) -> Option<Vec<u8>> {
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
        let (qname, qtype) = msg::question(&qmsg).unwrap_or_default();
        smm.qname = qname.clone();
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

        let mut answer = None;
        let base = smm.clone();
        for run in 1..=2 {
            smm = base.clone();
            let ans = match self.forward_once(&qmsg, q, &opts, &mut smm, start).await {
                Step::None => break,
                Step::Final(a) => {
                    // blocked by on-device blocklists: no onUpstreamAnswer (firestack)
                    answer = Some(a);
                    break;
                }
                Step::Answer(a) => a,
            };
            if run == 1 {
                let ipcsv = msg::parse(&ans)
                    .map(|m| {
                        msg::answer_ips(&m)
                            .iter()
                            .map(|i| i.to_string())
                            .collect::<Vec<_>>()
                            .join(",")
                    })
                    .unwrap_or_default();
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
        if let Some(a) = &answer
            && smm.blocked_target.is_empty()
        {
            self.remember(&smm.qname, a);
        }
        self.listener.on_response(smm);
        answer
    }

    /// One run of firestack `forwardInner`: local blocklists on the query, the upstream (through the transport's
    /// cache for `Cache<tid>`), then blocklists on the answer.
    async fn forward_once(
        &self,
        qmsg: &Message,
        q: &[u8],
        opts: &DnsOpts,
        smm: &mut DnsSummary,
        start: Instant,
    ) -> Step {
        let prefs = parse_tidcsv(&opts.tidcsv);
        let pref = prefs.first().cloned().unwrap_or(Pref {
            cache: true,
            tid: ids::PREFERRED.into(),
            pids: vec![],
        });
        let Some(t) = self.determine(&pref.tid) else {
            smm.status = dns_status::TRANSPORT_ERROR;
            smm.msg = format!("{};no such transport", pref.tid);
            smm.latency = start.elapsed().as_secs_f64();
            return Step::None;
        };
        smm.typ = t.typ().to_string();
        smm.id = if pref.cache {
            format!("{}{}", ids::CACHE_PREFIX, t.id())
        } else {
            t.id().to_string()
        };
        let pid = Self::pid_for(&pref.tid, &pref);
        let (qname, qtype) = msg::question(qmsg).unwrap_or_default();

        // blockQ: on-device blocklists, unless the transport is block-free
        if let Some((ans, lists)) = self.block_q(t.id(), qmsg, qtype) {
            if opts.noblock {
                smm.blocklists = lists; // report only
            } else {
                smm.latency = start.elapsed().as_secs_f64();
                smm.status = dns_status::COMPLETE;
                smm.blocklists = lists;
                smm.blocked_target = qname;
                smm.rdata = msg::interesting_rdata(msg::parse(&ans).as_ref());
                smm.msg = NO_ERROR.into();
                return Step::Final(ans);
            }
        }

        let ans = if pref.cache {
            self.query_cached(&t, qmsg, q, &pid, smm).await
        } else {
            query_direct(&t, q, &pid, smm).await
        };
        if smm.latency <= 0.0 {
            smm.latency = start.elapsed().as_secs_f64();
        }
        let Some(ans) = ans else {
            if smm.status == dns_status::START {
                smm.status = dns_status::INTERNAL_ERROR;
            }
            return Step::None;
        };
        let Some(am) = msg::parse(&ans) else {
            return Step::Answer(ans);
        };
        if t.id() == ids::BLOCK_ALL {
            smm.blocked_target = qname.clone();
        }

        // blockA: remote blockstamp → names, else on-device blocklists on CNAME / SVCB targets
        let (blocked, target, names) = self.block_a(t.id(), qmsg, &am, &smm.blocklists);
        if !names.is_empty() {
            smm.blocklists = names;
            smm.blocked_target = target;
        }
        if smm.msg.is_empty() {
            smm.msg = NO_ERROR.into();
        }
        if !opts.noblock
            && let Some(b) = blocked
        {
            let bm = msg::parse(&b);
            smm.rttl = bm.as_ref().map(|m| msg::max_ttl(m) as i64).unwrap_or(0);
            smm.rcode = 0;
            smm.rdata = msg::interesting_rdata(bm.as_ref());
            smm.status = dns_status::COMPLETE;
            return Step::Final(b);
        }
        Step::Answer(ans)
    }

    /// firestack `ctransport.fetch`: fresh cache hits are served as-is, stale ones with 15 s TTLs plus a background
    /// refresh; misses go upstream through the barrier. Every answer is reported as cached (firestack).
    async fn query_cached(
        &self,
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
        let tc = self.caches.get(t.id());
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

    /// firestack `blockQ`: refused answer and blocklist names when on-device blocklists block the query.
    fn block_q(&self, tid: &str, qmsg: &Message, qtype: u16) -> Option<(Vec<u8>, String)> {
        if skip_block(tid) {
            return None;
        }
        let rl = self.rdnsl.read().clone()?;
        if !rl.rdns.on_device_block() {
            return None;
        }
        let names: Vec<String> = qmsg.queries.iter().map(|q| q.name().to_ascii()).collect();
        let lists = rl
            .block_query(&names, qtype)
            .ok()
            .filter(|l| !l.is_empty())?;
        let ans = msg::refused_response(qmsg).and_then(|m| msg::pack(&m))?;
        Some((ans, lists))
    }

    /// firestack `blockA`: (blocked answer, blocked target, blocklist names).
    fn block_a(
        &self,
        tid: &str,
        qmsg: &Message,
        ans: &Message,
        stamp: &str,
    ) -> (Option<Vec<u8>>, String, String) {
        let none = (None, String::new(), String::new());
        if !stamp.is_empty()
            && let Some(br) = self.rdnsr.read().clone()
            && let Ok(names) = br.stamp_to_names(stamp)
        {
            return (None, String::new(), names); // the upstream blocked it
        }
        if skip_block(tid) {
            return none;
        }
        let Some(rl) = self.rdnsl.read().clone() else {
            return none;
        };
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
                    hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A(
                        "93.184.215.14".parse().unwrap(),
                    )),
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
        redirect: Mutex<Option<String>>,
        responses: Mutex<Vec<DnsSummary>>,
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
            Box::pin(async move {
                Some(DnsOpts {
                    uid,
                    tidcsv: tid,
                    ..Default::default()
                })
            })
        }
        fn on_upstream_answer(
            &self,
            _: String,
            _: DnsSummary,
            pref: DnsOpts,
            _: String,
        ) -> BoxFuture<Option<DnsOpts>> {
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
                ("example.com.", 1, "10123")
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
        assert_eq!(
            pol.responses.lock().last().unwrap().blocked_target,
            "ads.example."
        );
        assert_eq!(
            r.domains_for("93.184.215.14".parse().unwrap()),
            "example.com",
            "reverse map from answers"
        );
        assert_eq!(
            r.domains_for("0.0.0.0".parse().unwrap()),
            "",
            "blocked answers are not mapped"
        );

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
        r.add(Arc::new(Fake {
            id: "Preferred".into(),
            stamp: stamp.clone(),
            ..Default::default()
        }));
        r.forward(&q("ads.example.", 1), ORIGIN_TUNNEL, "f1", "1")
            .await
            .unwrap();
        let s = pol.responses.lock().last().unwrap().clone();
        assert_eq!(s.blocklists, rem.stamp_to_names(&stamp).unwrap());
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
        assert_eq!(s.blocked_target, "doubleclick.net.");
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
