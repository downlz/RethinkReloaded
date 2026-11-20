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

use crate::cache::{self, Cache};
use fs_core::bridge::{DnsListener, DnsOpts, DnsSummary, dns_status};
use fs_core::settings;
use fs_dns::ids;
use fs_dns::msg;
use fs_dns::transport::Transport;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const ON_QUERY_TIMEOUT: Duration = Duration::from_secs(3);
pub const ON_UPSTREAM_ANSWER_TIMEOUT: Duration = Duration::from_secs(15);
pub const ORIGIN_TUNNEL: &str = "tunnel";

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
    cache: Cache,
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
            cache: Cache::default(),
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
        for r in m.answers() {
            if let hickory_proto::rr::RData::CNAME(c) = r.data() {
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
        self.listener.on_dns_added(id);
        true
    }

    pub fn remove(&self, id: &str) -> bool {
        let removed = self.transports.write().remove(id).is_some();
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
        self.cache.clear();
    }

    pub fn stop_all(&self) {
        self.transports.write().clear();
        self.cache.clear();
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
            msg: "no error".into(),
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
        for run in 1..=2 {
            let r = self.forward_once(&qmsg, q, &opts, &mut smm, start).await;
            let Some(ans) = r else { break };
            if run == 1 && !smm.cached {
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
                        self.listener.on_response(smm);
                        return None;
                    }
                }
            }
            answer = Some(ans);
            break;
        }
        smm.latency = if smm.cached {
            0.0
        } else {
            start.elapsed().as_secs_f64()
        };
        if let Some(a) = &answer
            && smm.blocked_target.is_empty()
        {
            self.remember(&smm.qname, a);
        }
        self.listener.on_response(smm);
        answer
    }

    async fn forward_once(
        &self,
        qmsg: &hickory_proto::op::Message,
        q: &[u8],
        opts: &DnsOpts,
        smm: &mut DnsSummary,
        start: Instant,
    ) -> Option<Vec<u8>> {
        let prefs = parse_tidcsv(&opts.tidcsv);
        let pref = prefs.first().cloned().unwrap_or(Pref {
            cache: true,
            tid: ids::PREFERRED.into(),
            pids: vec![],
        });
        let Some(t) = self.determine(&pref.tid) else {
            smm.status = dns_status::TRANSPORT_ERROR;
            smm.msg = format!("{};no such transport", pref.tid);
            return None;
        };
        smm.typ = t.typ().to_string();
        smm.id = if pref.cache {
            format!("{}{}", ids::CACHE_PREFIX, t.id())
        } else {
            t.id().to_string()
        };
        let pid = Self::pid_for(&pref.tid, &pref);

        let (qname, qtype) = msg::question(qmsg).unwrap_or_default();
        let ckey = cache::key(&qname, qtype, smm.do_bit);
        if pref.cache
            && t.id() != ids::BLOCK_ALL
            && let Some(mut hit) = self.cache.get(&ckey)
        {
            if hit.len() >= 2 && q.len() >= 2 {
                hit[0] = q[0];
                hit[1] = q[1];
            }
            let m = msg::parse(&hit);
            smm.cached = true;
            smm.status = dns_status::COMPLETE;
            smm.rdata = msg::interesting_rdata(m.as_ref());
            smm.rcode = m
                .as_ref()
                .map(|m| u16::from(m.response_code()) as i64)
                .unwrap_or(0);
            smm.rttl = m.as_ref().map(|m| msg::max_ttl(m) as i64).unwrap_or(0);
            smm.pid = pid;
            return Some(hit);
        }

        match t.clone().query(q.to_vec(), pid.clone()).await {
            Ok(a) => {
                let m = msg::parse(&a.msg);
                smm.status = dns_status::COMPLETE;
                smm.server = a.server;
                smm.pid = a.pid;
                smm.rdata = msg::interesting_rdata(m.as_ref());
                if let Some(m) = &m {
                    smm.rcode = u16::from(m.response_code()) as i64;
                    smm.rttl = msg::max_ttl(m) as i64;
                    smm.ad = m.authentic_data();
                    if t.id() == ids::BLOCK_ALL {
                        smm.blocked_target = qname.clone();
                    }
                    let ips = msg::answer_ips(m);
                    let ok = m.response_code() == ResponseCode::NoError;
                    if pref.cache
                        && t.id() != ids::BLOCK_ALL
                        && cache::cacheable(&qname, ok, m.truncated(), &ips)
                    {
                        self.cache.put(ckey, a.msg.clone(), msg::max_ttl(m));
                    }
                }
                smm.latency = start.elapsed().as_secs_f64();
                Some(a.msg)
            }
            Err(e) => {
                smm.status = e.status;
                smm.msg = e.msg;
                smm.server = e.server;
                smm.pid = pid;
                smm.latency = start.elapsed().as_secs_f64();
                None
            }
        }
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

    struct Fake {
        id: String,
        n: AtomicUsize,
        fail: bool,
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
            Box::pin(async move {
                if fail {
                    return Err(QueryError::new(dns_status::SEND_FAILED, "boom"));
                }
                let m = msg::parse(&q).unwrap();
                let mut r = msg::empty_response(&m);
                let name = m.queries()[0].name().clone();
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
            n: AtomicUsize::new(0),
            fail: false,
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
            assert!(res[1].cached && res[1].latency == 0.0);
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
            n: AtomicUsize::new(0),
            fail: true,
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
