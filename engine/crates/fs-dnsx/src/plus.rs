// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2025 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/dnsx/plus.go
// Derived-From: celzero/firestack@d3d530ea3e:intra/dnsx/transport.go (Categorize, Fastest, IsEncrypted)

//! Rethink Plus ("smart DNS"): a transport over the transports Kotlin adds with ids prefixed `Plus`. Each query
//! tries up to six of them in order: the one that answered last, the healthy ones by p50, Default, then the
//! others, reordered by the Plus strategy (safest: encrypted only; random; fastest; robust: as is) and narrowed by
//! the Plus filter (ad-blocking, security or family resolvers only). Errors, SERVFAILs and blocked answers move on to
//! the next; no-answer responses do too, until half the tries are spent.

use fs_core::bridge::{BoxFuture, dns_status};
use fs_core::settings;
use fs_dns::msg;
use fs_dns::transport::{
    Answer, QueryError, TYPE_DNSCRYPT, TYPE_DOH, TYPE_DOT, TYPE_ODOH, Transport,
};
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;
use parking_lot::{Mutex, RwLock};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

pub const PLUS: &str = fs_dns::ids::PLUS;
const MAX_TRIES: usize = 6;
/// the order is reused for this long (firestack's 10 s barrier)
const ORDER_TTL: Duration = Duration::from_secs(10);
const ADDR: &str = "[fdaa:9125::9]:53";

pub const FILTER_NONE: i32 = 0;
pub const FILTER_ADBLOCK: i32 = 1;
pub const FILTER_SECURITY: i32 = 2;
pub const FILTER_FAMILY: i32 = 3;

/// firestack `isPlus`: `Plus…` or `CachedPlus…`.
pub fn is_plus(id: &str) -> bool {
    id.starts_with(PLUS)
        || id
            .strip_prefix(fs_dns::ids::CACHE_PREFIX)
            .is_some_and(|s| s.starts_with(PLUS))
}

fn is_encrypted(t: &dyn Transport) -> bool {
    matches!(t.typ(), TYPE_DOH | TYPE_DOT | TYPE_DNSCRYPT | TYPE_ODOH)
}

fn blocks_ad(enc: bool, a: &str) -> bool {
    enc && (a.contains("dns.adguard-dns")
        || a.contains("noads.joindns4")
        || a.contains("p2.freedns.controld"))
        || a.contains("freedns.controld.com/p2")
}

fn blocks_mal(enc: bool, a: &str) -> bool {
    enc && (a.contains("dns.quad9")
        || a.contains("9.9.9.9")
        || a.contains("security.cloudflare-dns")
        || a.contains("p1.freedns.controld"))
        || a.contains("freedns.controld.com/p1")
        || a.contains("security-filter-dns.cleanbrowsing")
        || a.contains("doh.cleanbrowsing.org/doh/security-filter")
}

fn blocks_unsafe(enc: bool, a: &str) -> bool {
    enc && (a.contains("doh.cleanbrowsing.org/doh/family-filter")
        || a.contains("family-filter-dns.cleanbrowsing")
        || a.contains("adult-filter-dns.cleanbrowsing.org")
        || a.contains("doh.cleanbrowsing.org/doh/adult-filter")
        || a.contains("family.cloudflare-dns.com")
        || a.contains("1.1.1.3")
        || a.contains("family.freedns.controld.com"))
        || a.contains("freedns.controld.com/family")
        || a.contains("family.adguard-dns")
}

/// firestack `makeFilterAttr` for the Plus filter in effect.
fn passes(filter: i32, t: &dyn Transport) -> bool {
    let a = t.addr().to_lowercase();
    if a.is_empty() {
        return false;
    }
    let enc = is_encrypted(t);
    match filter {
        FILTER_SECURITY => blocks_mal(enc, &a),
        FILTER_FAMILY => blocks_unsafe(enc, &a),
        _ => blocks_ad(enc, &a), // adblock is the default for any other non-zero filter
    }
}

/// firestack `Categorize` (non-relaying transports): best (complete), preferred (fresh or soft failures),
/// recoverable (internal/transport errors), errored (client errors, send failures); ended ones are dropped.
type Ranked = Vec<Arc<dyn Transport>>;
fn categorize(ts: Ranked) -> (Ranked, Ranked, Ranked, Ranked) {
    let (mut best, mut pref, mut recov, mut errd) = (vec![], vec![], vec![], vec![]);
    for t in ts {
        match t.status() {
            dns_status::COMPLETE => best.push(t),
            dns_status::START
            | dns_status::UNPAUSED
            | dns_status::NO_RESPONSE
            | dns_status::BAD_QUERY
            | dns_status::BAD_RESPONSE => pref.push(t),
            dns_status::INTERNAL_ERROR | dns_status::TRANSPORT_ERROR => recov.push(t),
            dns_status::DEND | dns_status::PAUSED | dns_status::UNKNOWN => {}
            _ => errd.push(t),
        }
    }
    best.sort_by_key(|t| t.p50());
    pref.sort_by_key(|t| t.p50());
    (best, pref, recov, errd)
}

fn uniq(ts: Ranked) -> Ranked {
    let mut seen = HashSet::new();
    ts.into_iter()
        .filter(|t| seen.insert(t.id().to_string()))
        .collect()
}

/// Supplies the Default transport (firestack `r.GetInternal(Default)`).
pub type DefaultDns = Box<dyn Fn() -> Option<Arc<dyn Transport>> + Send + Sync>;

pub struct Plus {
    transports: RwLock<HashMap<String, Arc<dyn Transport>>>,
    last: Mutex<Option<Weak<dyn Transport>>>,
    order: Mutex<Option<(Instant, Result<Ranked, String>)>>,
    default_dns: DefaultDns,
}

impl Plus {
    pub fn new(default_dns: DefaultDns) -> Self {
        Plus {
            transports: RwLock::new(HashMap::new()),
            last: Mutex::new(None),
            order: Mutex::new(None),
            default_dns,
        }
    }

    /// firestack `plus.Add`: relaying transports are refused (Plus never relays).
    pub fn add(&self, t: Arc<dyn Transport>) -> bool {
        self.transports.write().insert(t.id().to_string(), t);
        *self.order.lock() = None;
        true
    }

    pub fn remove(&self, id: &str) -> bool {
        let r = self.transports.write().remove(id).is_some();
        *self.order.lock() = None;
        r
    }

    pub fn get(&self, id: &str) -> Option<Arc<dyn Transport>> {
        self.transports.read().get(id).cloned()
    }

    fn all(&self) -> Ranked {
        self.transports.read().values().cloned().collect()
    }

    /// firestack `LiveTransports`: members that are not ended.
    pub fn live(&self) -> Vec<String> {
        let mut ids: Vec<String> = self
            .all()
            .into_iter()
            .filter(|t| {
                !matches!(
                    t.status(),
                    dns_status::DEND | dns_status::PAUSED | dns_status::UNKNOWN
                )
            })
            .map(|t| t.id().to_string())
            .collect();
        ids.sort();
        ids
    }

    /// firestack `Refresh`: forgets the cached order (it re-classifies filters).
    pub fn refresh(&self) -> String {
        *self.order.lock() = None;
        self.live().join(",")
    }

    pub fn stop_all(&self) {
        self.transports.write().clear();
        *self.last.lock() = None;
        *self.order.lock() = None;
    }

    fn latest(&self) -> Option<Arc<dyn Transport>> {
        if let Some(t) = self.last.lock().as_ref().and_then(Weak::upgrade) {
            return Some(t);
        }
        self.all().into_iter().next()
    }

    /// firestack `ordered`.
    fn ordered(&self) -> Result<Ranked, String> {
        let (best, pref, recov, errd) = categorize(self.all());
        let mut ord: Ranked = Vec::new();
        ord.extend(self.latest());
        ord.extend(best);
        ord.extend((self.default_dns)());
        ord.extend(pref);
        ord.extend(recov);
        let mut ord = uniq(ord);
        let strat = settings::PLUS_STRAT.load(Ordering::Relaxed) as i64;
        let filter = settings::PLUS_FILTER.load(Ordering::Relaxed);
        let apply = |mut o: Ranked| -> Ranked {
            match strat {
                settings::PLUS_ORDER_SAFEST => o.retain(|t| is_encrypted(t.as_ref())),
                settings::PLUS_ORDER_RANDOM => shuffle(&mut o),
                settings::PLUS_ORDER_FASTEST => o.sort_by_key(|t| t.p50()),
                _ => {}
            }
            o
        };
        ord = apply(ord);
        if ord.len() < MAX_TRIES {
            let mut more = ord;
            more.extend(errd);
            ord = apply(uniq(more));
        }
        if filter != FILTER_NONE {
            ord.retain(|t| passes(filter, t.as_ref()));
            if ord.is_empty() {
                return Err("plus: no transport passes the filter".into());
            }
        }
        if ord.is_empty() {
            return Err("plus: no such transport".into());
        }
        Ok(ord)
    }

    fn order(&self) -> Result<Ranked, String> {
        let mut g = self.order.lock();
        if let Some((at, o)) = g.as_ref()
            && at.elapsed() < ORDER_TTL
        {
            return o.clone();
        }
        let o = self.ordered();
        *g = Some((Instant::now(), o.clone()));
        o
    }

    /// firestack `forward`.
    async fn forward(&self, q: Vec<u8>, pid: String) -> Result<Answer, QueryError> {
        let all = self
            .order()
            .map_err(|e| QueryError::new(dns_status::TRANSPORT_ERROR, e))?;
        let qm = msg::parse(&q);
        let qt = qm.as_ref().map(msg::qtype).unwrap_or(0);
        let aquada = qt == u16::from(RecordType::A) || qt == u16::from(RecordType::AAAA);
        let svcb = qt == u16::from(RecordType::HTTPS) || qt == u16::from(RecordType::SVCB);
        let mut visited = HashSet::new();
        let mut last_ans: Option<Answer> = None;
        let mut last_err = QueryError::new(dns_status::NO_RESPONSE, "plus: no answer");
        for t in all {
            if visited.len() >= MAX_TRIES {
                break;
            }
            if !visited.insert(t.id().to_string()) {
                continue;
            }
            let a = match t.clone().query(q.clone(), pid.clone()).await {
                Ok(a) => a,
                Err(e) => {
                    last_err = e;
                    continue;
                }
            };
            let m = msg::parse(&a.msg);
            let failed = m
                .as_ref()
                .is_none_or(|m| m.metadata.response_code == ResponseCode::ServFail);
            let noans = !failed && m.as_ref().is_some_and(|m| !msg::has_answers(m));
            let ipblock = aquada && m.as_ref().is_some_and(msg::aquada_unspecified);
            let svcbblock = svcb && noans;
            last_ans = Some(a.clone());
            if failed || ipblock || svcbblock {
                continue;
            }
            if noans && visited.len() <= MAX_TRIES / 2 {
                continue; // an IPv4-only name answers AAAA with nothing; see if others agree
            }
            *self.last.lock() = Some(Arc::downgrade(&t));
            return Ok(a);
        }
        // errors are suppressed when some transport answered at all
        last_ans.ok_or(last_err)
    }
}

/// Fisher-Yates.
fn shuffle<T>(v: &mut [T]) {
    for i in (1..v.len()).rev() {
        let b: [u8; 4] = fs_dns::dnscrypt::crypto::random();
        v.swap(i, u32::from_le_bytes(b) as usize % (i + 1));
    }
}

impl Transport for Plus {
    fn id(&self) -> &str {
        PLUS
    }
    fn typ(&self) -> &str {
        TYPE_DOH
    }
    fn addr(&self) -> String {
        ADDR.into()
    }
    fn status(&self) -> i32 {
        self.latest()
            .map(|t| t.status())
            .unwrap_or(dns_status::CLIENT_ERROR)
    }
    fn p50(&self) -> i64 {
        self.latest().map(|t| t.p50()).unwrap_or(0)
    }
    fn query(self: Arc<Self>, q: Vec<u8>, pid: String) -> BoxFuture<Result<Answer, QueryError>> {
        Box::pin(async move { self.forward(q, pid).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fs_dns::transport::Stats;
    use hickory_proto::op::Message;
    use std::sync::atomic::AtomicUsize;

    /// Answers with `ip` (or SERVFAIL / nothing / an error), counting its queries.
    struct Fake {
        id: String,
        addr: String,
        typ: &'static str,
        answer: Option<Option<std::net::IpAddr>>,
        servfail: bool,
        p50: i64,
        n: AtomicUsize,
        stats: Stats,
    }

    fn fake(id: &str, addr: &str, answer: Option<Option<&str>>, p50: i64) -> Arc<Fake> {
        Arc::new(Fake {
            id: id.into(),
            addr: addr.into(),
            typ: TYPE_DOH,
            answer: answer.map(|a| a.map(|s| s.parse().unwrap())),
            servfail: false,
            p50,
            n: AtomicUsize::new(0),
            stats: Stats::default(),
        })
    }

    impl Transport for Fake {
        fn id(&self) -> &str {
            &self.id
        }
        fn typ(&self) -> &str {
            self.typ
        }
        fn addr(&self) -> String {
            self.addr.clone()
        }
        fn status(&self) -> i32 {
            self.stats.status()
        }
        fn p50(&self) -> i64 {
            self.p50
        }
        fn query(
            self: Arc<Self>,
            q: Vec<u8>,
            pid: String,
        ) -> BoxFuture<Result<Answer, QueryError>> {
            Box::pin(async move {
                self.n.fetch_add(1, Ordering::Relaxed);
                let m = msg::parse(&q).unwrap();
                let Some(ip) = self.answer else {
                    self.stats.err(dns_status::SEND_FAILED);
                    return Err(QueryError::new(dns_status::SEND_FAILED, "down"));
                };
                self.stats.ok(Duration::from_millis(1));
                let r: Message = if self.servfail {
                    msg::servfail(&m)
                } else {
                    match ip {
                        Some(ip) => msg::aquada_for_query(&m, 60, &[ip]).unwrap(),
                        None => msg::empty_response(&m),
                    }
                };
                Ok(Answer {
                    msg: msg::pack(&r).unwrap(),
                    server: self.addr.clone(),
                    pid,
                    ..Default::default()
                })
            })
        }
    }

    /// the Plus settings are global
    static SETTINGS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    fn q() -> Vec<u8> {
        msg::pack(&msg::query("example.com.", RecordType::A, 1).unwrap()).unwrap()
    }

    fn ips(a: &Answer) -> Vec<std::net::IpAddr> {
        msg::a_answers(&msg::parse(&a.msg).unwrap())
    }

    #[tokio::test]
    async fn tries_in_order_and_remembers() {
        let _g = SETTINGS.lock().await;
        settings::PLUS_STRAT.store(settings::PLUS_ORDER_ROBUST as i32, Ordering::SeqCst);
        settings::PLUS_FILTER.store(FILTER_NONE, Ordering::SeqCst);
        let p = Arc::new(Plus::new(Box::new(|| None)));
        let down = fake("Plus:1:a", "https://down.example/dns-query", None, 1);
        let block = fake(
            "Plus:1:b",
            "https://block.example/dns-query",
            Some(Some("0.0.0.0")),
            2,
        );
        let good = fake(
            "Plus:1:c",
            "https://good.example/dns-query",
            Some(Some("1.2.3.4")),
            3,
        );
        for t in [down.clone(), block.clone(), good.clone()] {
            p.add(t);
        }
        let a = p.clone().query(q(), "Base".into()).await.unwrap();
        assert_eq!(ips(&a), ["1.2.3.4".parse::<std::net::IpAddr>().unwrap()]);
        // the one that answered goes first next time
        *p.order.lock() = None;
        let before = good.n.load(Ordering::Relaxed);
        p.clone().query(q(), "Base".into()).await.unwrap();
        assert_eq!(good.n.load(Ordering::Relaxed), before + 1);
        assert_eq!(p.live().len(), 3);
        assert!(p.remove("Plus:1:a") && p.get("Plus:1:a").is_none());
    }

    #[tokio::test]
    async fn filters_and_safest() {
        let _g = SETTINGS.lock().await;
        settings::PLUS_STRAT.store(settings::PLUS_ORDER_ROBUST as i32, Ordering::SeqCst);
        let p = Arc::new(Plus::new(Box::new(|| None)));
        p.add(fake(
            "Plus:1:x",
            "https://cloudflare-dns.com/dns-query",
            Some(Some("1.1.1.1")),
            1,
        ));
        p.add(fake(
            "Plus:1:q",
            "https://dns.quad9.net/dns-query",
            Some(Some("9.9.9.9")),
            9,
        ));
        settings::PLUS_FILTER.store(FILTER_SECURITY, Ordering::SeqCst);
        let a = p.clone().query(q(), "Base".into()).await.unwrap();
        assert_eq!(
            a.server, "https://dns.quad9.net/dns-query",
            "only security resolvers"
        );
        settings::PLUS_FILTER.store(FILTER_FAMILY, Ordering::SeqCst);
        *p.order.lock() = None;
        assert!(
            p.clone().query(q(), "Base".into()).await.is_err(),
            "no family resolver"
        );
        settings::PLUS_FILTER.store(FILTER_NONE, Ordering::SeqCst);
        assert!(is_plus("Plus:1:x") && is_plus("CachePlus") && !is_plus("Preferred"));
    }
}
