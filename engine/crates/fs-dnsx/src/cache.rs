// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/dnsx/cacher.go
// Derived-From: celzero/firestack@d3d530ea3e:intra/core/barrier.go (request coalescing)
// Derived-From: celzero/firestack@d3d530ea3e:intra/core/hangover.go

//! Per-transport answer caches (firestack `ctransport`, one per transport id, used for `Cache<tid>` preferences):
//!
//! * key `qname:qtype:do` (normalized qname); entries live 10 min, or ttl + 5 min for longer ttls; each read bumps
//!   the expiry by `bumps x 5 min` (up to 10 bumps) while the entry is alive.
//! * a read is *fresh* when the entry is alive and either among its first three reads or a coin flip says so;
//!   otherwise the answer is served *stale* (answer TTLs set to 15 s) and refreshed in the background. Expired
//!   entries are kept (and served stale) until a scrub under high load evicts them.
//! * concurrent identical requests share one upstream exchange (the barrier), whose outcome is reused for 30 s
//!   (errors for 6 s).
//! * undelegated / special-use names are never cached (firestack `CacheUndelegatedQueries = false`).
//! * hangover: once a transport has failed to send for more than 10 s, nothing is served from its cache and
//!   requests get no answer until it recovers (so apps do not think there is connectivity).

use fs_dns::transport::QueryError;
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const TTL: Duration = Duration::from_secs(10 * 60);
const HALFLIFE: Duration = Duration::from_secs(5 * 60);
const MAX_BUMPS: u32 = 10;
/// firestack: 128 buckets x 256 entries (the bucket size is only a scrub threshold there)
const CAPACITY: usize = 128 * 256;
const SCRUB_GAP: Duration = Duration::from_secs(5 * 60);
/// TTL set on the answer records of stale responses.
pub const STALE_TTL: u32 = 15;
/// barrier: reuse completed outcomes for 30 s, errors for 6 s; requests time out after 30 s
pub const BARRIER_TTL: Duration = Duration::from_secs(30);
const BARRIER_NEG: Duration = Duration::from_secs(6);
/// hangover threshold
pub const HANGOVER: Duration = Duration::from_secs(10);

/// The summary fields a cached answer carries (firestack keeps a copy of the `DNSSummary`).
#[derive(Clone, Debug, Default)]
pub struct Summ {
    pub server: String,
    pub pid: String,
    pub rdata: String,
    pub ad: bool,
    pub rcode: i64,
    pub rttl: i64,
    pub status: i32,
    pub msg: String,
    pub blocklists: String,
    pub region: String,
    pub latency: f64,
}

/// An upstream exchange's outcome, as shared through the barrier.
pub type Outcome = Result<(Arc<Vec<u8>>, Summ), (QueryError, Summ)>;

struct Entry {
    msg: Arc<Vec<u8>>,
    s: Summ,
    expiry: Instant,
    bumps: u32,
}

/// A cache read.
pub struct Hit {
    pub msg: Arc<Vec<u8>>,
    pub s: Summ,
    pub fresh: bool,
}

struct Flight {
    dob: Instant,
    cell: tokio::sync::OnceCell<Outcome>,
}

/// One transport's cache, barrier and hangover tracker.
pub struct TCache {
    entries: Mutex<HashMap<String, Entry>>,
    barrier: Mutex<HashMap<String, Arc<Flight>>>,
    hangover: Mutex<Option<Instant>>,
    scrubtime: Mutex<Option<Instant>>,
}

/// Cheap randomness: a randomly keyed hash of the time.
fn coin(pct: u64) -> bool {
    use std::hash::BuildHasher;
    std::collections::hash_map::RandomState::new().hash_one(Instant::now()) % 100_000 < pct * 1000
}

/// firestack `mkcachekey`: `qname:qtype:do`; `None` for names that are not ASCII (firestack fails the query, the
/// port bypasses the cache).
pub fn key(qname: &str, qtype: u16, do_bit: bool) -> Option<String> {
    let n = fs_blocklist::normalize_qname(qname);
    if n.is_empty() || !n.is_ascii() {
        return None;
    }
    Some(format!("{n}:{qtype}:{}", u8::from(do_bit)))
}

/// firestack `isLocalIP`: loopback, private, link-local, multicast, CGNAT and other non-global unicast; never the
/// unspecified address (block answers).
pub fn is_local(ip: &IpAddr) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(*ip),
        _ => *ip,
    };
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_unspecified() {
                return false;
            }
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_multicast()
                || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64/10
                || v4.is_broadcast() // the only other non-global IPv4 unicast in Go
        }
        IpAddr::V6(v6) => {
            if v6.is_unspecified() {
                return false;
            }
            let s0 = v6.segments()[0];
            v6.is_loopback()
                || v6.is_multicast()
                || (s0 & 0xfe00) == 0xfc00 // ULA
                || (s0 & 0xffc0) == 0xfe80 // link-local
        }
    }
}

/// firestack `put` admission: NOERROR, not truncated, not `.onion`, no local addresses.
pub fn cacheable(key: &str, rcode_noerror: bool, truncated: bool, ips: &[IpAddr]) -> bool {
    let qname = key.split(':').next().unwrap_or_default();
    rcode_noerror
        && !truncated
        && !key.contains(".onion:")
        && !crate::undelegated::is_undelegated(qname) // CacheUndelegatedQueries = false
        && !ips.iter().any(is_local)
}

impl Default for TCache {
    fn default() -> Self {
        TCache {
            entries: Mutex::new(HashMap::new()),
            barrier: Mutex::new(HashMap::new()),
            hangover: Mutex::new(None),
            scrubtime: Mutex::new(None),
        }
    }
}

impl TCache {
    /// firestack `freshCopy`: bumps the entry; fresh = alive && (one of the first reads || 50% chance).
    pub fn fresh_copy(&self, key: &str) -> Option<Hit> {
        let mut m = self.entries.lock();
        let v = m.get_mut(key)?;
        let now = Instant::now();
        let recent = v.bumps <= 2;
        let alive = now <= v.expiry;
        if v.bumps < MAX_BUMPS {
            let n = HALFLIFE * v.bumps;
            // firestack: extend by n only while expiry-n is still in the future
            if alive && v.expiry.checked_sub(n).is_some_and(|t| now < t) {
                v.expiry += n;
            }
            v.bumps += 1;
        }
        Some(Hit {
            msg: v.msg.clone(),
            s: v.s.clone(),
            fresh: (coin(50) || recent) && alive,
        })
    }

    /// firestack `put`: callers check [`cacheable`] first. `ttl` is the answer's TTL (0 for empty answers).
    pub fn put(&self, key: &str, msg: Arc<Vec<u8>>, s: Summ, ttl: u32) {
        let ansttl = Duration::from_secs(ttl as u64);
        let life = if ansttl < TTL { TTL } else { ansttl + HALFLIFE };
        if coin(33) {
            self.scrub();
        }
        let mut m = self.entries.lock();
        if m.len() >= 2 * CAPACITY {
            // the port bounds memory (firestack only logs an overflow): drop expired entries, then the
            // eighth closest to expiry
            let now = Instant::now();
            m.retain(|_, e| e.expiry > now);
            if m.len() >= 2 * CAPACITY {
                let mut by_exp: Vec<(Instant, String)> =
                    m.iter().map(|(k, e)| (e.expiry, k.clone())).collect();
                by_exp.sort();
                for (_, k) in by_exp.into_iter().take(CAPACITY / 4) {
                    m.remove(&k);
                }
            }
        }
        m.insert(
            key.to_string(),
            Entry {
                msg,
                s,
                expiry: Instant::now() + life,
                bumps: 0,
            },
        );
    }

    /// firestack `scrubCache`: at most every 5 min; under high load (75% full) evicts expired entries among the
    /// next quarter of the cache.
    fn scrub(&self) {
        let now = Instant::now();
        {
            let mut st = self.scrubtime.lock();
            if st.is_some_and(|t| now.duration_since(t) < SCRUB_GAP) {
                return;
            }
            *st = Some(now);
        }
        let mut m = self.entries.lock();
        if m.len() < CAPACITY * 75 / 100 {
            return;
        }
        let expired: Vec<String> = m
            .iter()
            .take(CAPACITY / 4)
            .filter(|(_, e)| now > e.expiry)
            .map(|(k, _)| k.clone())
            .collect();
        for k in expired {
            m.remove(&k);
        }
    }

    pub fn remove(&self, key: &str) {
        self.entries.lock().remove(key);
    }

    pub fn len(&self) -> usize {
        self.entries.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// firestack `hangoverCheckpoint`: notes the start of a run of send failures, or ends it.
    pub fn checkpoint(&self, send_failed: bool) {
        let mut h = self.hangover.lock();
        if send_failed {
            h.get_or_insert_with(Instant::now);
        } else {
            *h = None;
        }
    }

    /// No send failures, or failing for at most [`HANGOVER`].
    pub fn transport_ok(&self) -> bool {
        self.hangover.lock().is_none_or(|t| t.elapsed() <= HANGOVER)
    }

    /// firestack `Barrier.DoIt`: runs `work` once for concurrent callers with the same key and reuses its
    /// outcome for [`BARRIER_TTL`] (errors for 6 s). Returns the outcome and whether this caller ran `work`.
    pub async fn barrier<F, Fut>(&self, key: &str, work: F) -> (Outcome, bool)
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Outcome>,
    {
        let fl = {
            let mut b = self.barrier.lock();
            let now = Instant::now();
            if b.len() > 1024 {
                b.retain(|_, f| now.duration_since(f.dob) <= BARRIER_TTL);
            }
            let live = b.get(key).filter(|f| {
                let ttl = match f.cell.get() {
                    Some(Err(_)) => BARRIER_NEG,
                    _ => BARRIER_TTL,
                };
                now.duration_since(f.dob) <= ttl
            });
            match live {
                Some(f) => f.clone(),
                None => {
                    let f = Arc::new(Flight {
                        dob: now,
                        cell: tokio::sync::OnceCell::new(),
                    });
                    b.insert(key.to_string(), f.clone());
                    f
                }
            }
        };
        let ran = AtomicBool::new(false);
        let out = fl
            .cell
            .get_or_init(|| async {
                ran.store(true, Ordering::Relaxed);
                match tokio::time::timeout(BARRIER_TTL, work()).await {
                    Ok(o) => o,
                    Err(_) => Err((
                        QueryError::new(
                            fs_core::bridge::dns_status::SEND_FAILED,
                            "dns: barrier timeout",
                        ),
                        Summ::default(),
                    )),
                }
            })
            .await
            .clone();
        (out, ran.load(Ordering::Relaxed))
    }
}

/// All transports' caches, by transport id.
#[derive(Default)]
pub struct Caches {
    m: RwLock<HashMap<String, Arc<TCache>>>,
}

impl Caches {
    pub fn get(&self, tid: &str) -> Arc<TCache> {
        if let Some(c) = self.m.read().get(tid) {
            return c.clone();
        }
        self.m.write().entry(tid.to_string()).or_default().clone()
    }

    /// Drops a transport's cache (the transport was replaced or removed).
    pub fn drop_tid(&self, tid: &str) {
        self.m.write().remove(tid);
    }

    pub fn clear(&self) {
        self.m.write().clear();
    }

    pub fn len(&self) -> usize {
        self.m.read().values().map(|c| c.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_and_rules() {
        assert_eq!(key("Example.COM.", 1, false).unwrap(), "example.com:1:0");
        assert_eq!(key("x.", 28, true).unwrap(), "x:28:1");
        assert!(key("ünï.de.", 1, false).is_none());
        let k = key("example.com.", 1, false).unwrap();
        assert!(cacheable(&k, true, false, &["1.2.3.4".parse().unwrap()]));
        assert!(
            cacheable(&k, true, false, &["0.0.0.0".parse().unwrap()]),
            "blocks are cacheable"
        );
        assert!(!cacheable(&k, false, false, &[]));
        assert!(!cacheable("x.onion:1:0", true, false, &[]));
        assert!(
            !cacheable("router.lan:1:0", true, false, &[]),
            "undelegated"
        );
        for ip in [
            "192.168.1.1",
            "100.64.0.1",
            "fe80::1",
            "::ffff:10.0.0.1",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            assert!(!cacheable(&k, true, false, &[ip.parse().unwrap()]), "{ip}");
        }
    }

    #[test]
    fn reads_bump_and_go_stale() {
        let c = TCache::default();
        c.put("a:1:0", Arc::new(vec![1, 2]), Summ::default(), 30);
        for _ in 0..3 {
            assert!(
                c.fresh_copy("a:1:0").unwrap().fresh,
                "first reads are fresh"
            );
        }
        assert!(c.fresh_copy("b:1:0").is_none());
        // expire it: still served, never fresh
        c.entries.lock().get_mut("a:1:0").unwrap().expiry = Instant::now() - Duration::from_secs(1);
        for _ in 0..5 {
            assert!(!c.fresh_copy("a:1:0").unwrap().fresh);
        }
    }

    #[tokio::test]
    async fn barrier_coalesces_and_retains() {
        let c = Arc::new(TCache::default());
        let n = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let work = |n: Arc<std::sync::atomic::AtomicUsize>| {
            move || async move {
                n.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(30)).await;
                let o: Outcome = Ok((Arc::new(vec![9u8]), Summ::default()));
                o
            }
        };
        let (a, b) = tokio::join!(
            c.barrier("k", work(n.clone())),
            c.barrier("k", work(n.clone()))
        );
        assert_eq!(n.load(Ordering::SeqCst), 1, "one exchange for two callers");
        assert!(a.1 ^ b.1, "exactly one caller ran the work");
        let (again, ran) = c.barrier("k", work(n.clone())).await;
        assert!(!ran && again.is_ok(), "outcome reused within 30 s");
        c.checkpoint(true);
        assert!(c.transport_ok());
        *c.hangover.lock() = Some(Instant::now() - Duration::from_secs(11));
        assert!(!c.transport_ok());
        c.checkpoint(false);
        assert!(c.transport_ok());
    }
}
