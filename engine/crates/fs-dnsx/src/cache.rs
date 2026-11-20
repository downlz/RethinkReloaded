// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/dnsx/cacher.go

//! Answer cache: key `lower(qname without dot):qtype:do`, entries live `max(10 min, ttl + 5 min)` and each hit
//! extends the life by 5 min (up to 10 bumps), as firestack. Only clean answers are stored (NOERROR, not
//! truncated, not `.onion`, no private-range addresses).
//!
//! Not yet ported: stale-while-revalidate (serving expired entries with TTL 15 s plus a background refresh)
//! and coalescing of concurrent identical queries.

use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

const MIN_LIFE: Duration = Duration::from_secs(10 * 60);
const TTL_GRACE: Duration = Duration::from_secs(5 * 60);
const BUMP: Duration = Duration::from_secs(5 * 60);
const MAX_BUMPS: u8 = 10;
/// firestack: 128 buckets x 256 entries
const CAPACITY: usize = 128 * 256;

struct Entry {
    msg: Vec<u8>,
    expires: Instant,
    bumps: u8,
}

#[derive(Default)]
pub struct Cache {
    m: Mutex<HashMap<String, Entry>>,
}

pub fn key(qname: &str, qtype: u16, do_bit: bool) -> String {
    format!(
        "{}:{qtype}:{}",
        qname.trim_end_matches('.').to_ascii_lowercase(),
        u8::from(do_bit)
    )
}

fn is_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Whether an answer may be cached.
pub fn cacheable(qname: &str, rcode_noerror: bool, truncated: bool, ips: &[IpAddr]) -> bool {
    rcode_noerror
        && !truncated
        && !qname.trim_end_matches('.').ends_with(".onion")
        && !ips.iter().any(is_local)
}

impl Cache {
    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        let mut m = self.m.lock();
        let now = Instant::now();
        let e = m.get_mut(key)?;
        if e.expires <= now {
            m.remove(key);
            return None;
        }
        if e.bumps < MAX_BUMPS {
            e.bumps += 1;
            e.expires += BUMP;
        }
        Some(e.msg.clone())
    }

    pub fn put(&self, key: String, msg: Vec<u8>, ttl: u32) {
        let life = MIN_LIFE.max(Duration::from_secs(ttl as u64) + TTL_GRACE);
        let mut m = self.m.lock();
        if m.len() >= CAPACITY {
            let now = Instant::now();
            m.retain(|_, e| e.expires > now);
            if m.len() >= CAPACITY {
                // still full: drop the entries closest to expiry (an eighth of the cache)
                let mut by_exp: Vec<(Instant, String)> =
                    m.iter().map(|(k, e)| (e.expires, k.clone())).collect();
                by_exp.sort();
                for (_, k) in by_exp.into_iter().take(CAPACITY / 8) {
                    m.remove(&k);
                }
            }
        }
        m.insert(
            key,
            Entry {
                msg,
                expires: Instant::now() + life,
                bumps: 0,
            },
        );
    }

    pub fn clear(&self) {
        self.m.lock().clear();
    }

    pub fn len(&self) -> usize {
        self.m.lock().len()
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
        assert_eq!(key("Example.COM.", 1, false), "example.com:1:0");
        assert!(cacheable(
            "example.com.",
            true,
            false,
            &["1.2.3.4".parse().unwrap()]
        ));
        assert!(!cacheable("example.com.", false, false, &[]));
        assert!(!cacheable("x.onion.", true, false, &[]));
        assert!(!cacheable(
            "lan.",
            true,
            false,
            &["192.168.1.1".parse().unwrap()]
        ));
        let c = Cache::default();
        c.put(key("a.", 1, false), vec![1, 2], 30);
        assert_eq!(c.get(&key("A.", 1, false)), Some(vec![1, 2]));
        assert_eq!(c.get(&key("a.", 28, false)), None);
    }
}
