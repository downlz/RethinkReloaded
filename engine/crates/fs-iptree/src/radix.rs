// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/backend/core_radixtree.go
// Derived-From: celzero/firestack@d3d530ea3e:intra/xdns/dnsutil.go (StringReverse)

//! `RadixTree`: a trie of domain names keyed by their (rune-wise) reversed form, so that
//! `GetAny("a.b.example.com")` finds the value stored for `.example.com` (wildcard) or `a.b.example.com` (exact).
//!
//! firestack uses `k-sone/critbitgo.Trie`; an ordered byte-keyed map gives the same lookup semantics.

use parking_lot::RwLock;
use std::collections::BTreeMap;

#[derive(Default)]
pub struct RadixTree {
    t: RwLock<BTreeMap<Vec<u8>, String>>,
}

/// `xdns.StringReverse`: reverses by Unicode scalar values (Go's `[]rune`).
pub fn reversed(s: &str) -> Vec<u8> {
    s.chars().rev().collect::<String>().into_bytes()
}

impl RadixTree {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `k` (with an empty value). Returns true if `k` was not already present.
    pub fn add(&self, k: &str) -> bool {
        let mut t = self.t.write();
        let key = reversed(k);
        if t.contains_key(&key) {
            return false;
        }
        t.insert(key, String::new());
        true
    }

    /// Sets `k` to `v`, overwriting any previous value.
    pub fn set(&self, k: &str, v: &str) {
        self.t.write().insert(reversed(k), v.to_string());
    }

    /// Deletes `k`. Returns true if it was present.
    pub fn del(&self, k: &str) -> bool {
        self.t.write().remove(&reversed(k)).is_some()
    }

    pub fn has(&self, k: &str) -> bool {
        self.t.read().contains_key(&reversed(k))
    }

    /// Value of `k`, or "" if absent.
    pub fn get(&self, k: &str) -> String {
        self.t.read().get(&reversed(k)).cloned().unwrap_or_default()
    }

    /// Deletes all keys having `prefix` (as a domain suffix, i.e. a prefix of the reversed key).
    /// Returns the number of keys deleted.
    ///
    /// Parity note: firestack seeds its key list with `make([][]byte, 10)`, i.e. ten nil keys, which deletes the
    /// empty key (if present) before the prefixed keys. That behaviour is reproduced here.
    pub fn del_all(&self, prefix: &str) -> i32 {
        let mut t = self.t.write();
        let mut n = 0;
        if t.remove(&Vec::new()).is_some() {
            n += 1;
        }
        let p = reversed(prefix);
        let keys: Vec<Vec<u8>> = t
            .range(p.clone()..)
            .take_while(|(k, _)| k.starts_with(&p))
            .map(|(k, _)| k.clone())
            .collect();
        for k in keys {
            if t.remove(&k).is_some() {
                n += 1;
            }
        }
        n
    }

    /// True if `s` or any of its parent domains (stored as `.parent`) is present.
    pub fn has_any(&self, s: &str) -> bool {
        self.get_match(s).is_some()
    }

    /// Value of the longest matching entry for `s` (exact, or a `.suffix` wildcard), or "".
    pub fn get_any(&self, s: &str) -> String {
        self.get_match(s).unwrap_or_default()
    }

    fn get_match(&self, s: &str) -> Option<String> {
        let t = self.t.read();
        let rev = reversed(s);
        // critbitgo LongestPrefix: the longest stored key that is a prefix of rev.
        let (mlen, v) = (0..=rev.len())
            .rev()
            .find_map(|l| t.get(&rev[..l]).map(|v| (l, v)))?;
        // full match, or a match up to a subdomain boundary (".example.com"; trailing dot when reversed)
        if mlen == rev.len() || (mlen > 0 && rev[mlen - 1] == b'.') {
            Some(v.clone())
        } else {
            // partial match that is not a subdomain boundary (e.g. "ample.com" for "example.com").
            // Parity note: Go indexes rev[-1] (and panics) when only the empty key matches; we report no match.
            None
        }
    }

    pub fn clear(&self) {
        self.t.write().clear();
    }

    pub fn len(&self) -> usize {
        self.t.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_set_get_del() {
        let r = RadixTree::new();
        assert!(r.add("example.com"));
        assert!(!r.add("example.com"));
        assert_eq!(r.get("example.com"), "");
        r.set("example.com", "v1");
        assert_eq!(r.get("example.com"), "v1");
        assert!(r.has("example.com"));
        assert!(r.del("example.com"));
        assert!(!r.del("example.com"));
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn wildcard_and_exact_matching() {
        let r = RadixTree::new();
        r.set(".example.com", "wild");
        r.set("exact.org", "ex");
        assert_eq!(r.get_any("a.b.example.com"), "wild");
        assert_eq!(r.get_any("example.com"), ""); // ".example.com" is not a prefix of "moc.elpmaxe"
        assert_eq!(r.get_any("badexample.com"), ""); // partial, not at a label boundary
        assert_eq!(r.get_any("exact.org"), "ex");
        assert_eq!(r.get_any("sub.exact.org"), ""); // "gro.tcaxe" matched but next char is not after a dot
        assert!(r.has_any("x.example.com"));
        assert!(!r.has_any("example.net"));
    }

    #[test]
    fn del_all_by_suffix() {
        let r = RadixTree::new();
        for k in ["a.example.com", "b.example.com", "example.org"] {
            r.add(k);
        }
        assert_eq!(r.del_all(".example.com"), 2);
        assert_eq!(r.len(), 1);
        r.add("");
        assert_eq!(r.del_all("zzz"), 1); // Go quirk: the empty key is always removed by DelAll
    }

    #[test]
    fn rune_reversal() {
        assert_eq!(reversed("añb"), "bña".as_bytes());
    }
}
