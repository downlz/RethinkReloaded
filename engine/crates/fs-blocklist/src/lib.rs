// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2020 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/dnsx/rethinkdns.go (rethinkdnslocal, blockQuery, blockAnswer)
// Derived-From: celzero/firestack@d3d530ea3e:intra/xdns/dnsutil.go (NormalizeQName)

//! RethinkDNS blocklists: blockstamps ([`stamp`]) and the on-device trie ([`trie`]). Checked against firestack's
//! own results by `tests/oracle.rs` (fixtures from `tools/go-oracle`).

pub mod bits;
pub mod goenc;
pub mod stamp;
pub mod trie;

use stamp::{ERR_NO_STAMPS, Mode, Rdns};
use std::path::Path;
use std::sync::Arc;

pub const ERR_NO_MATCH: &str = "no blocklist applies";

/// DNS types whose queries local blocklists may block: A, AAAA, SVCB, HTTPS.
pub fn blockable_qtype(qtype: u16) -> bool {
    matches!(qtype, 1 | 28 | 64 | 65)
}

/// firestack `xdns.NormalizeQName`: no trailing dot, ASCII lowercase; names with non-ASCII bytes are returned
/// with only the dot trimmed.
pub fn normalize_qname(s: &str) -> String {
    if s.is_empty() || s == "." {
        return ".".into();
    }
    let s = s.strip_suffix('.').unwrap_or(s);
    if !s.is_ascii() {
        return s.to_string();
    }
    s.to_ascii_lowercase()
}

/// firestack `rethinkdnslocal`: blockstamps plus the trie. `rdns` is shared with the `RDNS` object Kotlin holds,
/// so `setStamp` from Kotlin applies to lookups at once.
pub struct RdnsLocal {
    pub rdns: Arc<Rdns>,
    pub trie: trie::FrozenTrie,
}

impl RdnsLocal {
    /// firestack `newRDNSLocal`.
    pub fn new(td: &str, rd: &str, conf: &str, filetag: &str) -> Result<Self, String> {
        if td.is_empty() || rd.is_empty() || conf.is_empty() || filetag.is_empty() {
            return Err("missing data, unable to build blocklist".into());
        }
        let trie = trie::build(
            Path::new(td),
            Path::new(rd),
            Path::new(conf),
            Path::new(filetag),
        )?;
        let rdns = Arc::new(Rdns::from_filetag(Path::new(filetag), Mode::Local)?);
        Ok(RdnsLocal { rdns, trie })
    }

    fn stamp(&self) -> Result<String, String> {
        let s = self.rdns.get_stamp()?;
        if s.is_empty() {
            return Err(ERR_NO_STAMPS.into());
        }
        Ok(s)
    }

    fn names(&self, lists: &[String]) -> String {
        self.rdns.key_to_names(lists).join(",")
    }

    /// firestack `blockQuery`: `qnames` as in the question section, `qtype` of the first question. Returns the
    /// `group:name` csv of the selected lists that block the first blocked name.
    pub fn block_query(&self, qnames: &[String], qtype: u16) -> Result<String, String> {
        if qnames.is_empty() {
            return Err("no query name".into());
        }
        let stamp = self.stamp()?;
        for q in qnames {
            let qname = normalize_qname(q);
            if !blockable_qtype(qtype) {
                return Err(format!("unsupported dns query type {qtype}"));
            }
            let (block, lists) = self.trie.dn_lookup(&qname, &stamp);
            if block {
                return Ok(self.names(&lists));
            }
        }
        Err(ERR_NO_MATCH.into())
    }

    /// firestack `blockAnswer`: `targets` are the CNAME targets and AliasMode (priority 0) SVCB/HTTPS targets of the
    /// answer section, in order; `.` means `qname`. Returns (blocked target, `group:name` csv).
    pub fn block_answer(
        &self,
        qname: &str,
        answers: usize,
        targets: &[String],
    ) -> Result<(String, String), String> {
        if answers == 0 {
            return Err("req at least one answer".into());
        }
        let stamp = self.stamp()?;
        for t in targets {
            if t.is_empty() {
                continue;
            }
            let t = if t == "." { qname } else { t.as_str() };
            let target = normalize_qname(t);
            let (block, lists) = self.trie.dn_lookup(&target, &stamp);
            if block {
                return Ok((target, self.names(&lists)));
            }
        }
        Err(format!("answers not in blocklist {stamp}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize() {
        assert_eq!(normalize_qname("WWW.Example.COM."), "www.example.com");
        assert_eq!(normalize_qname("."), ".");
        assert_eq!(normalize_qname(""), ".");
        assert_eq!(normalize_qname("Ünï.De."), "Ünï.De");
        assert!(blockable_qtype(65) && !blockable_qtype(16));
    }
}
