// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2025 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/gotrie@a2756ab2f6bd:trie/frozentrie.go
// Derived-From: celzero/gotrie@a2756ab2f6bd:trie/frozentrienode.go
// Derived-From: celzero/gotrie@a2756ab2f6bd:trie/build.go
// Derived-From: celzero/gotrie@a2756ab2f6bd:trie/commons.go (dupElems, subdomains)

//! The RethinkDNS on-device blocklist: a succinct (LOUDS-style) radix trie of reversed domain names whose
//! terminal nodes carry the ids of the blocklists that list the domain. `td.txt` holds the trie bits, `rd.txt` the
//! rank directory; both are memory-mapped, as firestack does (`trie.Fmmap`).

use crate::bits::{BinStr, L2, RankDir, W};
use crate::goenc::{self, Codec};
use crate::stamp::header_indices;
use md5::{Digest, Md5};
use memmap2::Mmap;
use parking_lot::Mutex;
use std::cell::Cell;
use std::collections::HashMap;
use std::path::Path;

const EXTRA_BIT: i64 = 1;
const BITSLEN: i64 = 9 + EXTRA_BIT;
/// "considerably greater than the observed max-size of a node in the radix-trie"
const MAXITERS: usize = 3000;
const CACHE_HI: usize = 2100;

pub struct FrozenTrie {
    data: BinStr<Mmap>,
    dir: BinStr<Mmap>,
    rank: RankDir,
    letter_start: i64,
    /// value -> uname
    rflags: HashMap<i64, String>,
    /// the last decoded user stamp and its unames
    usr: Mutex<(String, Vec<String>)>,
    /// domain -> unames of every list that has it (positive lookups only)
    bcache: Mutex<HashMap<String, Vec<String>>>,
}

/// Maps a blocklist file and returns its md5 (hex). The digest is computed with plain reads, not through the
/// mapping (gotrie hashes the mapping, which leaves the whole ~170 MB trie resident in the process): only the
/// pages that lookups touch become resident, and the kernel is told lookups are random (no read-ahead).
fn mmap(path: &Path) -> Result<(Mmap, String), String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).map_err(|e| format!("trie: {}: {e}", path.display()))?;
    let mut h = Md5::new();
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = f.read(&mut buf).map_err(|e| format!("trie: {}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    let md5 = h.finalize().iter().map(|x| format!("{x:02x}")).collect();
    // SAFETY: the blocklist files are written once by the app before they are handed to the engine and are
    // replaced by new files (new directory per timestamp), never modified in place.
    let m = unsafe { Mmap::map(&f) }.map_err(|e| format!("trie: mmap {}: {e}", path.display()))?;
    #[cfg(unix)]
    let _ = m.advise(memmap2::Advice::Random);
    Ok((m, md5))
}

/// gotrie `Build`: td, rd, basicconfig.json, filetag.json.
pub fn build(td: &Path, rd: &Path, bc: &Path, ft: &Path) -> Result<FrozenTrie, String> {
    let (td, tdmd5) = mmap(td)?;
    let (rd, rdmd5) = mmap(rd)?;
    let bconf: serde_json::Value = serde_json::from_slice(
        &std::fs::read(bc).map_err(|e| format!("trie: {}: {e}", bc.display()))?,
    )
    .map_err(|e| format!("trie: err reading basicconfig: {e}"))?;
    let nodecount = bconf
        .get("nodecount")
        .and_then(|v| v.as_f64())
        .ok_or("trie: basicconfig: no nodecount")? as i64;
    let want = |k: &str| {
        bconf
            .get(k)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    let (wtd, wrd) = (want("tdmd5"), want("rdmd5"));
    if tdmd5 != wtd || rdmd5 != wrd {
        return Err(format!(
            "trie: md5 mismatch: {tdmd5} <=> {wtd} | {rdmd5} <=> {wrd}"
        ));
    }
    let rflags = load_tag(ft)?;
    Ok(FrozenTrie {
        data: BinStr::new(td),
        dir: BinStr::new(rd),
        rank: RankDir::new(nodecount * 2 + 1, L2),
        letter_start: nodecount * 2 + 1,
        rflags,
        usr: Mutex::new((String::new(), Vec::new())),
        bcache: Mutex::new(HashMap::new()),
    })
}

/// gotrie `LoadTag`: value -> uname.
fn load_tag(path: &Path) -> Result<HashMap<i64, String>, String> {
    let data = std::fs::read(path).map_err(|e| format!("trie: loadtag read err: {e}"))?;
    let obj: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(&data).map_err(|e| format!("trie: loadtag json err: {e}"))?;
    if obj.is_empty() {
        return Err("trie: loadtag json err: trie: zero len blocklist json".into());
    }
    let mut out = HashMap::with_capacity(obj.len());
    for (k, v) in &obj {
        // gotrie type-asserts both fields (and panics when they are missing)
        let value = v.get("value").and_then(|x| x.as_f64());
        let uname = v.get("uname").and_then(|x| x.as_str());
        match (value, uname) {
            (Some(value), Some(uname)) => {
                out.insert(value as i64, uname.to_string());
            }
            _ => return Err(format!("trie: loadtag: bad entry {k}")),
        }
    }
    Ok(out)
}

/// A node, with gotrie's lazily cached child bounds.
struct Node {
    index: i64,
    fc: Cell<Option<i64>>,
    cn: Cell<Option<i64>>,
}

impl FrozenTrie {
    fn node(&self, index: i64) -> Node {
        Node {
            index,
            fc: Cell::new(None),
            cn: Cell::new(None),
        }
    }

    fn bit_at(&self, n: &Node) -> i64 {
        self.letter_start + n.index * BITSLEN
    }
    fn compressed(&self, n: &Node) -> bool {
        self.data.get(self.bit_at(n), 1) == 1
    }
    fn is_final(&self, n: &Node) -> bool {
        self.data.get(self.bit_at(n) + EXTRA_BIT, 1) == 1
    }
    fn letter(&self, n: &Node) -> u32 {
        self.data
            .get(self.bit_at(n) + 1 + EXTRA_BIT, BITSLEN - 1 - EXTRA_BIT)
    }
    fn flag(&self, n: &Node) -> bool {
        self.compressed(n) && self.is_final(n)
    }
    fn first_child(&self, n: &Node) -> i64 {
        if let Some(v) = n.fc.get() {
            return v;
        }
        let v = self.rank.rank(&self.dir, &self.data, n.index + 1) - n.index;
        n.fc.set(Some(v));
        v
    }
    fn child_of_next_node(&self, n: &Node) -> i64 {
        if let Some(v) = n.cn.get() {
            return v;
        }
        let v = self.rank.rank(&self.dir, &self.data, n.index + 2) - n.index - 1;
        n.cn.set(Some(v));
        v
    }
    fn child_count(&self, n: &Node) -> i64 {
        self.child_of_next_node(n) - self.first_child(n)
    }
    fn child(&self, n: &Node, i: i64) -> Node {
        self.node(self.first_child(n) + i)
    }

    /// Blocklist-id words stored under a terminal node (pairs of flag children make one u16).
    fn value(&self, n: &Node) -> Vec<u32> {
        let mut value: Vec<u32> = Vec::new();
        let mut i = 0;
        let mut j = 0;
        while i < self.child_count(n) {
            let vc = self.child(n, i);
            if !self.flag(&vc) {
                break;
            }
            if i % 2 == 0 {
                value.push(self.letter(&vc) << 8);
            } else {
                value[j] |= self.letter(&vc);
                j += 1;
            }
            i += 1;
        }
        value
    }

    /// gotrie `lookup`: `word` is the domain, byte-reversed.
    pub fn lookup(&self, word: &[u8]) -> (bool, Vec<u32>) {
        let mut node = self.node(0);
        let mut i = 0usize;
        while i < word.len() {
            let mut is_flag: i64 = -1;
            loop {
                let that = self.child(&node, is_flag + 1);
                if !self.flag(&that) {
                    break;
                }
                is_flag += 1;
                if is_flag + 1 >= self.child_count(&node) {
                    break;
                }
            }
            let min_child = is_flag;
            if self.child_count(&node) - 1 <= min_child {
                return (false, vec![]);
            }
            let mut high = self.child_count(&node);
            let mut low = is_flag;
            let mut child: Option<Node> = None;
            while high - low > 1 {
                let probe = (high + low) / 2;
                let c = self.child(&node, probe);
                let prev = if probe > is_flag {
                    Some(self.child(&node, probe - 1))
                } else {
                    None
                };
                let prev_open = prev
                    .as_ref()
                    .is_some_and(|p| self.compressed(p) && !self.flag(p));
                if self.compressed(&c) || prev_open {
                    let c_compressed = self.compressed(&c);
                    let mut startchild = vec![c];
                    let mut start: i64 = 1;
                    let mut k = 0;
                    loop {
                        if k >= MAXITERS {
                            return (false, vec![]);
                        }
                        let temp = self.child(&node, probe - start);
                        if !self.compressed(&temp) || self.flag(&temp) {
                            break;
                        }
                        startchild.push(temp);
                        start += 1;
                        k += 1;
                    }
                    let first = self.letter(&startchild[start as usize - 1]) as u8;
                    if first > word[i] {
                        high = probe - start + 1;
                        if high - low <= 1 {
                            return (false, vec![]);
                        }
                        child = startchild.into_iter().next();
                        continue;
                    }
                    let mut endchild = Vec::new();
                    let mut end: i64 = 0;
                    if c_compressed {
                        let mut k = 0;
                        loop {
                            if k >= MAXITERS {
                                return (false, vec![]);
                            }
                            end += 1;
                            let temp = self.child(&node, probe + end);
                            let more = self.compressed(&temp);
                            endchild.push(temp);
                            if !more {
                                break;
                            }
                            k += 1;
                        }
                    }
                    if first < word[i] {
                        low = probe + end;
                        if high - low <= 1 {
                            return (false, vec![]);
                        }
                        child = startchild.into_iter().next();
                        continue;
                    }
                    startchild.reverse();
                    let mut nodes = startchild;
                    nodes.extend(endchild);
                    let comp: Vec<u8> = nodes.iter().map(|n| self.letter(n) as u8).collect();
                    let sliceend = (i + comp.len()).min(word.len());
                    let w = &word[i..sliceend];
                    if w.len() < comp.len() || w != comp.as_slice() {
                        return (false, vec![]);
                    }
                    i += comp.len() - 1;
                    child = nodes.pop();
                    break;
                } else {
                    let l = self.letter(&c) as u8;
                    if l == word[i] {
                        child = Some(c);
                        break;
                    } else if word[i] > l {
                        low = probe;
                    } else {
                        high = probe;
                    }
                    child = Some(c);
                }
                if high - low <= 1 {
                    return (false, vec![]);
                }
            }
            match child {
                None => return (false, vec![]),
                Some(c) => node = c,
            }
            i += 1;
        }
        if self.is_final(&node) {
            return (true, self.value(&node));
        }
        (false, vec![])
    }

    /// gotrie `FlagstoTag` (exported variant): blocklist-id words → unames; empty on a header mismatch.
    pub fn flags_to_tag(&self, flags: &[u32]) -> Vec<String> {
        let mut values = Vec::new();
        if self.rflags.is_empty() || flags.is_empty() {
            return values;
        }
        let tag_indices = header_indices(flags[0] as u16);
        if tag_indices.len() != flags.len() - 1 {
            return values; // "flags and header mismatch (bug in upsert?)"
        }
        for (i, &f) in flags.iter().enumerate().skip(1) {
            self.collect_tags(f as u16, tag_indices[i - 1], &mut values, true);
        }
        values
    }

    fn collect_tags(&self, flag: u16, index: usize, values: &mut Vec<String>, skip_empty: bool) {
        let mut mask: u16 = 0x8000;
        for j in 0..16 {
            if flag << j == 0 {
                break;
            }
            if flag & mask == mask {
                let pos = (index * 16 + j) as i64;
                if (pos as usize) < self.rflags.len() {
                    let v = self.rflags.get(&pos).cloned().unwrap_or_default();
                    if !skip_empty || !v.is_empty() {
                        values.push(v);
                    }
                }
            }
            mask >>= 1;
        }
    }

    /// gotrie `decode` + `flagstotag`: a user stamp (`ver:data`, or a bare legacy stamp) → unames.
    fn decode_stamp(&self, usr_flag: &str) -> Result<Vec<String>, String> {
        let s: Vec<&str> = usr_flag.split(':').collect();
        let (stamp, ver) = if s.len() > 1 {
            (s[1], s[0])
        } else {
            (usr_flag, "0")
        };
        let (text, codec) = match ver {
            "0" => (goenc::unescape(stamp, true)?, Codec::Std),
            "1" => (goenc::unescape(stamp, false)?, Codec::Url),
            _ => return Err(format!("trie: version does not exist: {ver}")),
        };
        let text = String::from_utf8(text).map_err(|_| "trie: illegal base64 data")?;
        let buf = codec.decode(&text)?;
        let flags = if ver == "0" {
            goenc::runes_u16(&buf)
        } else {
            goenc::le_u16(&buf)
        };
        if flags.is_empty() {
            return Err("trie: flagstotag: zero len flags".into());
        }
        if self.rflags.is_empty() {
            return Err("trie: flagstotag: unexpected zero len blocklist".into());
        }
        let tag_indices = header_indices(flags[0]);
        if tag_indices.len() != flags.len() - 1 {
            return Err("trie: flagstotag: flags and header mismatch".into());
        }
        let mut values = Vec::new();
        for (i, &f) in flags.iter().enumerate().skip(1) {
            self.collect_tags(f, tag_indices[i - 1], &mut values, false);
        }
        Ok(values)
    }

    /// gotrie `DNlookup`: is `dn` (or any parent domain) in a blocklist selected by `usr_flag`? Returns the unames
    /// of the matching selected lists.
    pub fn dn_lookup(&self, dn: &str, usr_flag: &str) -> (bool, Vec<String>) {
        let usr = {
            let mut u = self.usr.lock();
            if u.0.is_empty() || u.0 != usr_flag {
                match self.decode_stamp(usr_flag) {
                    Ok(b) => *u = (usr_flag.to_string(), b),
                    Err(_) => {
                        *u = (String::new(), Vec::new());
                        return (false, Vec::new());
                    }
                }
            }
            u.1.clone()
        };
        let (block, lists) = self.lookup_domain(dn, &usr);
        if block {
            return (block, lists);
        }
        for d in subdomains(dn) {
            let (block, lists) = self.lookup_domain(d, &usr);
            if block {
                return (block, lists);
            }
        }
        (false, Vec::new())
    }

    fn lookup_domain(&self, dn: &str, usr: &[String]) -> (bool, Vec<String>) {
        let dn = dn.trim();
        if let Some(tags) = self.bcache.lock().get(dn) {
            return dup_elems(usr, tags);
        }
        let word: Vec<u8> = dn.bytes().rev().collect();
        let (status, arr) = self.lookup(&word);
        if status && !arr.is_empty() {
            let tags = self.flags_to_tag(&arr);
            let r = dup_elems(usr, &tags);
            if !tags.is_empty() {
                let mut c = self.bcache.lock();
                if c.len() >= CACHE_HI {
                    c.clear();
                }
                c.insert(dn.to_string(), tags);
            }
            return r;
        }
        (false, Vec::new())
    }

    /// Size of the mapped trie and rank directory, in bytes.
    pub fn mapped_bytes(&self) -> usize {
        self.data.as_bytes().len() + self.dir.as_bytes().len()
    }
}

/// `b.c.tld`, `c.tld`, `tld` for `a.b.c.tld`.
fn subdomains(target: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut t = target;
    for _ in 0..target.matches('.').count() {
        let s = t.find('.').map(|i| i + 1).unwrap_or(0);
        t = &t[s..];
        out.push(t);
    }
    out
}

/// gotrie `dupElems`: elements of `list1` (non-empty, in order) that occur in `list2`, once per occurrence.
fn dup_elems(list1: &[String], list2: &[String]) -> (bool, Vec<String>) {
    let mut ret = Vec::new();
    if list1.is_empty() || list2.is_empty() {
        return (false, ret);
    }
    for v in list1 {
        if v.is_empty() {
            continue;
        }
        for iv in list2 {
            if v == iv {
                ret.push(v.clone());
            }
        }
    }
    (!ret.is_empty(), ret)
}

const _: () = assert!(W == 16);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(subdomains("a.b.c.tld"), vec!["b.c.tld", "c.tld", "tld"]);
        assert!(subdomains("tld").is_empty());
        assert_eq!(subdomains("a..b"), vec![".b", "b"]);
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(
            dup_elems(&s(&["A", "", "B"]), &s(&["B", "A", "B", ""])),
            (true, s(&["A", "B", "B"]))
        );
        assert_eq!(dup_elems(&s(&["A"]), &s(&["C"])), (false, vec![]));
    }
}
