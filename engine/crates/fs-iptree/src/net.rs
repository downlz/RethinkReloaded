// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
// Copyright (c) 2015 Keita Sone (critbitgo), MIT License: see engine/LICENSES/MIT-critbitgo.txt
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: github.com/k-sone/critbitgo@v1.4.0:net.go
// Derived-From: celzero/firestack@d3d530ea3e:intra/core/ip.go (IP2Cidr)

//! IP routes on top of the crit-bit trie, as critbitgo's `Net`: keys are the (IPv4-normalised) address bytes
//! followed by one prefix-length byte. Also Go's `net.ParseCIDR` / `netip.ParseAddr(Port)` / `IPNet.String`
//! semantics needed by firestack's `IP2Cidr`.

use crate::critbit::{Node, Trie};
use std::net::{IpAddr, Ipv6Addr};

/// Go `*net.IPNet` as used by firestack: raw address bytes (4 or 16) and the mask's prefix length.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpNet {
    pub ip: Vec<u8>,
    pub ones: u8,
}

impl IpNet {
    /// Go `IP.To4() != nil`
    pub fn is_v4(&self) -> bool {
        to4(&self.ip).is_some()
    }
}

/// Go `net.IP.To4`: 4-byte form of an IPv4 or IPv4-mapped IPv6 address.
pub fn to4(ip: &[u8]) -> Option<&[u8]> {
    match ip.len() {
        4 => Some(ip),
        16 if ip[..10].iter().all(|&b| b == 0) && ip[10] == 0xff && ip[11] == 0xff => {
            Some(&ip[12..])
        }
        _ => None,
    }
}

/// critbitgo `netValidateIP`
fn validate_ip(ip: &[u8]) -> Option<Vec<u8>> {
    if let Some(v4) = to4(ip) {
        Some(v4.to_vec())
    } else if ip.len() == 16 {
        Some(ip.to_vec())
    } else {
        None
    }
}

fn key_of(ip: &[u8], ones: u8) -> Vec<u8> {
    let mut k = ip.to_vec();
    k.push(ones);
    k
}

/// Go `IPNet.String()` for a critbitgo key (`netKeyToIPNet(k).String()`).
pub fn key_to_string(k: &[u8]) -> String {
    let iplen = k.len() - 1;
    let ones = k[iplen] as usize;
    if ones > iplen * 8 {
        return "<nil>".into(); // CIDRMask returns nil; Go prints "<nil>"
    }
    format!("{}/{}", ip_string(&k[..iplen]), ones)
}

/// Go `net.IP.String()`.
pub fn ip_string(ip: &[u8]) -> String {
    if let Some(v4) = to4(ip) {
        return format!("{}.{}.{}.{}", v4[0], v4[1], v4[2], v4[3]);
    }
    if ip.len() != 16 {
        return "?".into();
    }
    // RFC 5952 as Go does it: compress the first longest run (>= 2) of zero groups; lowercase hex.
    let g: Vec<u16> = ip
        .chunks(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    let (mut best_s, mut best_l) = (usize::MAX, 0usize);
    let mut i = 0;
    while i < 8 {
        if g[i] == 0 {
            let s = i;
            while i < 8 && g[i] == 0 {
                i += 1;
            }
            if i - s >= 2 && i - s > best_l {
                best_s = s;
                best_l = i - s;
            }
        } else {
            i += 1;
        }
    }
    let mut out = String::new();
    let mut i = 0;
    while i < 8 {
        if i == best_s {
            out.push_str("::");
            i += best_l;
            continue;
        }
        if !out.is_empty() && !out.ends_with(':') {
            out.push(':');
        }
        out.push_str(&format!("{:x}", g[i]));
        i += 1;
    }
    out
}

// ---------------------------------------------------------------- parsing (Go semantics)

/// Go's `dtoi` + range check, as used by `net.ParseCIDR` for the prefix length.
fn parse_prefix_len(s: &str, bits: usize) -> Option<u8> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut n: usize = 0;
    for b in s.bytes() {
        n = n * 10 + (b - b'0') as usize;
        if n >= 0xFF_FFFF {
            return None;
        }
    }
    (n <= bits).then_some(n as u8)
}

fn mask_bytes(ip: &mut [u8], ones: u8) {
    let ones = ones as usize;
    for (i, b) in ip.iter_mut().enumerate() {
        let bit = i * 8;
        if bit >= ones {
            *b = 0;
        } else if ones - bit < 8 {
            *b &= 0xffu8 << (8 - (ones - bit));
        }
    }
}

/// Go `net.ParseCIDR` (go1.22+: netip-based, zones rejected). Returns the masked network.
pub fn parse_cidr(s: &str) -> Option<IpNet> {
    let (addr, mask) = s.split_once('/')?;
    if addr.contains('%') {
        return None;
    }
    let ip: IpAddr = addr.parse().ok()?;
    let (mut bytes, bits) = match ip {
        IpAddr::V4(v4) => (v4.octets().to_vec(), 32),
        IpAddr::V6(v6) => (v6.octets().to_vec(), 128),
    };
    let ones = parse_prefix_len(mask, bits)?;
    mask_bytes(&mut bytes, ones);
    Some(IpNet { ip: bytes, ones })
}

/// Go `netip.ParseAddr` (zones accepted and dropped by `AsSlice`).
fn parse_addr(s: &str) -> Option<IpAddr> {
    if let Some((a, zone)) = s.split_once('%') {
        if zone.is_empty() || !a.contains(':') {
            return None;
        }
        return a.parse::<Ipv6Addr>().ok().map(IpAddr::V6);
    }
    s.parse().ok()
}

/// Go `netip.ParseAddrPort`.
fn parse_addr_port(s: &str) -> Option<IpAddr> {
    let i = s.rfind(':')?;
    let (host, port) = (&s[..i], &s[i + 1..]);
    if port.is_empty()
        || !port.bytes().all(|b| b.is_ascii_digit())
        || port.parse::<u32>().ok()? > 65535
    {
        return None;
    }
    if let Some(inner) = host.strip_prefix('[') {
        let inner = inner.strip_suffix(']')?;
        match parse_addr(inner)? {
            IpAddr::V4(_) => None, // v4 in brackets is invalid
            v6 => Some(v6),
        }
    } else {
        match parse_addr(host)? {
            IpAddr::V6(_) => None, // v6 without brackets is invalid
            v4 => Some(v4),
        }
    }
}

/// firestack `core.IP2Cidr`: a CIDR, or an `ip:port` / `ip` turned into a host route (unspecified -> /0).
pub fn ip2cidr(s: &str) -> Result<IpNet, String> {
    if let Some(n) = parse_cidr(s) {
        return Ok(n);
    }
    let addr = parse_addr_port(s)
        .or_else(|| parse_addr(s))
        .ok_or_else(|| format!("ip2cidr: errs: {s}"))?;
    let (ip, bits) = match addr {
        IpAddr::V4(v4) => (v4.octets().to_vec(), 32u8),
        IpAddr::V6(v6) => (v6.octets().to_vec(), 128u8),
    };
    let ones = if addr.is_unspecified() { 0 } else { bits };
    Ok(IpNet { ip, ones })
}

// ---------------------------------------------------------------- critbitgo Net

/// critbitgo `Net`.
#[derive(Default)]
pub struct Net {
    trie: Trie<String>,
}

impl Net {
    pub fn add(&mut self, r: &IpNet, v: String) -> Result<(), String> {
        let ip = validate_ip(&r.ip).ok_or("Invalid IP address")?;
        self.trie.set(&key_of(&ip, r.ones), v);
        Ok(())
    }

    pub fn delete(&mut self, r: &IpNet) -> Option<String> {
        let ip = validate_ip(&r.ip)?;
        self.trie.delete(&key_of(&ip, r.ones))
    }

    pub fn get(&self, r: &IpNet) -> Option<String> {
        let ip = validate_ip(&r.ip)?;
        self.trie.get(&key_of(&ip, r.ones))
    }

    /// critbitgo `Match`: the longest-matching route (key) and its value.
    pub fn match_route(&self, r: &IpNet) -> Option<(Vec<u8>, String)> {
        let ip = validate_ip(&r.ip)?;
        if self.trie.is_empty() {
            return None;
        }
        let key = key_of(&ip, r.ones);
        lookup(&self.trie.root, &key, false).map(|(k, v)| (k.to_vec(), v.clone()))
    }

    /// critbitgo `WalkMatch`: every route matching `r` in trie order. Note: uses `r.ip` as-is (not IPv4-normalised).
    pub fn walk_match(&self, r: &IpNet, handle: &mut dyn FnMut(&[u8], &String) -> bool) {
        if !self.trie.is_empty() {
            walk_match(&self.trie.root, &key_of(&r.ip, r.ones), handle);
        }
    }

    pub fn clear(&mut self) {
        self.trie.clear();
    }

    pub fn len(&self) -> usize {
        self.trie.len()
    }

    pub fn is_empty(&self) -> bool {
        self.trie.is_empty()
    }
}

/// Does external route key `e` cover query key `key`? (critbitgo's leaf test). Go indexes out of range (panics)
/// for malformed mixes of key lengths; those cases are treated as "no match" here.
fn covers(e: &[u8], key: &[u8]) -> bool {
    let mask = e[e.len() - 1];
    if key[key.len() - 1] < mask {
        return false;
    }
    let div = (mask >> 3) as usize;
    if div > e.len() || div > key.len() {
        return false;
    }
    if e[..div] != key[..div] {
        return false;
    }
    let m = mask & 0x07;
    if m > 0 {
        let bit = 8 - m;
        if div >= e.len() || div >= key.len() {
            return false;
        }
        if e[div] != key[div] & (0xffu8 >> bit << bit) {
            return false;
        }
    }
    true
}

fn lookup<'a>(
    p: &'a Node<String>,
    key: &[u8],
    backtracking: bool,
) -> Option<(&'a [u8], &'a String)> {
    match p {
        Node::Internal(i) => {
            let direction = if i.offset + 1 == key.len() {
                1
            } else if backtracking {
                0
            } else {
                i.direction(key)
            };
            if let Some(c) = lookup(&i.child[direction], key, backtracking) {
                return Some(c);
            }
            if direction == 1 {
                lookup(&i.child[0], key, true)
            } else {
                None
            }
        }
        Node::External(e) => {
            if e.key.len() != key.len() || !covers(&e.key, key) {
                return None;
            }
            Some((&e.key, &e.value))
        }
        Node::Empty => None,
    }
}

fn walk_match(
    p: &Node<String>,
    key: &[u8],
    handle: &mut dyn FnMut(&[u8], &String) -> bool,
) -> bool {
    match p {
        Node::Internal(i) => {
            if !walk_match(&i.child[0], key, handle) {
                return false;
            }
            if i.offset + 1 >= key.len() || (i.offset < key.len() && key[i.offset] & i.bit > 0) {
                return walk_match(&i.child[1], key, handle);
            }
            true
        }
        Node::External(e) => {
            if !covers(&e.key, key) {
                return true;
            }
            handle(&e.key, &e.value)
        }
        Node::Empty => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsing_matches_go() {
        assert_eq!(
            ip2cidr("10.1.2.3/8").unwrap(),
            IpNet {
                ip: vec![10, 0, 0, 0],
                ones: 8
            }
        );
        assert_eq!(
            ip2cidr("10.1.2.3").unwrap(),
            IpNet {
                ip: vec![10, 1, 2, 3],
                ones: 32
            }
        );
        assert_eq!(ip2cidr("10.1.2.3:443").unwrap().ones, 32);
        assert_eq!(ip2cidr("0.0.0.0").unwrap().ones, 0);
        assert_eq!(ip2cidr("::").unwrap().ones, 0);
        assert_eq!(ip2cidr("[2001:db8::1]:53").unwrap().ones, 128);
        assert_eq!(ip2cidr("fe80::1%wlan0").unwrap().ones, 128);
        // ParseCIDR rejects zones, but netip.ParseAddr accepts any non-empty zone: Go yields a /128 host route
        assert_eq!(ip2cidr("fe80::1%wlan0/64").unwrap().ones, 128);
        assert!(ip2cidr("10.0.0.1/33").is_err());
        assert!(ip2cidr("010.0.0.1").is_err());
        assert!(ip2cidr("2001:db8::1:53").unwrap().ip.len() == 16); // parsed as a plain v6 address
        assert_eq!(ip2cidr("10.0.0.0/08").unwrap().ones, 8); // Go's dtoi accepts leading zeros
        assert!(ip2cidr("::ffff:1.2.3.4").unwrap().is_v4());
    }

    #[test]
    fn go_ip_strings() {
        assert_eq!(
            ip_string(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets()),
            "2001:db8::1"
        );
        assert_eq!(
            ip_string(&"::1.2.3.4".parse::<Ipv6Addr>().unwrap().octets()),
            "::102:304"
        );
        assert_eq!(
            ip_string(&"2001:0:0:1:0:0:0:1".parse::<Ipv6Addr>().unwrap().octets()),
            "2001:0:0:1::1"
        );
        assert_eq!(
            ip_string(&"1:0:2:0:3:0:4:0".parse::<Ipv6Addr>().unwrap().octets()),
            "1:0:2:0:3:0:4:0"
        );
        assert_eq!(ip_string(&[0u8; 16]), "::");
        assert_eq!(key_to_string(&[1, 2, 3, 0, 120]), "<nil>");
    }

    #[test]
    fn match_and_walk() {
        let mut n = Net::default();
        for (c, v) in [
            ("10.0.0.0/8", "a"),
            ("10.1.0.0/16", "b"),
            ("10.1.2.0/24", "c"),
            ("192.168.0.0/16", "d"),
        ] {
            n.add(&ip2cidr(c).unwrap(), v.into()).unwrap();
        }
        let q = ip2cidr("10.1.2.3").unwrap();
        let (k, v) = n.match_route(&q).unwrap();
        assert_eq!(
            (key_to_string(&k), v.as_str()),
            ("10.1.2.0/24".to_string(), "c")
        );
        let mut seen = vec![];
        n.walk_match(&q, &mut |k, v| {
            seen.push(format!("{}={v}", key_to_string(k)));
            true
        });
        assert_eq!(seen, ["10.0.0.0/8=a", "10.1.0.0/16=b", "10.1.2.0/24=c"]);
        assert!(n.match_route(&ip2cidr("11.0.0.1").unwrap()).is_none());
    }
}
