// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/x64/natpt.go
// Derived-From: celzero/firestack@d3d530ea3e:intra/x64/dns64.go
// Derived-From: celzero/firestack@d3d530ea3e:intra/x64/nat64.go
// Derived-From: celzero/firestack@d3d530ea3e:intra/xdns/dnsutil.go (MaybeToQuadA, ip4to6, Request4FromResponse6)

//! DNS64 / NAT64 (firestack `natPt`). Each resolver's NAT64 prefixes come from its answer to `ipv4only.arpa AAAA`
//! (RFC 7050); `System` maps to the underlay (the network's, also settable), `Goos` to the stdlib resolver, and the
//! engine's own local 464 prefix `64:ff9b:1:fffe::/96` is always there as the last resort. AAAA questions that get
//! no AAAA answer are answered from the name's A records under the resolver's prefix (or a fallback's); flows to
//! the local prefix are dialed over IPv4 (`X64`), and IPv4 targets can be reached through the network's NAT64
//! (`X46`). Active per the PT mode: off for `none`, on for `auto` only when the network has IPv6.

use fs_core::settings;
use fs_dns::msg;
use hickory_proto::op::Message;
use hickory_proto::rr::{RData, Record, RecordType};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};

pub const RFC7050_WKN: &str = "ipv4only.arpa.";
pub const ANY_RESOLVER: &str = "__anyresolver";
pub const UNDERLAY: &str = "__underlay";
pub const STDLIB: &str = "__stdlib";
pub const LOCAL464: &str = "__local464";
const WKA1: [u8; 4] = [192, 0, 0, 170];
const WKA2: [u8; 4] = [192, 0, 0, 171];
/// xdns `ansTTL`: synthesized records live at least this long (0 in firestack's build, as `msg::ANS_TTL`)
const ANS_TTL: u32 = msg::ANS_TTL;

/// An IPv6 prefix (address with the host bits zeroed, and its length in bits).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prefix {
    pub ip: Ipv6Addr,
    pub bits: u8,
}

impl Prefix {
    pub fn contains(&self, ip: Ipv6Addr) -> bool {
        let (a, b) = (u128::from(self.ip), u128::from(ip));
        let mask = if self.bits == 0 {
            0
        } else {
            u128::MAX << (128 - self.bits as u32)
        };
        a & mask == b & mask
    }
    pub fn parse(s: &str) -> Option<Prefix> {
        let (ip, bits) = s.split_once('/')?;
        let bits: u8 = bits.parse().ok().filter(|b| *b <= 128)?;
        let ip: Ipv6Addr = ip.parse().ok()?;
        let mask = if bits == 0 {
            0
        } else {
            u128::MAX << (128 - bits as u32)
        };
        Some(Prefix {
            ip: Ipv6Addr::from(u128::from(ip) & mask),
            bits,
        })
    }
}

impl std::fmt::Display for Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.ip, self.bits)
    }
}

/// x64 `ip4to6` (X46): the prefix's bytes, then the IPv4 address right after the prefix (no byte-8 gap, as firestack).
pub fn x46(p: &Prefix, ip4: Ipv4Addr) -> Option<Ipv6Addr> {
    if ip4.is_unspecified() {
        return Some(Ipv6Addr::UNSPECIFIED);
    }
    let start = p.bits as usize / 8;
    if start + 4 > 16 {
        return None;
    }
    let mut b = p.ip.octets();
    b[start..start + 4].copy_from_slice(&ip4.octets());
    Some(Ipv6Addr::from(b))
}

/// xdns `ip4to6` (DNS64 synthesis): RFC 6052 placement, skipping byte 8.
pub fn synth6(p: &Prefix, ip4: Ipv4Addr) -> Ipv6Addr {
    let mut b = p.ip.octets();
    let mut shift = p.bits as usize / 8;
    for (i, x) in ip4.octets().into_iter().enumerate() {
        if shift + i == 8 {
            shift += 1;
        }
        if shift + i < 16 {
            b[shift + i] = x;
        }
    }
    Ipv6Addr::from(b)
}

/// x64 `ip6to4` (X64): RFC 6052 extraction, skipping byte 8 (with firestack's index arithmetic).
pub fn x64(p: &Prefix, ip6: Ipv6Addr) -> Option<Ipv4Addr> {
    if ip6.is_unspecified() {
        return Some(Ipv4Addr::UNSPECIFIED);
    }
    let b = ip6.octets();
    let mut start = p.bits as usize / 8;
    if start + 4 > 16 {
        return None;
    }
    let mut out = [0u8; 4];
    for (i, o) in out.iter_mut().enumerate() {
        if start + i == 8 {
            start += 1;
        }
        *o = *b.get(start + i)?;
    }
    Some(Ipv4Addr::from(out))
}

/// dns64 `add`: prefixes from `ipv4only.arpa` AAAA answers, by where the well-known address sits.
pub fn prefixes_of(answers: &[Ipv6Addr]) -> Vec<Prefix> {
    let mut out: Vec<Prefix> = Vec::new();
    for ip in answers {
        let b = ip.octets();
        let at = |i: [usize; 4]| {
            let w = [b[i[0]], b[i[1]], b[i[2]], b[i[3]]];
            w == WKA1 || w == WKA2
        };
        let end = if at([12, 13, 14, 15]) {
            12
        } else if at([9, 10, 11, 12]) {
            8
        } else if at([7, 9, 10, 11]) {
            7
        } else if at([6, 7, 9, 10]) {
            6
        } else if at([5, 6, 7, 9]) {
            5
        } else if at([4, 5, 6, 7]) {
            4
        } else {
            continue;
        };
        let mut p = [0u8; 16];
        p[..end].copy_from_slice(&b[..end]);
        let pfx = Prefix {
            ip: Ipv6Addr::from(p),
            bits: (end * 8) as u8,
        };
        if pfx.ip.is_unspecified() {
            continue; // IsZeroPrefix
        }
        if !out.contains(&pfx) {
            out.push(pfx);
        }
    }
    out
}

fn id64(tid: &str) -> &str {
    match tid {
        fs_dns::ids::SYSTEM => UNDERLAY,
        fs_dns::ids::GOOS => STDLIB,
        _ => tid,
    }
}

/// firestack `natPt` (dns64 + nat64).
pub struct NatPt {
    prefixes: RwLock<HashMap<String, Vec<Prefix>>>,
    /// does the network have IPv6? (PT mode `auto` is active only then)
    has6: AtomicBool,
}

impl Default for NatPt {
    fn default() -> Self {
        let n = NatPt {
            prefixes: RwLock::new(HashMap::new()),
            has6: AtomicBool::new(false),
        };
        n.prefixes.write().insert(
            LOCAL464.into(),
            vec![Prefix::parse("64:ff9b:1:fffe::/96").unwrap()],
        );
        n
    }
}

impl NatPt {
    /// The link's families changed (`setLinkAndRoutes`).
    pub fn set_has6(&self, y: bool) {
        self.has6.store(y, Ordering::Relaxed);
    }

    /// dns64 `pauseOrResume`: synthesis is off for PT mode `none`, and for `auto` on IPv4-only networks.
    pub fn active(&self) -> bool {
        match settings::PT_MODE.load(Ordering::Relaxed) {
            settings::PT_MODE_NONE => false,
            settings::PT_MODE_AUTO => self.has6.load(Ordering::Relaxed),
            _ => true,
        }
    }

    pub fn get(&self, id: &str) -> Vec<Prefix> {
        self.prefixes
            .read()
            .get(id64(id))
            .cloned()
            .unwrap_or_default()
    }

    /// Registers resolver `id`'s answer to `ipv4only.arpa AAAA` (`Add64`); false when it carries no prefix.
    pub fn add_resolver(&self, id: &str, answers: &[Ipv6Addr]) -> bool {
        let p = prefixes_of(answers);
        let ok = !p.is_empty();
        let mut m = self.prefixes.write();
        if ok {
            m.insert(id64(id).to_string(), p);
        } else {
            m.remove(id64(id));
        }
        ok
    }

    /// `Remove64` (the local prefix stays).
    pub fn remove_resolver(&self, id: &str) {
        let id = id64(id);
        if id != LOCAL464 {
            self.prefixes.write().remove(id);
        }
    }

    /// `ResetNat64Prefix`: the network's NAT64 prefix (underlay).
    pub fn reset_nat64_prefix(&self, p: &str) -> bool {
        match Prefix::parse(p) {
            Some(x) if !x.ip.is_unspecified() => {
                self.prefixes.write().insert(UNDERLAY.into(), vec![x]);
                true
            }
            _ => false,
        }
    }

    /// `IsNat64`: is `ip` under one of `id`'s prefixes?
    pub fn is_nat64(&self, id: &str, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V6(v6) => self.get(id).iter().any(|p| p.contains(v6)),
            IpAddr::V4(_) => false,
        }
    }

    /// `X64`: the IPv4 address `ip6` encodes under `id`'s prefixes (any resolver's for [`ANY_RESOLVER`]).
    pub fn x64(&self, id: &str, ip6: Ipv6Addr) -> Option<Ipv4Addr> {
        if ip6.is_unspecified() {
            return Some(Ipv4Addr::UNSPECIFIED); // blocked answers stay blocked
        }
        let all: Vec<Prefix> = if id == ANY_RESOLVER {
            self.prefixes.read().values().flatten().copied().collect()
        } else {
            self.get(id)
        };
        all.iter()
            .find(|p| p.contains(ip6))
            .and_then(|p| x64(p, ip6))
    }

    /// `X46`: `ip4` under `id`'s first prefix.
    pub fn x46(&self, id: &str, ip4: Ipv4Addr) -> Option<Ipv6Addr> {
        if ip4.is_unspecified() {
            return Some(Ipv6Addr::UNSPECIFIED);
        }
        self.get(id).first().and_then(|p| x46(p, ip4))
    }

    /// The prefixes to synthesize under for resolver `id`: its own, else the underlay's, the stdlib's, the local one.
    fn synth_prefixes(&self, id: &str) -> Vec<Prefix> {
        [id64(id), UNDERLAY, STDLIB, LOCAL464]
            .iter()
            .map(|x| self.get(x))
            .find(|p| !p.is_empty())
            .unwrap_or_default()
    }

    /// dns64 `eval` (decision half): should `ans6` (an answer to an AAAA question) be replaced by a synthesized one?
    pub fn wants64(&self, ans6: &Message) -> bool {
        if !self.active() {
            return false;
        }
        let force = matches!(
            settings::PT_MODE.load(Ordering::Relaxed),
            settings::PT_MODE_FORCE64 | settings::PT_MODE_FORCE
        );
        let q6 = msg::qtype(ans6) == u16::from(RecordType::AAAA);
        let has6 = !msg::aaaa_answers(ans6).is_empty();
        let auth = ans6.metadata.authentic_data;
        let unspecified = msg::aquada_unspecified(ans6);
        q6 && !((auth || has6) && !force) && !unspecified
    }

    /// dns64 `eval` (synthesis half): an AAAA answer from the A answer `ans4` to the same name, under resolver
    /// `id`'s prefixes (or a fallback's); `None` when nothing could be translated.
    #[allow(clippy::unnecessary_min_or_max)] // ANS_TTL is 0 in this build; kept for parity with firestack's ansTTL
    pub fn synthesize(&self, id: &str, ans6: &Message, ans4: &Message) -> Option<Message> {
        if ans4.answers.is_empty() || msg::aquada_unspecified(ans4) {
            return None;
        }
        let prefixes = self.synth_prefixes(id);
        let mut out = msg::empty_response(ans6);
        out.metadata.response_code = ans4.metadata.response_code;
        let mut translated = false;
        for rr in &ans4.answers {
            match &rr.data {
                RData::A(a) => {
                    for p in &prefixes {
                        let v6 = synth6(p, a.0);
                        if v6.is_unspecified() {
                            continue;
                        }
                        let mut r = Record::from_rdata(
                            rr.name.clone(),
                            rr.ttl.max(ANS_TTL),
                            RData::AAAA(v6.into()),
                        );
                        r.dns_class = rr.dns_class;
                        out.answers.push(r);
                        translated = true;
                    }
                }
                _ => out.answers.push(rr.clone()), // CNAMEs and the like, as is
            }
        }
        translated.then_some(out)
    }

    /// xdns `Request4FromResponse6`: the A question for `ans6`'s name.
    pub fn request4(ans6: &Message) -> Option<Message> {
        let name = ans6.queries.first()?.name().to_ascii();
        msg::query(&name, RecordType::A, ans6.metadata.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local464_roundtrip() {
        let n = NatPt::default();
        let p = n.get(LOCAL464)[0];
        assert_eq!(p.to_string(), "64:ff9b:1:fffe::/96");
        let v6 = synth6(&p, Ipv4Addr::new(93, 184, 216, 34));
        assert_eq!(v6.to_string(), "64:ff9b:1:fffe::5db8:d822");
        assert!(n.is_nat64(LOCAL464, v6.into()));
        assert_eq!(n.x64(LOCAL464, v6), Some(Ipv4Addr::new(93, 184, 216, 34)));
        assert_eq!(
            n.x64(ANY_RESOLVER, v6),
            Some(Ipv4Addr::new(93, 184, 216, 34))
        );
        assert!(n.reset_nat64_prefix("64:ff9b::/96"));
        assert_eq!(
            n.x46(fs_dns::ids::SYSTEM, Ipv4Addr::new(1, 2, 3, 4))
                .unwrap()
                .to_string(),
            "64:ff9b::102:304"
        );
    }
}
