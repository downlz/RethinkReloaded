// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/xdns/dnsutil.go
// Derived-From: celzero/firestack@d3d530ea3e:intra/xdns/common.go

//! DNS message helpers with firestack semantics: question extraction, `RData` summaries for Kotlin, EDNS0
//! padding (RFC 8467 block size 128) and the synthesized "refused"/blocked answers.

use hickory_proto::op::{Edns, Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
use hickory_proto::rr::rdata::svcb::{IpHint, SvcParamKey, SvcParamValue};
use hickory_proto::rr::rdata::{A, AAAA, HINFO};
use hickory_proto::rr::{RData, Record, RecordType};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// RFC 8467 recommended padding block size (firestack `paddingBlockSize`).
pub const PADDING_BLOCK_SIZE: usize = 128;
/// TTL of synthesized blocked answers (firestack `blockTTL`): 5, but `BustDnsproxydResNetCache` sets it to 0 at
/// init so Android's resolver cache never keeps a block.
pub const BLOCK_TTL: u32 = 0;
/// TTL of synthesized answers (firestack `ansTTL`, also 0 for the same reason) and of ALG answers (`ZeroTTL`).
pub const ANS_TTL: u32 = 0;

pub fn parse(b: &[u8]) -> Option<Message> {
    Message::from_vec(b).ok()
}

pub fn pack(m: &Message) -> Option<Vec<u8>> {
    m.to_vec().ok()
}

/// (qname with trailing dot, qtype) of the first question.
pub fn question(m: &Message) -> Option<(String, u16)> {
    let q = m.queries.first()?;
    let mut name = q.name().to_ascii();
    if !name.ends_with('.') {
        name.push('.');
    }
    Some((name, u16::from(q.query_type())))
}

pub fn has_do_bit(m: &Message) -> bool {
    m.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok)
}

/// Max TTL across the answer section (firestack `RTtl`).
pub fn max_ttl(m: &Message) -> u32 {
    m.answers.iter().map(|r| r.ttl).max().unwrap_or(0)
}

/// firestack `GetInterestingRData`: csv of A/AAAA (SVCB/HTTPS ip hints first), else one representative value
/// of the first non-address record; `"--"` for no message.
pub fn interesting_rdata(m: Option<&Message>) -> String {
    let Some(m) = m else { return "--".into() };
    let mut ips: Vec<String> = Vec::new();
    for r in &m.answers {
        match &r.data {
            RData::A(a) => ips.push(a.0.to_string()),
            RData::AAAA(a) => ips.push(a.0.to_string()),
            RData::NS(ns) if ips.is_empty() => return ns.0.to_string(),
            RData::TXT(t) if ips.is_empty() => {
                return t
                    .txt_data
                    .first()
                    .map(|d| String::from_utf8_lossy(d).into_owned())
                    .unwrap_or_default();
            }
            RData::SOA(soa) if ips.is_empty() => return soa.rname.to_string(),
            RData::HINFO(h) if ips.is_empty() => {
                return String::from_utf8_lossy(&h.os).into_owned();
            }
            RData::SRV(s) if ips.is_empty() => return s.target.to_string(),
            RData::MX(mx) if ips.is_empty() => return mx.exchange.to_string(),
            RData::CNAME(_) => continue,
            other if ips.is_empty() && !matches!(other, RData::A(_) | RData::AAAA(_)) => {
                return other.to_string();
            }
            _ => {}
        }
    }
    ips.join(",")
}

/// csv of A/AAAA addresses in the answer section.
pub fn answer_ips(m: &Message) -> Vec<std::net::IpAddr> {
    m.answers
        .iter()
        .filter_map(|r| match &r.data {
            RData::A(a) => Some(std::net::IpAddr::V4(a.0)),
            RData::AAAA(a) => Some(std::net::IpAddr::V6(a.0)),
            _ => None,
        })
        .collect()
}

/// firestack `AddEDNS0PaddingIfNoneFound`: pads the encoded message to a multiple of [`PADDING_BLOCK_SIZE`].
pub fn add_padding_if_none(m: &mut Message) {
    let has_padding = m
        .edns
        .as_ref()
        .is_some_and(|e| e.options().get(EdnsCode::Padding).is_some());
    if has_padding {
        return;
    }
    if m.edns.is_none() {
        let mut e = Edns::new();
        e.set_max_payload(4096);
        m.set_edns(e);
    }
    // encoded size with an empty padding option (4 bytes header), then fill up to the block size
    let base = {
        let mut probe = m.clone();
        if let Some(e) = probe.edns.as_mut() {
            e.options_mut().insert(EdnsOption::Unknown(
                u16::from(EdnsCode::Padding),
                Vec::new(),
            ));
        }
        probe.to_vec().map(|v| v.len()).unwrap_or(0)
    };
    let pad = (PADDING_BLOCK_SIZE - base % PADDING_BLOCK_SIZE) % PADDING_BLOCK_SIZE;
    if let Some(e) = m.edns.as_mut() {
        e.options_mut().insert(EdnsOption::Unknown(
            u16::from(EdnsCode::Padding),
            vec![0u8; pad],
        ));
    }
}

/// firestack `EmptyResponseFromMessage`: header/question copied, response flag set, RA if RD.
pub fn empty_response(q: &Message) -> Message {
    let mut r = Message::new(q.metadata.id, MessageType::Response, q.metadata.op_code);
    r.metadata.recursion_desired = q.metadata.recursion_desired;
    r.metadata.recursion_available = q.metadata.recursion_desired;
    r.metadata.checking_disabled = q.metadata.checking_disabled;
    r.add_queries(q.queries.iter().cloned());
    r
}

/// firestack `RefusedResponseFromMessage`: blocked answer. A → 0.0.0.0, AAAA → ::, SVCB/HTTPS → NODATA, anything
/// else → an HINFO record; all with [`BLOCK_TTL`] and rcode NOERROR.
pub fn refused_response(q: &Message) -> Option<Message> {
    let question = q.queries.first()?.clone();
    let mut r = empty_response(q);
    r.metadata.response_code = ResponseCode::NoError;
    let name = question.name().clone();
    match question.query_type() {
        RecordType::A => {
            r.add_answer(Record::from_rdata(
                name,
                BLOCK_TTL,
                RData::A(A(Ipv4Addr::UNSPECIFIED)),
            ));
        }
        RecordType::AAAA => {
            r.add_answer(Record::from_rdata(
                name,
                BLOCK_TTL,
                RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED)),
            ));
        }
        RecordType::SVCB | RecordType::HTTPS => {}
        _ => {
            let h = HINFO::new(
                "These are not the queries you are".into(),
                "looking for".into(),
            );
            r.add_answer(Record::from_rdata(name, BLOCK_TTL, RData::HINFO(h)));
        }
    }
    Some(r)
}

/// SERVFAIL for a query (used when an upstream fails and a reply is still wanted, e.g. internal lookups).
pub fn servfail(q: &Message) -> Message {
    let mut r = empty_response(q);
    r.metadata.response_code = ResponseCode::ServFail;
    r
}

/// Builds an A or AAAA query for internal lookups (bootstrap of DoH hostnames).
/// Normalized qname of the first question (no trailing dot, ASCII lowercase), `""` without one.
pub fn qname(m: &Message) -> String {
    m.queries
        .first()
        .map(|q| normalize(&q.name().to_ascii()))
        .unwrap_or_default()
}

/// firestack `NormalizeQName` (non-ASCII names keep their case).
pub fn normalize(s: &str) -> String {
    if s.is_empty() || s == "." {
        return ".".into();
    }
    let s = s.strip_suffix('.').unwrap_or(s);
    if s.is_ascii() {
        s.to_ascii_lowercase()
    } else {
        s.to_string()
    }
}

pub fn qtype(m: &Message) -> u16 {
    m.queries
        .first()
        .map(|q| u16::from(q.query_type()))
        .unwrap_or(0)
}

pub fn has_answers(m: &Message) -> bool {
    !m.answers.is_empty()
}

pub fn a_answers(m: &Message) -> Vec<IpAddr> {
    m.answers
        .iter()
        .filter_map(|r| match &r.data {
            RData::A(a) => Some(IpAddr::V4(a.0)),
            _ => None,
        })
        .collect()
}

pub fn aaaa_answers(m: &Message) -> Vec<IpAddr> {
    m.answers
        .iter()
        .filter_map(|r| match &r.data {
            RData::AAAA(a) => Some(IpAddr::V6(a.0)),
            _ => None,
        })
        .collect()
}

/// firestack `AQuadAUnspecified`: any A 0.0.0.0 or AAAA :: (an upstream block).
pub fn aquada_unspecified(m: &Message) -> bool {
    m.answers.iter().any(|r| match &r.data {
        RData::A(a) => a.0.is_unspecified(),
        RData::AAAA(a) => a.0.is_unspecified(),
        _ => false,
    })
}

fn svcb_of(r: &Record) -> Option<&hickory_proto::rr::rdata::SVCB> {
    match &r.data {
        RData::SVCB(s) => Some(s),
        RData::HTTPS(h) => Some(&h.0),
        _ => None,
    }
}

/// firestack `IPHints`: ip hints (`v6` selects ipv6hint) of SVCB/HTTPS answers to an SVCB/HTTPS question.
pub fn ip_hints(m: &Message, v6: bool) -> Vec<IpAddr> {
    if !matches!(qtype(m), 64 | 65) {
        return Vec::new();
    }
    let mut out = Vec::new();
    for r in &m.answers {
        let Some(s) = svcb_of(r) else { continue };
        for (_, v) in &s.svc_params {
            match v {
                SvcParamValue::Ipv4Hint(h) if !v6 => {
                    out.extend(h.0.iter().map(|a| IpAddr::V4(a.0)))
                }
                SvcParamValue::Ipv6Hint(h) if v6 => out.extend(h.0.iter().map(|a| IpAddr::V6(a.0))),
                _ => {}
            }
        }
    }
    out
}

/// firestack `Targets`: the qname, then the owner names of A/AAAA, CNAME targets and AliasMode SVCB/HTTPS
/// targets (normalized, de-duplicated, in order).
pub fn targets(m: &Message) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let q = qname(m);
    if !q.is_empty() && q.is_ascii() {
        seen.insert(q.clone());
        out.push(q);
    }
    for r in &m.answers {
        let t = match &r.data {
            RData::A(_) | RData::AAAA(_) => r.name.to_ascii(),
            RData::CNAME(c) => c.0.to_ascii(),
            _ => match svcb_of(r) {
                Some(s) if s.svc_priority == 0 && !s.target_name.is_root() => {
                    s.target_name.to_ascii()
                }
                _ => continue,
            },
        };
        if t.is_empty() || t == "." || !t.is_ascii() {
            continue;
        }
        let n = normalize(&t);
        if seen.insert(n.clone()) {
            out.push(n);
        }
    }
    out
}

/// firestack `CopyAns`: AD, RD and CD cleared.
pub fn copy_ans(m: &Message) -> Message {
    let mut out = m.clone();
    out.metadata.authentic_data = false;
    out.metadata.recursion_desired = false;
    out.metadata.checking_disabled = false;
    out
}

/// firestack `SubstARecords` / `SubstAAAARecords`: one record per owner name, carrying `ip`, at the position of
/// that name's first record; other records keep their order. Returns whether any record was substituted.
pub fn subst_addr_records(m: &mut Message, ip: IpAddr, ttl: u32) -> bool {
    let v4 = ip.to_canonical().is_ipv4();
    let mut touched = HashSet::new();
    let mut rrs = Vec::with_capacity(m.answers.len());
    for r in m.answers.drain(..) {
        let ours = matches!((&r.data, v4), (RData::A(_), true) | (RData::AAAA(_), false));
        if !ours {
            rrs.push(r);
            continue;
        }
        if touched.insert(r.name.clone()) {
            let data = match ip.to_canonical() {
                IpAddr::V4(a) => RData::A(A(a)),
                IpAddr::V6(a) => RData::AAAA(AAAA(a)),
            };
            rrs.push(Record::from_rdata(r.name.clone(), ttl, data));
        }
    }
    m.answers = rrs;
    !touched.is_empty()
}

/// firestack `SubstSVCBRecordIPs`: replaces the ipv4hint (or ipv6hint) of SVCB records, and of HTTPS records in
/// ServiceMode with target `.`, by `ip` alone; clears the additional section when anything changed.
pub fn subst_svcb_hints(m: &mut Message, v6: bool, ip: IpAddr, ttl: u32) -> bool {
    let mut n = 0;
    for r in m.answers.iter_mut() {
        let svcb = match &mut r.data {
            RData::SVCB(s) => s,
            RData::HTTPS(h) => {
                if h.0.svc_priority == 0 || !h.0.target_name.is_root() {
                    continue;
                }
                &mut h.0
            }
            _ => continue,
        };
        let mut hit = false;
        for (k, v) in svcb.svc_params.iter_mut() {
            match (k, ip, v6) {
                (SvcParamKey::Ipv4Hint, IpAddr::V4(a), false) => {
                    *v = SvcParamValue::Ipv4Hint(IpHint(vec![A(a)]));
                    hit = true;
                }
                (SvcParamKey::Ipv6Hint, IpAddr::V6(a), true) => {
                    *v = SvcParamValue::Ipv6Hint(IpHint(vec![AAAA(a)]));
                    hit = true;
                }
                _ => {}
            }
        }
        if hit {
            r.ttl = ttl;
            n += 1;
        }
    }
    if n > 0 {
        m.additionals.clear();
    }
    n > 0
}

/// firestack `AQuadAForQueryTTL`: an answer to an A (or AAAA) question with the addresses of that family; `None`
/// when none match.
pub fn aquada_for_query(q: &Message, ttl: u32, ips: &[IpAddr]) -> Option<Message> {
    let question = q.queries.first()?;
    let qt = question.query_type();
    let mut a = empty_response(q);
    a.metadata.response_code = ResponseCode::NoError;
    for ip in ips {
        let data = match (qt, ip.to_canonical()) {
            (RecordType::A, IpAddr::V4(v4)) => RData::A(A(v4)),
            (RecordType::AAAA, IpAddr::V6(v6)) if ip.is_ipv6() => RData::AAAA(AAAA(v6)),
            _ => continue,
        };
        a.add_answer(Record::from_rdata(question.name().clone(), ttl, data));
    }
    if a.answers.is_empty() { None } else { Some(a) }
}

/// firestack `BustAndroidCacheIfNeeded`: TTL 0 on A/AAAA/SVCB/HTTPS/CNAME answers unless DNSSEC-authenticated.
pub fn bust_android_cache(m: &mut Message) {
    if m.metadata.authentic_data {
        return;
    }
    for r in m.answers.iter_mut() {
        if matches!(
            r.record_type(),
            RecordType::A
                | RecordType::AAAA
                | RecordType::SVCB
                | RecordType::HTTPS
                | RecordType::CNAME
        ) {
            r.ttl = 0;
        }
    }
}

pub fn query(name: &str, qtype: RecordType, id: u16) -> Option<Message> {
    let mut m = Message::new(id, MessageType::Query, hickory_proto::op::OpCode::Query);
    m.metadata.recursion_desired = true;
    let n = hickory_proto::rr::Name::from_ascii(name).ok()?;
    m.add_query(hickory_proto::op::Query::query(n, qtype));
    Some(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_and_refused() {
        let mut q = query("example.com.", RecordType::A, 0x1234).unwrap();
        add_padding_if_none(&mut q);
        assert_eq!(pack(&q).unwrap().len() % PADDING_BLOCK_SIZE, 0);
        let again = parse(&pack(&q).unwrap()).unwrap();
        assert_eq!(question(&again), Some(("example.com.".to_string(), 1)));

        let r = refused_response(&q).unwrap();
        assert_eq!(r.metadata.id, 0x1234);
        assert_eq!(interesting_rdata(Some(&r)), "0.0.0.0");
        assert_eq!(max_ttl(&r), BLOCK_TTL);
        let q6 = query("example.com.", RecordType::AAAA, 1).unwrap();
        assert_eq!(
            interesting_rdata(Some(&refused_response(&q6).unwrap())),
            "::"
        );
        let qtxt = query("example.com.", RecordType::TXT, 1).unwrap();
        assert_eq!(
            interesting_rdata(Some(&refused_response(&qtxt).unwrap())),
            "looking for"
        );
        let qh = query("example.com.", RecordType::HTTPS, 1).unwrap();
        assert_eq!(refused_response(&qh).unwrap().answers.len(), 0);
        assert_eq!(interesting_rdata(None), "--");
    }
}
