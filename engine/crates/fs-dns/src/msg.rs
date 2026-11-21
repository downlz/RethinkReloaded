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
use hickory_proto::rr::rdata::{A, AAAA, HINFO};
use hickory_proto::rr::{RData, Record, RecordType};
use std::net::{Ipv4Addr, Ipv6Addr};

/// RFC 8467 recommended padding block size (firestack `paddingBlockSize`).
pub const PADDING_BLOCK_SIZE: usize = 128;
/// TTL of synthesized blocked answers (firestack `blockTTL`).
pub const BLOCK_TTL: u32 = 5;

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
