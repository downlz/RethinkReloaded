// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2020 RethinkDNS and its authors.
// Copyright (c) 2018-2021 Frank Denis <j at pureftpd dot org>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/dnscrypt/certs.go (ISC portions: dnscrypt-proxy)

//! DNSCrypt certificates: the provider's TXT records, verified with its ed25519 key; the newest valid one (highest
//! serial, then the preferred construction) wins.

use super::crypto::{CLIENT_MAGIC_LEN, Construction};

const CERT_MAGIC: [u8; 4] = *b"DNSC";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertInfo {
    pub construction: Construction,
    pub server_pk: [u8; 32],
    pub magic: [u8; CLIENT_MAGIC_LEN],
    /// validity at most 7 days
    pub forward_security: bool,
}

/// The selection loop of firestack's `fetchCurrentDNSCryptCert` over raw TXT record bytes.
pub fn pick(pk: &[u8; 32], records: &[Vec<u8>], now: u32, ignore_ts: bool) -> Option<CertInfo> {
    let key = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, pk);
    let mut best: Option<CertInfo> = None;
    let mut highest = 0u32;
    for b in records {
        if b.len() < 124 || b[..4] != CERT_MAGIC {
            continue;
        }
        let c = match u16::from_be_bytes([b[4], b[5]]) {
            1 => Construction::XSalsa20Poly1305,
            2 => Construction::XChaCha20Poly1305,
            _ => continue,
        };
        if key.verify(&b[72..], &b[8..72]).is_err() {
            continue;
        }
        let be = |i: usize| u32::from_be_bytes(b[i..i + 4].try_into().unwrap());
        let (serial, begin, end) = (be(112), be(116), be(120));
        if begin >= end {
            continue;
        }
        if !ignore_ts && (now > end || now < begin) {
            continue;
        }
        if serial < highest {
            continue;
        }
        let cur = best.as_ref().map(|x| x.construction).unwrap_or_default();
        if serial == highest && c < cur {
            continue;
        }
        best = Some(CertInfo {
            construction: c,
            server_pk: b[72..104].try_into().unwrap(),
            magic: b[104..112].try_into().unwrap(),
            forward_security: end - begin <= 86400 * 7,
        });
        highest = serial;
    }
    best
}

/// firestack `packTxtString`: unescapes a TXT string as miekg/dns presents it (`\DDD`, `\t`, `\r`, `\n`, `\x`).
pub fn pack_txt_string(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' {
            i += 1;
            if i == b.len() {
                break;
            }
            if i + 2 < b.len() && b[i..i + 3].iter().all(u8::is_ascii_digit) {
                let v = (b[i] - b'0') as u32 * 100
                    + (b[i + 1] - b'0') as u32 * 10
                    + (b[i + 2] - b'0') as u32;
                out.push(v as u8);
                i += 2;
            } else {
                out.push(match b[i] {
                    b't' => b'\t',
                    b'r' => b'\r',
                    b'n' => b'\n',
                    x => x,
                });
            }
        } else {
            out.push(b[i]);
        }
        i += 1;
    }
    out
}
