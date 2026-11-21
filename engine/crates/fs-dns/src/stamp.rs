// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2018-2021 Frank Denis <j at pureftpd dot org>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: jedisct1/go-dnsstamps@302248eecc94:dnsstamps.go (ISC; the version firestack d3d530ea3e pins)

//! DNS stamps (`sdns://`): DNSCrypt servers, DoH servers and DNSCrypt relays, as go-dnsstamps parses them (other
//! protocols are rejected, as by the pinned version). Addresses without a port get 443.

use base64::Engine;
use std::net::IpAddr;

pub const PROTO_PLAIN: u8 = 0x00;
pub const PROTO_DNSCRYPT: u8 = 0x01;
pub const PROTO_DOH: u8 = 0x02;
pub const PROTO_DNSCRYPT_RELAY: u8 = 0x81;
const DEFAULT_PORT: u16 = 443;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stamp {
    pub proto: u8,
    pub props: u64,
    /// `ip:port` (`[v6]:port`); may be empty for DoH
    pub addr: String,
    pub server_pk: Vec<u8>,
    pub hashes: Vec<Vec<u8>>,
    pub provider_name: String,
    pub path: String,
}

fn err<T>(m: &str) -> Result<T, String> {
    Err(format!("stamp: {m}"))
}

/// Appends the default port when missing and checks `ip:port` (go-dnsstamps' address validation).
fn check_addr(addr: &mut String) -> Result<(), String> {
    let mut col = addr.rfind(':').map(|i| i as isize).unwrap_or(-1);
    let br = addr.rfind(']').map(|i| i as isize).unwrap_or(-1);
    if col < br {
        col = -1;
    }
    if col < 0 {
        col = addr.len() as isize;
        *addr = format!("{addr}:{DEFAULT_PORT}");
    }
    let col = col as usize;
    if col >= addr.len() - 1 {
        return err("invalid stamp (empty port)");
    }
    let (ip, port) = (&addr[..col], &addr[col + 1..]);
    if port.parse::<u16>().is_err() {
        return err("invalid stamp (port range)");
    }
    if ip
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
        .is_err()
    {
        return err("invalid stamp (IP address)");
    }
    Ok(())
}

fn str_of(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

impl Stamp {
    /// go-dnsstamps `NewServerStampFromString`.
    pub fn parse(s: &str) -> Result<Stamp, String> {
        let Some(rest) = s.strip_prefix("sdns:") else {
            return err("stamps are expected to start with \"sdns:\"");
        };
        let rest = rest.strip_prefix("//").unwrap_or(rest);
        let bin = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(rest)
            .map_err(|e| format!("stamp: {e}"))?;
        match bin.first() {
            None => err("stamp is too short"),
            Some(&PROTO_DNSCRYPT) => Self::dnscrypt(&bin),
            Some(&PROTO_DOH) => Self::doh(&bin),
            Some(&PROTO_DNSCRYPT_RELAY) => Self::relay(&bin),
            Some(_) => err("unsupported stamp version or protocol"),
        }
    }

    // id(u8)=0x01 props addrLen(1) serverAddr pkStrlen(1) pkStr providerNameLen(1) providerName
    fn dnscrypt(bin: &[u8]) -> Result<Stamp, String> {
        if bin.len() < 66 {
            return err("stamp is too short");
        }
        let mut st = Stamp {
            proto: PROTO_DNSCRYPT,
            props: u64::from_le_bytes(bin[1..9].try_into().unwrap()),
            ..Default::default()
        };
        let n = bin.len();
        let mut pos = 9;
        let len = bin[pos] as usize;
        if 1 + len >= n - pos {
            return err("invalid stamp");
        }
        pos += 1;
        st.addr = str_of(&bin[pos..pos + len]);
        pos += len;
        check_addr(&mut st.addr)?;
        let len = bin[pos] as usize;
        if 1 + len >= n - pos {
            return err("invalid stamp");
        }
        pos += 1;
        st.server_pk = bin[pos..pos + len].to_vec();
        pos += len;
        let len = bin[pos] as usize;
        if len >= n - pos {
            return err("invalid stamp");
        }
        pos += 1;
        st.provider_name = str_of(&bin[pos..pos + len]);
        pos += len;
        if pos != n {
            return err("invalid stamp (garbage after end)");
        }
        Ok(st)
    }

    // id(u8)=0x02 props addrLen(1) serverAddr hashLen(1) hash providerNameLen(1) providerName pathLen(1) path
    fn doh(bin: &[u8]) -> Result<Stamp, String> {
        if bin.len() < 22 {
            return err("stamp is too short");
        }
        let mut st = Stamp {
            proto: PROTO_DOH,
            props: u64::from_le_bytes(bin[1..9].try_into().unwrap()),
            ..Default::default()
        };
        let n = bin.len();
        let mut pos = 9;
        let len = bin[pos] as usize;
        if 1 + len >= n - pos {
            return err("invalid stamp");
        }
        pos += 1;
        st.addr = str_of(&bin[pos..pos + len]);
        pos += len;
        loop {
            let vlen = bin[pos] as usize;
            let len = vlen & !0x80;
            if 1 + len >= n - pos {
                return err("invalid stamp");
            }
            pos += 1;
            if len > 0 {
                st.hashes.push(bin[pos..pos + len].to_vec());
            }
            pos += len;
            if vlen & 0x80 != 0x80 {
                break;
            }
        }
        let len = bin[pos] as usize;
        if 1 + len >= n - pos {
            return err("invalid stamp");
        }
        pos += 1;
        st.provider_name = str_of(&bin[pos..pos + len]);
        pos += len;
        let len = bin[pos] as usize;
        if len >= n - pos {
            return err("invalid stamp");
        }
        pos += 1;
        st.path = str_of(&bin[pos..pos + len]);
        pos += len;
        if pos != n {
            return err("invalid stamp (garbage after end)");
        }
        if !st.addr.is_empty() {
            check_addr(&mut st.addr)?;
        }
        Ok(st)
    }

    // id(u8)=0x81 addrLen(1) serverAddr
    fn relay(bin: &[u8]) -> Result<Stamp, String> {
        if bin.len() < 13 {
            return err("stamp is too short");
        }
        let mut st = Stamp {
            proto: PROTO_DNSCRYPT_RELAY,
            ..Default::default()
        };
        let n = bin.len();
        let mut pos = 1;
        let len = bin[pos] as usize;
        if 1 + len > n - pos {
            return err("invalid stamp");
        }
        pos += 1;
        st.addr = str_of(&bin[pos..pos + len]);
        pos += len;
        check_addr(&mut st.addr)?;
        if pos != n {
            return err("invalid stamp (garbage after end)");
        }
        Ok(st)
    }
}
