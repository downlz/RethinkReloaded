// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2020 RethinkDNS and its authors.
// Copyright (c) 2018-2021 Frank Denis <j at pureftpd dot org>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/dnscrypt/crypto.go (ISC portions: dnscrypt-proxy)
// Derived-From: jedisct1/xsecretbox@b731c21297f9:xsecretbox.go (ISC)

//! DNSCrypt v2 crypto: NaCl secretbox (`tag ‖ ciphertext`) over XSalsa20 or XChaCha20 (xsecretbox), shared keys
//! from X25519 + HSalsa20 / HChaCha20, ISO/IEC 7816-4 padding.

use chacha20::XChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher, generic_array::GenericArray, typenum::U10};
use poly1305::Poly1305;
use poly1305::universal_hash::KeyInit;
use salsa20::XSalsa20;

pub const NONCE_SIZE: usize = 24;
pub const HALF_NONCE: usize = NONCE_SIZE / 2;
pub const TAG_SIZE: usize = 16;
pub const PUBLIC_KEY_SIZE: usize = 32;
pub const CLIENT_MAGIC_LEN: usize = 8;
/// `r6fnvWj8`
pub const SERVER_MAGIC: [u8; 8] = [0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38];
pub const QUERY_OVERHEAD: usize = CLIENT_MAGIC_LEN + PUBLIC_KEY_SIZE + HALF_NONCE + TAG_SIZE;
pub const RESPONSE_OVERHEAD: usize = SERVER_MAGIC.len() + NONCE_SIZE + TAG_SIZE;
pub const MIN_DNS_PACKET: usize = 12 + 5;
pub const MAX_DNS_PACKET: usize = 4096;
pub const MAX_DNS_UDP_PACKET: usize = 4096;
pub const MAX_DNS_UDP_SAFE_PACKET: usize = 1252;

/// The certificate's es-version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum Construction {
    #[default]
    Undefined = 0,
    XSalsa20Poly1305 = 1,
    XChaCha20Poly1305 = 2,
}

/// The stream cipher keyed for `nonce`: its first 32 keystream bytes are the Poly1305 key (secretbox).
enum Stream {
    Salsa(XSalsa20),
    ChaCha(XChaCha20),
}

impl Stream {
    fn new(c: Construction, key: &[u8; 32], nonce: &[u8; NONCE_SIZE]) -> Stream {
        let (k, n) = (
            GenericArray::from_slice(key),
            GenericArray::from_slice(nonce),
        );
        match c {
            Construction::XChaCha20Poly1305 => Stream::ChaCha(XChaCha20::new(k, n)),
            _ => Stream::Salsa(XSalsa20::new(k, n)),
        }
    }
    fn xor(&mut self, b: &mut [u8]) {
        match self {
            Stream::Salsa(s) => s.apply_keystream(b),
            Stream::ChaCha(s) => s.apply_keystream(b),
        }
    }
}

fn poly_key(s: &mut Stream) -> Poly1305 {
    let mut k = [0u8; 32];
    s.xor(&mut k);
    Poly1305::new(GenericArray::from_slice(&k))
}

/// `secretbox.Seal` / `xsecretbox.Seal`: `tag ‖ ciphertext`.
pub fn seal(c: Construction, key: &[u8; 32], nonce: &[u8; NONCE_SIZE], msg: &[u8]) -> Vec<u8> {
    let mut s = Stream::new(c, key, nonce);
    let mac = poly_key(&mut s);
    let mut ct = msg.to_vec();
    s.xor(&mut ct);
    let tag = mac.compute_unpadded(&ct);
    let mut out = tag.to_vec();
    out.extend_from_slice(&ct);
    out
}

/// `secretbox.Open` / `xsecretbox.Open`.
pub fn open(
    c: Construction,
    key: &[u8; 32],
    nonce: &[u8; NONCE_SIZE],
    sealed: &[u8],
) -> Option<Vec<u8>> {
    if sealed.len() < TAG_SIZE {
        return None;
    }
    let mut s = Stream::new(c, key, nonce);
    let mac = poly_key(&mut s);
    let (tag, ct) = sealed.split_at(TAG_SIZE);
    let want = mac.compute_unpadded(ct);
    if !ring_eq(want.as_slice(), tag) {
        return None;
    }
    let mut pt = ct.to_vec();
    s.xor(&mut pt);
    Some(pt)
}

fn ring_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// `computeSharedKey`: HSalsa20 (NaCl `box.Precompute`) or HChaCha20 (`xsecretbox.SharedKey`) of X25519(sk, pk).
pub fn shared_key(c: Construction, sk: &[u8; 32], pk: &[u8; 32]) -> [u8; 32] {
    let dh = x25519_dalek::x25519(*sk, *pk);
    let zero = GenericArray::default();
    let k = GenericArray::from_slice(&dh);
    let out = match c {
        Construction::XChaCha20Poly1305 => chacha20::hchacha::<U10>(k, &zero),
        _ => salsa20::hsalsa::<U10>(k, &zero),
    };
    out.into()
}

/// X25519 public key of `sk`.
pub fn public_key(sk: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::x25519(*sk, x25519_dalek::X25519_BASEPOINT_BYTES)
}

pub fn pad(mut packet: Vec<u8>, min: usize) -> Vec<u8> {
    packet.push(0x80);
    if packet.len() < min {
        packet.resize(min, 0);
    }
    packet
}

pub fn unpad(packet: &[u8]) -> Option<&[u8]> {
    let mut i = packet.len();
    loop {
        if i == 0 {
            return None;
        }
        i -= 1;
        match packet[i] {
            0x80 => return Some(&packet[..i]),
            0x00 => {}
            _ => return None,
        }
    }
}

pub fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut b).expect("system rng");
    b
}

/// A server's session parameters, from its certificate.
#[derive(Clone, Debug)]
pub struct Session {
    pub construction: Construction,
    pub shared_key: [u8; 32],
    pub client_pk: [u8; 32],
    pub magic: [u8; CLIENT_MAGIC_LEN],
}

/// firestack `encrypt`: `client-magic ‖ client-pk ‖ client-nonce ‖ box(pad(query))`. Padded to 1252 bytes over
/// UDP, 4096 over TCP through a relay, and to a random multiple of 64 over plain TCP.
pub fn encrypt(
    s: &Session,
    query: &[u8],
    udp: bool,
    relay: bool,
) -> Result<(Vec<u8>, [u8; HALF_NONCE]), String> {
    let client_nonce: [u8; HALF_NONCE] = random();
    let mut nonce = [0u8; NONCE_SIZE];
    nonce[..HALF_NONCE].copy_from_slice(&client_nonce);
    let padded_len = if udp {
        MAX_DNS_UDP_SAFE_PACKET
    } else if relay {
        MAX_DNS_PACKET
    } else {
        let xpad: [u8; 1] = random();
        let min = QUERY_OVERHEAD + query.len() + xpad[0] as usize;
        MAX_DNS_UDP_PACKET.min((min.max(QUERY_OVERHEAD) + 1 + 63) & !63)
    };
    if QUERY_OVERHEAD + query.len() + 1 > padded_len {
        return Err("dnscrypt: query size too large".into());
    }
    let mut out = Vec::with_capacity(padded_len);
    out.extend_from_slice(&s.magic);
    out.extend_from_slice(&s.client_pk);
    out.extend_from_slice(&client_nonce);
    let padded = pad(query.to_vec(), padded_len - QUERY_OVERHEAD);
    out.extend_from_slice(&seal(s.construction, &s.shared_key, &nonce, &padded));
    Ok((out, client_nonce))
}

/// firestack `decrypt`: checks the server magic and the client half of the nonce, opens and unpads.
pub fn decrypt(
    s: &Session,
    encrypted: &[u8],
    client_nonce: &[u8; HALF_NONCE],
) -> Result<Vec<u8>, String> {
    let head = SERVER_MAGIC.len() + NONCE_SIZE;
    if encrypted.len() < head + TAG_SIZE + MIN_DNS_PACKET
        || encrypted.len() > head + TAG_SIZE + MAX_DNS_PACKET
        || encrypted[..SERVER_MAGIC.len()] != SERVER_MAGIC
    {
        return Err("dnscrypt: response too large or too small".into());
    }
    let nonce: [u8; NONCE_SIZE] = encrypted[SERVER_MAGIC.len()..head].try_into().unwrap();
    if nonce[..HALF_NONCE] != client_nonce[..] {
        return Err("dnscrypt: unexpected nonce".into());
    }
    let pt = open(s.construction, &s.shared_key, &nonce, &encrypted[head..])
        .ok_or("dnscrypt: incorrect tag")?;
    if pt.is_empty() {
        return Err("dnscrypt: response too large or too small".into());
    }
    match unpad(&pt) {
        Some(p) if p.len() >= MIN_DNS_PACKET => Ok(p.to_vec()),
        _ => Err("dnscrypt: incorrect padding".into()),
    }
}
