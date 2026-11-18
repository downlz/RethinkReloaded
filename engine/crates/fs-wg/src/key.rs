// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// This file incorporates work covered by the following copyright and
// permission notice:
//
//     SPDX-License-Identifier: MIT
//
//     Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/backend/ipn_wgkeygen.go

//! `backend.WgKey`: a 32-byte curve25519 key.

use base64::Engine;
use base64::engine::{GeneralPurpose, GeneralPurposeConfig, general_purpose};

pub const KLEN: usize = 32;

/// Go's `base64.StdEncoding`: padded, but tolerant of non-zero trailing bits.
const GO_STD: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
);

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct WgKey(pub [u8; KLEN]);

impl std::fmt::Debug for WgKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WgKey(..)") // never log key material
    }
}

fn clamp(mut k: [u8; KLEN]) -> [u8; KLEN] {
    k[0] &= 248;
    k[31] = (k[31] & 127) | 64;
    k
}

impl WgKey {
    /// `Backend.newWgPrivateKey()`: random, clamped.
    pub fn new_private() -> Result<Self, String> {
        let mut k = [0u8; KLEN];
        getrandom::getrandom(&mut k).map_err(|e| e.to_string())?;
        Ok(WgKey(clamp(k)))
    }

    /// `NewWgPrivateKeyFrom`: clamps the given bytes.
    pub fn private_from(k: [u8; KLEN]) -> Self {
        WgKey(clamp(k))
    }

    /// `Backend.newWgPrivateKeyOf(b64)`: decodes as-is (no clamping, as firestack).
    pub fn from_base64(s: &str) -> Result<Self, String> {
        // Go's decoder ignores '\r' and '\n'
        let cleaned: String = s.chars().filter(|c| *c != '\r' && *c != '\n').collect();
        let k = GO_STD
            .decode(cleaned)
            .map_err(|e| format!("invalid key: {e}"))?;
        let k: [u8; KLEN] = k
            .try_into()
            .map_err(|_| "keys must decode to exactly 32 bytes".to_string())?;
        Ok(WgKey(k))
    }

    pub fn is_zero(&self) -> bool {
        // constant time, as Go's subtle.ConstantTimeCompare
        self.0.iter().fold(0u8, |acc, b| acc | b) == 0
    }

    pub fn base64(&self) -> String {
        general_purpose::STANDARD.encode(self.0)
    }

    pub fn hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Scalar multiplication with the curve25519 basepoint (private -> public key); clamps internally.
    pub fn mult(&self) -> WgKey {
        WgKey(x25519_dalek::x25519(
            self.0,
            x25519_dalek::X25519_BASEPOINT_BYTES,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc7748_vector() {
        // RFC 7748 §6.1: Alice's private and public keys
        let sk = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
        let pk = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = u8::from_str_radix(&sk[2 * i..2 * i + 2], 16).unwrap();
        }
        let key = WgKey(k);
        assert_eq!(key.mult().hex(), pk);
        assert_eq!(WgKey::from_base64(&key.base64()).unwrap(), key);
    }

    #[test]
    fn generation_and_parsing() {
        let k = WgKey::new_private().unwrap();
        assert_eq!(k.0[0] & 7, 0);
        assert_eq!(k.0[31] & 0xc0, 0x40);
        assert!(!k.is_zero());
        assert!(WgKey([0; 32]).is_zero());
        assert!(WgKey::from_base64("AAAA").is_err());
        assert!(WgKey::from_base64("not base64!").is_err());
        let b = WgKey([7; 32]).base64();
        let wrapped = format!("{}\n{}", &b[..10], &b[10..]);
        assert_eq!(WgKey::from_base64(&wrapped).unwrap(), WgKey([7; 32]));
    }
}
