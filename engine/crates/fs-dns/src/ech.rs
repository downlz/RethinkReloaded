// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2024 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/dialers/dns.go (ECH)
// Derived-From: celzero/firestack@d3d530ea3e:intra/doh/doh.go (ech, echVerifyFn, ECH retry)

//! Encrypted Client Hello for DoH (and ODoH relays): the server's ECH configs come from the `ech` parameter of its
//! HTTPS record, looked up through the engine's resolver (as firestack's `dialers.ECH`). rustls does the ECH
//! handshake; it needs HPKE, which its ring provider lacks, so this module supplies the client side (sealing) of
//! the suites ECH deployments use: DHKEM(X25519, HKDF-SHA256) with HKDF-SHA256 and AES-128-GCM, AES-256-GCM or
//! ChaCha20-Poly1305, over the `hpke` crate (the one ODoH uses).

use fs_core::bridge::BoxFuture;
use hpke::aead::{Aead, AeadCtxS, AesGcm128, AesGcm256, ChaCha20Poly1305};
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as _, OpModeS, Serializable};
use parking_lot::RwLock;
use rustls::Error;
use rustls::crypto::hpke::{
    EncapsulatedSecret, Hpke, HpkeOpener, HpkePrivateKey, HpkePublicKey, HpkeSealer, HpkeSuite,
};
use rustls::internal::msgs::enums::{HpkeAead, HpkeKdf, HpkeKem};
use rustls::internal::msgs::handshake::HpkeSymmetricCipherSuite;
use std::fmt;
use std::marker::PhantomData;
use std::sync::Arc;

type Kem = X25519HkdfSha256;

/// One HPKE suite (X25519 / HKDF-SHA256 / `A`).
pub struct Suite<A> {
    aead: HpkeAead,
    _a: PhantomData<fn() -> A>,
}

impl<A> fmt::Debug for Suite<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "hpke(x25519, hkdf-sha256, {:?})", self.aead)
    }
}

struct Sealer<A: Aead>(AeadCtxS<A, HkdfSha256, Kem>);

impl<A: Aead> fmt::Debug for Sealer<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("hpke sealer")
    }
}

fn err(e: hpke::HpkeError) -> Error {
    Error::General(format!("hpke: {e}"))
}

impl<A: Aead + 'static> HpkeSealer for Sealer<A>
where
    AeadCtxS<A, HkdfSha256, Kem>: Send + Sync,
{
    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        self.0.seal(plaintext, aad).map_err(err)
    }
}

impl<A: Aead + 'static> Hpke for Suite<A>
where
    AeadCtxS<A, HkdfSha256, Kem>: Send + Sync,
{
    fn seal(
        &self,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Vec<u8>), Error> {
        let (enc, mut s) = self.setup_sealer(info, pub_key)?;
        Ok((enc, s.seal(aad, plaintext)?))
    }

    fn setup_sealer(
        &self,
        info: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Box<dyn HpkeSealer + 'static>), Error> {
        let pk = <Kem as hpke::Kem>::PublicKey::from_bytes(&pub_key.0).map_err(err)?;
        let (enc, ctx) =
            hpke::setup_sender::<A, HkdfSha256, Kem>(&OpModeS::Base, &pk, info).map_err(err)?;
        Ok((
            EncapsulatedSecret(enc.to_bytes().to_vec()),
            Box::new(Sealer(ctx)),
        ))
    }

    fn open(
        &self,
        _: &EncapsulatedSecret,
        _: &[u8],
        _: &[u8],
        _: &[u8],
        _: &HpkePrivateKey,
    ) -> Result<Vec<u8>, Error> {
        Err(Error::General("hpke: client only".into()))
    }

    fn setup_opener(
        &self,
        _: &EncapsulatedSecret,
        _: &[u8],
        _: &HpkePrivateKey,
    ) -> Result<Box<dyn HpkeOpener + 'static>, Error> {
        Err(Error::General("hpke: client only".into()))
    }

    fn generate_key_pair(&self) -> Result<(HpkePublicKey, HpkePrivateKey), Error> {
        let (sk, pk) = Kem::gen_keypair();
        Ok((
            HpkePublicKey(pk.to_bytes().to_vec()),
            HpkePrivateKey::from(sk.to_bytes().to_vec()),
        ))
    }

    fn suite(&self) -> HpkeSuite {
        HpkeSuite {
            kem: HpkeKem::DHKEM_X25519_HKDF_SHA256,
            sym: HpkeSymmetricCipherSuite {
                kdf_id: HpkeKdf::HKDF_SHA256,
                aead_id: self.aead,
            },
        }
    }
}

static X25519_AES128: Suite<AesGcm128> = Suite {
    aead: HpkeAead::AES_128_GCM,
    _a: PhantomData,
};
static X25519_AES256: Suite<AesGcm256> = Suite {
    aead: HpkeAead::AES_256_GCM,
    _a: PhantomData,
};
static X25519_CHACHA: Suite<ChaCha20Poly1305> = Suite {
    aead: HpkeAead::CHACHA20_POLY_1305,
    _a: PhantomData,
};

/// The HPKE suites offered for ECH.
pub static SUITES: &[&dyn Hpke] = &[&X25519_AES128, &X25519_AES256, &X25519_CHACHA];

/// Looks up the ECH config list (the `ech` SvcParam of the host's HTTPS record) for a host name.
pub type EchLookup = Arc<dyn Fn(String) -> BoxFuture<Option<Vec<u8>>> + Send + Sync>;

static LOOKUP: RwLock<Option<EchLookup>> = RwLock::new(None);

/// Set by the tunnel (its resolver); unset, no ECH.
pub fn set_lookup(l: Option<EchLookup>) {
    *LOOKUP.write() = l;
}

/// firestack `dialers.ECH(hostname)`, bounded as firestack (25 s).
pub async fn config_for(host: &str) -> Option<Vec<u8>> {
    let l = LOOKUP.read().clone()?;
    tokio::time::timeout(std::time::Duration::from_secs(25), l(host.to_string()))
        .await
        .ok()
        .flatten()
        .filter(|v| !v.is_empty())
}

/// The ECH config list of an HTTPS/SVCB answer (raw `ech` value: an ECHConfigList with its length prefix).
pub fn from_answer(m: &hickory_proto::op::Message) -> Option<Vec<u8>> {
    use hickory_proto::rr::RData;
    use hickory_proto::rr::rdata::svcb::SvcParamValue;
    m.answers.iter().find_map(|r| {
        let s = match &r.data {
            RData::HTTPS(h) => &h.0,
            RData::SVCB(s) => s,
            _ => return None,
        };
        s.svc_params.iter().find_map(|(_, v)| match v {
            SvcParamValue::EchConfigList(e) => Some(e.0.clone()),
            _ => None,
        })
    })
}

/// The retry configs a server sent with its rejection of our ECH (re-encoded as an ECHConfigList), if any.
pub fn retry_configs(e: &Error) -> Option<Vec<u8>> {
    use rustls::internal::msgs::codec::Codec;
    match e {
        Error::PeerIncompatible(rustls::PeerIncompatible::ServerRejectedEncryptedClientHello(
            Some(list),
        )) => {
            let mut b = Vec::new();
            list.encode(&mut b);
            Some(b)
        }
        _ => None,
    }
}

/// Whether a handshake error is an ECH rejection or an unusable config (firestack `ECHRejectionError`).
pub fn rejected(e: &Error) -> bool {
    matches!(
        e,
        Error::PeerIncompatible(rustls::PeerIncompatible::ServerRejectedEncryptedClientHello(_))
            | Error::InvalidEncryptedClientHello(_)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seals_for_a_receiver() {
        // round trip through the hpke crate's receiver
        let (sk, pk) = Kem::gen_keypair();
        let pk = HpkePublicKey(pk.to_bytes().to_vec());
        for s in SUITES {
            assert_eq!(s.suite().kem, HpkeKem::DHKEM_X25519_HKDF_SHA256);
        }
        let (enc, ct) = X25519_AES128
            .seal(b"info", b"aad", b"hello ech", &pk)
            .unwrap();
        let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(&enc.0).unwrap();
        let mut rx = hpke::setup_receiver::<AesGcm128, HkdfSha256, Kem>(
            &hpke::OpModeR::Base,
            &sk,
            &enc,
            b"info",
        )
        .unwrap();
        assert_eq!(rx.open(&ct, b"aad").unwrap(), b"hello ech");
    }
}
