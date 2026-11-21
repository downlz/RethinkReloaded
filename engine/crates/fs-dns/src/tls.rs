// Copyright (c) 2026 RethinkReloaded contributors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! TLS client configuration. Trust anchors come from Android's system CA store (as firestack, which uses Go's
//! default roots on Android: /apex/com.android.conscrypt/cacerts and /system/etc/security/cacerts), falling back to
//! the bundled Mozilla roots (webpki-roots) when no system store is readable (host tests, unusual devices).
//! User-installed CAs are not trusted, matching firestack.

use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use std::sync::{Arc, OnceLock};

const SYSTEM_CA_DIRS: &[&str] = &[
    "/apex/com.android.conscrypt/cacerts",
    "/system/etc/security/cacerts",
];

fn roots() -> RootCertStore {
    let mut store = RootCertStore::empty();
    for dir in SYSTEM_CA_DIRS {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for e in entries.flatten() {
            let Ok(bytes) = std::fs::read(e.path()) else {
                continue;
            };
            for cert in CertificateDer::pem_slice_iter(&bytes).flatten() {
                let _ = store.add(cert);
            }
        }
        if !store.is_empty() {
            return store;
        }
    }
    store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    store
}

/// Client config with the given ALPN protocols (e.g. `h2`, `http/1.1`, `dot`).
pub fn client_config(alpn: &[&[u8]]) -> Arc<ClientConfig> {
    static ROOTS: OnceLock<Arc<RootCertStore>> = OnceLock::new();
    let roots = ROOTS.get_or_init(|| Arc::new(roots())).clone();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .expect("tls versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(cfg)
}

/// Accepts any server certificate (handshake signatures are still checked). Only for what the user marked
/// insecure: firestack's `http://` DoH and scheme-less DoT URLs (`InsecureSkipVerify`).
#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &rustls_pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            msg,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            msg,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Client config that skips certificate verification (see [`NoVerify`]).
pub fn client_config_insecure(alpn: &[&[u8]]) -> Arc<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .expect("tls versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(cfg)
}
