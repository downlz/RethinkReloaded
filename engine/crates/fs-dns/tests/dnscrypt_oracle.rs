// Copyright (c) 2026 RethinkReloaded contributors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Replays testdata/oracle/<pin>/dnscrypt.tsv (firestack's own Go: nacl/secretbox, xsecretbox, curve25519,
//! go-dnsstamps, pad/unpad, packTxtString, certificate selection).

use fs_dns::dnscrypt::cert;
use fs_dns::dnscrypt::crypto::{self, Construction};
use fs_dns::stamp::Stamp;

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn arr<const N: usize>(s: &str) -> [u8; N] {
    unhex(s).try_into().unwrap()
}

#[test]
fn replays_firestack() {
    let pin = include_str!("../../../api/PIN").trim();
    let path = format!(
        "{}/../../testdata/oracle/{pin}/dnscrypt.tsv",
        env!("CARGO_MANIFEST_DIR")
    );
    let data = std::fs::read_to_string(&path).expect("dnscrypt.tsv (tools/go-oracle/run.sh)");
    let mut n = 0;
    for (ln, line) in data.lines().enumerate() {
        let f: Vec<&str> = line.split('\t').collect();
        let ctx = || format!("line {}: {line}", ln + 1);
        match f[0] {
            "shared" => {
                let (sk, pk) = (arr::<32>(f[1]), arr::<32>(f[2]));
                assert_eq!(
                    hex(&crypto::shared_key(
                        Construction::XSalsa20Poly1305,
                        &sk,
                        &pk
                    )),
                    f[3],
                    "{}",
                    ctx()
                );
                assert_eq!(
                    hex(&crypto::shared_key(
                        Construction::XChaCha20Poly1305,
                        &sk,
                        &pk
                    )),
                    f[4],
                    "{}",
                    ctx()
                );
            }
            "seal_xsalsa" | "seal_xchacha" => {
                let c = if f[0] == "seal_xsalsa" {
                    Construction::XSalsa20Poly1305
                } else {
                    Construction::XChaCha20Poly1305
                };
                let (k, nonce, msg) = (arr::<32>(f[1]), arr::<24>(f[2]), unhex(f[3]));
                let sealed = crypto::seal(c, &k, &nonce, &msg);
                assert_eq!(hex(&sealed), f[4], "{}", ctx());
                assert_eq!(
                    crypto::open(c, &k, &nonce, &sealed).unwrap(),
                    msg,
                    "{}",
                    ctx()
                );
                let mut bad = sealed.clone();
                bad[0] ^= 1;
                assert!(crypto::open(c, &k, &nonce, &bad).is_none(), "{}", ctx());
            }
            "pad" => {
                let min: usize = f[2].parse().unwrap();
                assert_eq!(hex(&crypto::pad(unhex(f[1]), min)), f[3], "{}", ctx());
            }
            "unpad_random" => {}
            "txt" => assert_eq!(hex(&cert::pack_txt_string(f[1])), f[2], "{}", ctx()),
            "certs" => {
                let (pk, now, ignore) = (arr::<32>(f[1]), f[2].parse().unwrap(), f[3] == "true");
                let recs: Vec<Vec<u8>> = f[4].split(' ').map(cert::pack_txt_string).collect();
                let got = match cert::pick(&pk, &recs, now, ignore) {
                    None => "none".to_string(),
                    Some(c) => format!(
                        "{}|{}|{}",
                        c.construction as u8,
                        hex(&c.server_pk),
                        hex(&c.magic)
                    ),
                };
                assert_eq!(got, f[5], "{}", ctx());
            }
            "stamp" => {
                let got = match Stamp::parse(f[1]) {
                    Err(_) => "err".to_string(),
                    Ok(s) => format!(
                        "{}|{}|{}|{}|{}|{}|{}",
                        s.proto,
                        s.props,
                        s.addr,
                        hex(&s.server_pk),
                        s.provider_name,
                        s.path,
                        s.hashes
                            .iter()
                            .map(|h| hex(h))
                            .collect::<Vec<_>>()
                            .join(",")
                    ),
                };
                assert_eq!(got, f[2], "{}", ctx());
            }
            op => panic!("unknown op {op}"),
        }
        n += 1;
    }
    assert!(n > 600, "{n} vectors");
}
