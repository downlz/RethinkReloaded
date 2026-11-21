// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/doh/odoh.go
// Derived-From: celzero/firestack@d3d530ea3e:intra/doh/doh.go (NewOdohTransport)

//! Oblivious DoH (RFC 9230): queries sealed with HPKE to the target's ODoH config, POSTed to the target or,
//! through an ODoH relay ("proxy"), with `targethost`/`targetpath`. The config comes from the target's HTTPS
//! record (SvcParam 32769), asked of 1.1.1.1 over DoH, or from `/.well-known/odohconfigs`; it is cached for the
//! record's TTL (an hour for the well-known one) and dropped when the target answers with a client error.

use crate::doh::{DohTransport, HostResolver, Req};
use crate::msg;
use crate::transport::{Answer, QueryError, Stats, TYPE_ODOH, Transport};
use bytes::Bytes;
use fs_core::bridge::{BoxFuture, dns_status};
use fs_dialers::SharedDial;
use hickory_proto::rr::rdata::svcb::SvcParamValue;
use hickory_proto::rr::{RData, RecordType};
use odoh_rs::{
    ObliviousDoHConfigContents, ObliviousDoHConfigs, ObliviousDoHMessage,
    ObliviousDoHMessagePlaintext,
};
use parking_lot::Mutex;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const MIME: &str = "application/oblivious-dns-message";
const CONFIG_DNS: &str = "https://1.1.1.1/dns-query";
const WELL_KNOWN: &str = "/.well-known/odohconfigs";
const TARGET_PATH: &str = "/dns-query";
const PROXY_PATH: &str = "/proxy";
const WELL_KNOWN_TTL: Duration = Duration::from_secs(3600);
/// the HTTPS-record SvcParam carrying ODoH configs (0x8001, up to draft-06)
const ODOH_SVC_KEY: u16 = 32769;
const BASE: &str = "Base";

/// ring's system RNG for HPKE (rand_core 0.10).
struct SysRng;
impl rand_core::TryRng for SysRng {
    type Error = std::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(u32::from_le_bytes(crate::dnscrypt::crypto::random()))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(u64::from_le_bytes(crate::dnscrypt::crypto::random()))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), dst).expect("system rng");
        Ok(())
    }
}
impl rand_core::TryCryptoRng for SysRng {}

pub struct OdohTransport {
    id: String,
    target_name: String,
    target_path: String,
    /// `(proxy host, proxy path)` when queries go through an ODoH relay
    proxy: Option<(String, String)>,
    /// the endpoint queries are POSTed to: the relay, else the target
    endpoint: DohTransport,
    /// the target itself, for its well-known config
    target: DohTransport,
    /// DoH to 1.1.1.1, for the target's HTTPS record
    config_dns: Arc<DohTransport>,
    config: Mutex<Option<(ObliviousDoHConfigContents, Instant)>>,
    prefer_well_known: AtomicBool,
    stats: Stats,
}

fn url_parts(u: &str) -> Option<(String, String)> {
    let uri: http::Uri = u.parse().ok()?;
    let host = uri.host()?.trim_matches(['[', ']']).to_string();
    let host = match uri.port_u16() {
        Some(p) => format!("{host}:{p}"),
        None => host,
    };
    Some((host, uri.path().to_string()))
}

impl OdohTransport {
    /// firestack `NewOdohTransport(id, endpoint, target, addrs)`: `endpoint` is the relay URL (may be empty);
    /// `seeds` are the relay's addresses, or the target's when there is no relay.
    pub fn new(
        id: &str,
        endpoint: &str,
        target: &str,
        seeds: Vec<IpAddr>,
        dialer: SharedDial,
        resolve_host: Option<HostResolver>,
    ) -> Result<Self, String> {
        let (target_name, tpath) = url_parts(target)
            .filter(|(h, _)| !h.is_empty())
            .ok_or("odoh: no odoh target")?;
        let target_path = if tpath.len() > 1 {
            tpath
        } else {
            TARGET_PATH.into()
        };
        let proxy = url_parts(endpoint)
            .filter(|(h, _)| !h.is_empty())
            .map(|(h, p)| {
                (
                    h,
                    if p.len() > 1 {
                        p
                    } else {
                        PROXY_PATH.to_string()
                    },
                )
            });
        let (endpoint_url, endpoint_seeds, target_seeds) = match &proxy {
            Some((h, _)) => (format!("https://{h}/"), seeds, Vec::new()),
            None => (format!("https://{target_name}/"), seeds.clone(), seeds),
        };
        let ep = DohTransport::new(
            id,
            &endpoint_url,
            endpoint_seeds,
            dialer.clone(),
            resolve_host.clone(),
        )?;
        let tg = DohTransport::new(
            id,
            &format!("https://{target_name}/"),
            target_seeds,
            dialer.clone(),
            resolve_host,
        )?;
        let cd = Arc::new(DohTransport::new(id, CONFIG_DNS, Vec::new(), dialer, None)?);
        Ok(OdohTransport {
            id: id.to_string(),
            target_name,
            target_path,
            proxy,
            endpoint: ep,
            target: tg,
            config_dns: cd,
            config: Mutex::new(None),
            prefer_well_known: AtomicBool::new(false),
            stats: Stats::default(),
        })
    }

    /// firestack `fetchTargetConfig`: cached, else refreshed (the source that worked last goes first).
    async fn config(&self) -> Result<ObliviousDoHConfigContents, String> {
        if let Some((c, exp)) = self.config.lock().clone()
            && Instant::now() < exp
        {
            return Ok(c);
        }
        let wk_first = self.prefer_well_known.load(Ordering::Relaxed);
        let first = if wk_first {
            self.config_from_well_known().await
        } else {
            self.config_from_dns().await
        };
        let r = match first {
            Ok(x) => Ok(x),
            Err(_) => {
                self.prefer_well_known.store(!wk_first, Ordering::Relaxed);
                if wk_first {
                    self.config_from_dns().await
                } else {
                    self.config_from_well_known().await
                }
            }
        };
        let (c, ttl) = r?;
        *self.config.lock() = Some((c.clone(), Instant::now() + ttl));
        Ok(c)
    }

    fn first_config(raw: &[u8]) -> Result<ObliviousDoHConfigContents, String> {
        let cfgs: ObliviousDoHConfigs = odoh_rs::parse(&mut Bytes::copy_from_slice(raw))
            .map_err(|e| format!("odoh: config: {e}"))?;
        cfgs.supported()
            .into_iter()
            .next()
            .map(Into::into)
            .ok_or_else(|| "odoh: no odoh configs found".into())
    }

    async fn config_from_well_known(&self) -> Result<(ObliviousDoHConfigContents, Duration), String> {
        let req = Req {
            method: "GET",
            path_and_query: WELL_KNOWN.into(),
            ctype: "application/octet-stream",
            body: None,
        };
        let (body, _) = self.target.send(req, BASE).await.map_err(|e| e.msg)?;
        Ok((Self::first_config(&body)?, WELL_KNOWN_TTL))
    }

    async fn config_from_dns(&self) -> Result<(ObliviousDoHConfigContents, Duration), String> {
        let name = format!(
            "{}.",
            self.target_name.split(':').next().unwrap_or_default()
        );
        let q = msg::query(&name, RecordType::HTTPS, 0).ok_or("odoh: bad target name")?;
        let a = self
            .config_dns
            .clone()
            .query(msg::pack(&q).unwrap_or_default(), BASE.into())
            .await
            .map_err(|e| e.msg)?;
        let m = msg::parse(&a.msg).ok_or("odoh: no odoh config response")?;
        for rr in &m.answers {
            let RData::HTTPS(h) = &rr.data else { continue };
            for (k, v) in &h.0.svc_params {
                if u16::from(*k) != ODOH_SVC_KEY {
                    continue;
                }
                if let SvcParamValue::Unknown(u) = v {
                    return Ok((
                        Self::first_config(&u.0)?,
                        Duration::from_secs(rr.ttl as u64),
                    ));
                }
            }
        }
        Err("odoh: no config in https/svcb".into())
    }

    async fn exchange(&self, q: &[u8], pid: &str) -> Result<Vec<u8>, QueryError> {
        let internal = |e: String| QueryError::new(dns_status::INTERNAL_ERROR, e);
        let cfg = self.config().await.map_err(internal)?;
        // firestack ComputePaddingSize: to a multiple of 128, counting a padding option header
        let pad = (128 - (q.len() + 4) % 128) % 128;
        let pt = ObliviousDoHMessagePlaintext::new(q, pad);
        let (oq, secret) =
            odoh_rs::encrypt_query(&pt, &cfg, &mut SysRng).map_err(|e| internal(e.to_string()))?;
        let body = odoh_rs::compose(&oq)
            .map_err(|e| internal(e.to_string()))?
            .to_vec();
        let path_and_query = match &self.proxy {
            Some((_, p)) => format!(
                "{p}?targethost={}&targetpath={}",
                pct(&self.target_name),
                pct(&self.target_path)
            ),
            None => self.target_path.clone(),
        };
        let req = Req {
            method: "POST",
            path_and_query,
            ctype: MIME,
            body: Some(body),
        };
        let (ans, _) = match self.endpoint.send(req, pid).await {
            Ok(x) => x,
            Err(e) => {
                // RFC 9230 §4.3/§7: 400/401 on padding or HPKE failures; drop the cached config
                if e.status == dns_status::CLIENT_ERROR {
                    *self.config.lock() = None;
                }
                return Err(e);
            }
        };
        let om: ObliviousDoHMessage = odoh_rs::parse(&mut Bytes::from(ans))
            .map_err(|e| QueryError::new(dns_status::BAD_RESPONSE, e.to_string()))?;
        let plain =
            odoh_rs::decrypt_response(&pt, &om, secret).map_err(|e| internal(e.to_string()))?;
        Ok(plain.into_msg().to_vec())
    }
}

/// Percent-encodes a query parameter value (Go's `url.Values.Encode`).
fn pct(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

impl Transport for OdohTransport {
    fn id(&self) -> &str {
        &self.id
    }
    fn typ(&self) -> &str {
        TYPE_ODOH
    }
    fn addr(&self) -> String {
        match &self.proxy {
            Some((p, _)) => format!("{p}>{}", self.target_name),
            None => self.target_name.clone(),
        }
    }
    fn status(&self) -> i32 {
        self.stats.status()
    }
    fn p50(&self) -> i64 {
        self.stats.p50()
    }
    fn query(self: Arc<Self>, q: Vec<u8>, pid: String) -> BoxFuture<Result<Answer, QueryError>> {
        Box::pin(async move {
            let start = Instant::now();
            let server = self.target_name.clone();
            match self.exchange(&q, &pid).await {
                Ok(ans) if msg::parse(&ans).is_some() => {
                    let latency = start.elapsed();
                    self.stats.ok(latency);
                    Ok(Answer {
                        msg: ans,
                        server,
                        pid,
                        latency,
                        ..Default::default()
                    })
                }
                Ok(_) => {
                    self.stats.err(dns_status::BAD_RESPONSE);
                    Err(QueryError {
                        status: dns_status::BAD_RESPONSE,
                        msg: "odoh: bad answer".into(),
                        server,
                    })
                }
                Err(mut e) => {
                    self.stats.err(e.status);
                    e.server = server;
                    Err(e)
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        assert_eq!(
            url_parts("https://odoh.example/dns-query").unwrap(),
            ("odoh.example".into(), "/dns-query".into())
        );
        assert_eq!(
            url_parts("https://r.example:8443").unwrap(),
            ("r.example:8443".into(), "/".into())
        );
        assert_eq!(pct("odoh.cloudflare-dns.com"), "odoh.cloudflare-dns.com");
        assert_eq!(pct("/dns-query"), "%2Fdns-query");
    }

    #[test]
    fn seals_and_opens_against_a_target_key() {
        // a target's key pair; the client seals to its public config, the target answers under the derived secret
        let kp = odoh_rs::ObliviousDoHKeyPair::new(&mut SysRng);
        let q = msg::pack(&msg::query("example.com.", RecordType::A, 1).unwrap()).unwrap();
        let pt = ObliviousDoHMessagePlaintext::new(&q, 7);
        let (oq, secret) = odoh_rs::encrypt_query(&pt, kp.public(), &mut SysRng).unwrap();
        let wire = odoh_rs::compose(&oq).unwrap();
        let got: ObliviousDoHMessage = odoh_rs::parse(&mut wire.freeze()).unwrap();
        let (qpt, srv_secret) = odoh_rs::decrypt_query(&got, &kp).unwrap();
        assert_eq!(qpt.into_msg().as_ref(), &q[..]);
        let reply = ObliviousDoHMessagePlaintext::new(b"answer-bytes", 0);
        let nonce: [u8; 16] = crate::dnscrypt::crypto::random();
        let resp = odoh_rs::encrypt_response(&pt, &reply, srv_secret, nonce).unwrap();
        let opened = odoh_rs::decrypt_response(&pt, &resp, secret).unwrap();
        assert_eq!(opened.into_msg().as_ref(), b"answer-bytes");
    }
}
