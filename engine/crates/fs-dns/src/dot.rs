// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/dns53/dot.go

//! DNS-over-TLS (RFC 7858): `tls://host[:853]`, 2-byte length framing, 20 s timeout. As firestack (miekg's
//! `tcp-tls` client) each query uses its own protected TLS connection.

use crate::doh::HostResolver;
use crate::msg;
use crate::tls;
use crate::transport::{Answer, QueryError, Stats, TYPE_DOT, Transport};
use fs_core::bridge::{BoxFuture, dns_status};
use fs_dialers::Protector;
use rustls_pki_types::ServerName;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const TIMEOUT: Duration = Duration::from_secs(20);

pub struct DotTransport {
    id: String,
    url: String,
    host: String,
    port: u16,
    seeds: Vec<IpAddr>,
    resolve_host: Option<HostResolver>,
    protector: Protector,
    stats: Stats,
}

impl DotTransport {
    pub fn new(
        id: &str,
        url: &str,
        seeds: Vec<IpAddr>,
        protector: Protector,
        resolve_host: Option<HostResolver>,
    ) -> Result<Self, String> {
        let hp = url
            .trim()
            .strip_prefix("tls://")
            .unwrap_or(url.trim())
            .trim_end_matches('/');
        if hp.is_empty() {
            return Err("dot: empty url".into());
        }
        let (host, port) = match hp.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') || h.ends_with(']') => (
                h.trim_matches(['[', ']']).to_string(),
                p.parse::<u16>()
                    .map_err(|_| format!("dot: bad port in {url}"))?,
            ),
            _ => (hp.trim_matches(['[', ']']).to_string(), 853),
        };
        Ok(DotTransport {
            id: id.into(),
            url: url.into(),
            host,
            port,
            seeds,
            resolve_host,
            protector,
            stats: Stats::default(),
        })
    }

    async fn ips(&self) -> Vec<IpAddr> {
        if let Ok(ip) = self.host.parse::<IpAddr>() {
            return vec![ip];
        }
        if !self.seeds.is_empty() {
            return self.seeds.clone();
        }
        match &self.resolve_host {
            Some(r) => r(self.host.clone()).await,
            None => Vec::new(),
        }
    }

    async fn exchange(&self, q: &[u8], pid: &str) -> Result<Vec<u8>, QueryError> {
        let ips = self.ips().await;
        if ips.is_empty() {
            return Err(QueryError::new(
                dns_status::SEND_FAILED,
                format!("dot: no ips for {}", self.host),
            ));
        }
        let mut last = String::new();
        for ip in ips {
            let tcp = match self
                .protector
                .dial_tcp(
                    pid,
                    SocketAddr::new(ip, self.port),
                    fs_dialers::DIAL_TIMEOUT,
                )
                .await
            {
                Ok(t) => t,
                Err(e) => {
                    last = e.to_string();
                    continue;
                }
            };
            let name = ServerName::try_from(self.host.clone())
                .map_err(|e| QueryError::new(dns_status::INTERNAL_ERROR, e.to_string()))?;
            let mut s = match tokio_rustls::TlsConnector::from(tls::client_config(&[b"dot"]))
                .connect(name, tcp)
                .await
            {
                Ok(s) => s,
                Err(e) => {
                    last = format!("tls: {e}");
                    continue;
                }
            };
            let mut framed = (q.len() as u16).to_be_bytes().to_vec();
            framed.extend_from_slice(q);
            let io = async {
                s.write_all(&framed).await?;
                let mut len = [0u8; 2];
                s.read_exact(&mut len).await?;
                let mut out = vec![0u8; u16::from_be_bytes(len) as usize];
                s.read_exact(&mut out).await?;
                Ok::<_, std::io::Error>(out)
            };
            return io
                .await
                .map_err(|e| QueryError::new(dns_status::SEND_FAILED, format!("dot: {e}")));
        }
        Err(QueryError {
            status: dns_status::SEND_FAILED,
            msg: last,
            server: self.host.clone(),
        })
    }
}

impl Transport for DotTransport {
    fn id(&self) -> &str {
        &self.id
    }
    fn typ(&self) -> &str {
        TYPE_DOT
    }
    fn addr(&self) -> String {
        self.url.clone()
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
            let Some(mut m) = msg::parse(&q) else {
                return Err(QueryError::new(
                    dns_status::BAD_QUERY,
                    "dot: unparsable query",
                ));
            };
            msg::add_padding_if_none(&mut m);
            let body = msg::pack(&m).unwrap_or(q);
            let r = match tokio::time::timeout(TIMEOUT, self.exchange(&body, &pid)).await {
                Ok(r) => r,
                Err(_) => Err(QueryError::new(dns_status::SEND_FAILED, "dot: timeout")),
            };
            match r {
                Ok(ans) if msg::parse(&ans).is_some() => {
                    let latency = start.elapsed();
                    self.stats.ok(latency);
                    Ok(Answer {
                        msg: ans,
                        server: self.host.clone(),
                        pid,
                        latency,
                    })
                }
                Ok(_) => {
                    self.stats.err(dns_status::BAD_RESPONSE);
                    Err(QueryError::new(dns_status::BAD_RESPONSE, "dot: bad answer"))
                }
                Err(mut e) => {
                    self.stats.err(e.status);
                    e.server = self.host.clone();
                    Err(e)
                }
            }
        })
    }
}
