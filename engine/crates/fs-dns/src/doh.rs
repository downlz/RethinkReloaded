// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/doh/doh.go

//! DNS-over-HTTPS (RFC 8484) over HTTP/2: POST `application/dns-message`, query id zeroed and EDNS0-padded,
//! one reused protected TLS connection per transport (re-dialed on failure). Switches to GET `?dns=` after a
//! 404/405, as firestack. Server IPs come from the `ipcsv` seeds or, failing that, from `resolve_host`
//! (the Default/bootstrap transport).

use crate::msg;
use crate::tls;
use crate::transport::{Answer, QueryError, Stats, TYPE_DOH, Transport};
use base64::Engine;
use bytes::Bytes;
use fs_core::bridge::{BoxFuture, dns_status};
use fs_dialers::SharedDial;
use parking_lot::Mutex;
use rustls_pki_types::ServerName;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// Resolves a hostname to IPs (used when a DoH transport has no seeded IPs).
pub type HostResolver = Arc<dyn Fn(String) -> BoxFuture<Vec<IpAddr>> + Send + Sync>;

const QUERY_TIMEOUT: Duration = Duration::from_secs(20);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(7);
const MAX_RESPONSE: usize = 65535;

pub struct DohTransport {
    id: String,
    url: http::Uri,
    host: String,
    port: u16,
    seeds: Mutex<Vec<IpAddr>>,
    resolve_host: Option<HostResolver>,
    dialer: SharedDial,
    conn: tokio::sync::Mutex<Option<h2::client::SendRequest<Bytes>>>,
    use_get: AtomicBool,
    stats: Stats,
}

impl DohTransport {
    /// `url` must be `https://…` (firestack also accepts `http://` meaning https without verification; not
    /// supported here: rejected).
    pub fn new(
        id: &str,
        url: &str,
        seeds: Vec<IpAddr>,
        dialer: SharedDial,
        resolve_host: Option<HostResolver>,
    ) -> Result<Self, String> {
        let uri: http::Uri = url
            .parse()
            .map_err(|e| format!("doh: bad url {url}: {e}"))?;
        if uri.scheme_str() != Some("https") {
            return Err(format!("doh: url must be https: {url}"));
        }
        let host = uri
            .host()
            .ok_or("doh: url has no host")?
            .trim_matches(['[', ']'])
            .to_string();
        let port = uri.port_u16().unwrap_or(443);
        Ok(DohTransport {
            id: id.to_string(),
            url: uri,
            host,
            port,
            seeds: Mutex::new(seeds),
            resolve_host,
            dialer,
            conn: tokio::sync::Mutex::new(None),
            use_get: AtomicBool::new(false),
            stats: Stats::default(),
        })
    }

    async fn ips(&self) -> Vec<IpAddr> {
        if let Ok(ip) = self.host.parse::<IpAddr>() {
            return vec![ip];
        }
        let seeds = self.seeds.lock().clone();
        if !seeds.is_empty() {
            return seeds;
        }
        match &self.resolve_host {
            Some(r) => r(self.host.clone()).await,
            None => Vec::new(),
        }
    }

    async fn connect(&self, pid: &str) -> Result<h2::client::SendRequest<Bytes>, QueryError> {
        let ips = self.ips().await;
        if ips.is_empty() {
            return Err(QueryError::new(
                dns_status::SEND_FAILED,
                format!("doh: no ips for {}", self.host),
            ));
        }
        let mut last = String::new();
        for ip in ips {
            let sa = SocketAddr::new(ip, self.port);
            let tcp = match self
                .dialer
                .dial_tcp(pid, sa, fs_dialers::DIAL_TIMEOUT)
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
            let tls = tokio_rustls::TlsConnector::from(tls::client_config(&[b"h2"]));
            let stream =
                match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, tls.connect(name, tcp)).await {
                    Ok(Ok(s)) => s,
                    Ok(Err(e)) => {
                        last = format!("tls: {e}");
                        continue;
                    }
                    Err(_) => {
                        last = "tls: handshake timeout".into();
                        continue;
                    }
                };
            if stream.get_ref().1.alpn_protocol() != Some(b"h2") {
                last = "doh: server did not negotiate h2".into();
                continue;
            }
            let (send, conn) = match h2::client::handshake(stream).await {
                Ok(x) => x,
                Err(e) => {
                    last = format!("h2: {e}");
                    continue;
                }
            };
            tokio::spawn(async move {
                let _ = conn.await;
            });
            return Ok(send);
        }
        Err(QueryError {
            status: dns_status::SEND_FAILED,
            msg: last,
            server: self.host.clone(),
        })
    }

    async fn exchange(
        &self,
        body: Vec<u8>,
        pid: &str,
    ) -> Result<(Vec<u8>, RdnsHeaders), QueryError> {
        let mut guard = self.conn.lock().await;
        let send = match guard.as_ref() {
            Some(s) => s.clone(),
            None => {
                let s = self.connect(pid).await?;
                *guard = Some(s.clone());
                s
            }
        };
        drop(guard);
        let r = self.request(send, body.clone()).await;
        if let Err(e) = &r
            && e.status == dns_status::SEND_FAILED
        {
            // stale connection: re-dial once
            *self.conn.lock().await = None;
            let s = self.connect(pid).await?;
            *self.conn.lock().await = Some(s.clone());
            return self.request(s, body).await;
        }
        r
    }

    async fn request(
        &self,
        send: h2::client::SendRequest<Bytes>,
        body: Vec<u8>,
    ) -> Result<(Vec<u8>, RdnsHeaders), QueryError> {
        let sendfail = |e: h2::Error| QueryError::new(dns_status::SEND_FAILED, format!("h2: {e}"));
        let mut send = send.ready().await.map_err(sendfail)?;
        let get = self.use_get.load(Ordering::Relaxed);
        let uri = if get {
            let q = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&body);
            let pq = self.url.path_and_query().map(|p| p.as_str()).unwrap_or("/");
            let sep = if pq.contains('?') { '&' } else { '?' };
            format!(
                "https://{}:{}{pq}{sep}dns={q}",
                self.url.host().unwrap_or(&self.host),
                self.port
            )
        } else {
            self.url.to_string()
        };
        let mut req = http::Request::builder()
            .method(if get { "GET" } else { "POST" })
            .uri(uri)
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message");
        if !get {
            // Go's net/http always sends it; some front ends (Cloudflare) answer 400 without it
            req = req.header("content-length", body.len().to_string());
        }
        let req = req
            .body(())
            .map_err(|e| QueryError::new(dns_status::INTERNAL_ERROR, e.to_string()))?;
        let (resp, mut stream) = send.send_request(req, get).map_err(sendfail)?;
        if !get {
            stream
                .send_data(Bytes::from(body), true)
                .map_err(sendfail)?;
        }
        let resp = resp.await.map_err(sendfail)?;
        let status = resp.status();
        if status.as_u16() == 404 || status.as_u16() == 405 {
            self.use_get.store(true, Ordering::Relaxed);
        }
        if !status.is_success() {
            let st = if status.is_client_error() {
                dns_status::CLIENT_ERROR
            } else {
                dns_status::TRANSPORT_ERROR
            };
            return Err(QueryError::new(st, format!("doh: http {status}")));
        }
        let hdrs = RdnsHeaders::from(resp.headers());
        let mut body = resp.into_body();
        let mut out = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk
                .map_err(|e| QueryError::new(dns_status::BAD_RESPONSE, format!("h2 body: {e}")))?;
            let _ = body.flow_control().release_capacity(chunk.len());
            out.extend_from_slice(&chunk);
            if out.len() > MAX_RESPONSE {
                return Err(QueryError::new(
                    dns_status::BAD_RESPONSE,
                    "doh: response too large",
                ));
            }
        }
        Ok((out, hdrs))
    }
}

/// firestack `rdnsHeaders`: what RethinkDNS upstreams say about an answer.
#[derive(Debug, Default)]
struct RdnsHeaders {
    blocklists: String,
    region: String,
}

impl From<&http::HeaderMap> for RdnsHeaders {
    fn from(h: &http::HeaderMap) -> Self {
        let get = |k: &str| {
            h.get(k)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string()
        };
        let mut region = get("x-nile-region");
        if region.is_empty() {
            // Cf-Ray: d1e2a3d4b5e6e7f8-SIN
            region = get("cf-ray")
                .split_once('-')
                .map(|(_, r)| r.to_string())
                .unwrap_or_default();
        }
        RdnsHeaders {
            blocklists: get("x-nile-flags"),
            region,
        }
    }
}

impl Transport for DohTransport {
    fn id(&self) -> &str {
        &self.id
    }
    fn typ(&self) -> &str {
        TYPE_DOH
    }
    fn addr(&self) -> String {
        self.url.to_string()
    }
    fn status(&self) -> i32 {
        self.stats.status()
    }
    fn p50(&self) -> i64 {
        self.stats.p50()
    }
    fn query(self: Arc<Self>, q: Vec<u8>, pid: String) -> BoxFuture<Result<Answer, QueryError>> {
        let me = self;
        Box::pin(async move {
            let start = Instant::now();
            let Some(mut m) = msg::parse(&q) else {
                me.stats.err(dns_status::BAD_QUERY);
                return Err(QueryError::new(
                    dns_status::BAD_QUERY,
                    "doh: unparsable query",
                ));
            };
            let id = m.metadata.id;
            m.metadata.id = 0;
            msg::add_padding_if_none(&mut m);
            let body = msg::pack(&m).unwrap_or(q);
            let r = tokio::time::timeout(QUERY_TIMEOUT, me.exchange(body, &pid)).await;
            let (raw, hdrs) = match r {
                Ok(Ok(x)) => x,
                Ok(Err(mut e)) => {
                    me.stats.err(e.status);
                    e.server = me.host.clone();
                    return Err(e);
                }
                Err(_) => {
                    me.stats.err(dns_status::SEND_FAILED);
                    return Err(QueryError {
                        status: dns_status::SEND_FAILED,
                        msg: "doh: timeout".into(),
                        server: me.host.clone(),
                    });
                }
            };
            let Some(mut ans) = msg::parse(&raw) else {
                me.stats.err(dns_status::BAD_RESPONSE);
                return Err(QueryError::new(
                    dns_status::BAD_RESPONSE,
                    "doh: unparsable answer",
                ));
            };
            ans.metadata.id = id;
            let latency = start.elapsed();
            me.stats.ok(latency);
            Ok(Answer {
                msg: msg::pack(&ans).unwrap_or(raw),
                server: me.host.clone(),
                pid,
                latency,
                blocklists: hdrs.blocklists,
                region: hdrs.region,
            })
        })
    }
}
