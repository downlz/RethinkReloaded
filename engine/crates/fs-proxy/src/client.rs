// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2025 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/ipn/pxclient.go

//! `Proxy.client()`: the proxy's egress address and its metadata (`backend.IPMetadata`), asked of public
//! "what is my IP" services over the proxy itself. Providers are tried in firestack's order (RethinkDNS, Cloudflare
//! trace, WARP, Mullvad) and the answer is cached per proxy, family and address for an hour (12 minutes for the
//! built-in proxies), unless the proxy's dialer changed. firestack also asks Windscribe's geo API with a made-up
//! bearer token; the fork does not send forged credentials to a third party, so that step is skipped.

use crate::{INTERNET, Proxy, SharedProxy, TKO, TOK, local};
use fs_core::bridge::BoxFuture;
use fs_core::settings;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Resolves `host` on the DNS transport `tid` (set by the tunnel).
pub type IdResolver = Arc<dyn Fn(String, String) -> BoxFuture<Vec<IpAddr>> + Send + Sync>;

const SHORT_HTTP_TIMEOUT: Duration = Duration::from_secs(4);
const MAX_BODY: usize = 128 * 1024;
const MAX_LIFETIME: Duration = Duration::from_secs(3600);
const MIN_LIFETIME: Duration = Duration::from_secs(12 * 60);

pub const IPINFO_URL: &str = "https://dl.rethinkdns.com/ip";
pub const TRACE_URL: &str = "https://sky.rethinkdns.com/cdn-cgi/trace";
pub const WARP_URL: &str = "https://redir.nile.workers.dev/p/warp";
pub const MULLVAD4_URL: &str = "https://ipv4.am.i.mullvad.net/json";
pub const MULLVAD6_URL: &str = "https://ipv6.am.i.mullvad.net/json";

/// `backend.IPMetadata`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct IpMeta {
    pub id: String,
    pub provider_url: String,
    pub ip: String,
    pub asn: String,
    pub asn_org: String,
    pub asn_dom: String,
    pub cc: String,
    pub city: String,
    pub addr: String,
    pub lat: f64,
    pub lon: f64,
}

/// The provider URLs (tests point them elsewhere).
#[derive(Clone, Debug)]
pub struct Providers {
    pub ipinfo: String,
    pub trace: String,
    pub warp: String,
    pub mullvad4: String,
    pub mullvad6: String,
}

impl Default for Providers {
    fn default() -> Self {
        Providers {
            ipinfo: IPINFO_URL.into(),
            trace: TRACE_URL.into(),
            warp: WARP_URL.into(),
            mullvad4: MULLVAD4_URL.into(),
            mullvad6: MULLVAD6_URL.into(),
        }
    }
}

/// The process-wide client (firestack keeps its cache and resolver in package globals too).
pub fn client() -> &'static Client {
    static C: std::sync::OnceLock<Client> = std::sync::OnceLock::new();
    C.get_or_init(Client::default)
}

/// IP metadata lookups over proxies.
pub struct Client {
    cache: Mutex<HashMap<String, (u64, IpMeta, Instant)>>,
    resolver: parking_lot::RwLock<Option<IdResolver>>,
    pub providers: parking_lot::RwLock<Providers>,
    /// trust these roots instead of the system's (tests)
    tls: parking_lot::RwLock<Option<Arc<tokio_rustls::rustls::ClientConfig>>>,
}

impl Default for Client {
    fn default() -> Self {
        Client {
            cache: Mutex::new(HashMap::new()),
            resolver: parking_lot::RwLock::new(None),
            providers: parking_lot::RwLock::new(Providers::default()),
            tls: parking_lot::RwLock::new(None),
        }
    }
}

fn key(p: &dyn Proxy, v6: bool) -> String {
    format!(
        "{}/{}/{}",
        p.id(),
        if v6 { "tcp6" } else { "tcp4" },
        p.addr()
    )
}

/// firestack `fetchIPMetadata` step error.
fn e(s: impl Into<String>) -> String {
    s.into()
}

impl Client {
    pub fn set_resolver(&self, r: IdResolver) {
        *self.resolver.write() = Some(r);
    }

    pub fn set_tls(&self, c: Arc<tokio_rustls::rustls::ClientConfig>) {
        *self.tls.write() = Some(c);
    }

    /// firestack `ClearIPMeta`.
    pub fn clear(&self) {
        self.cache.lock().clear();
    }

    fn cached(&self, p: &dyn Proxy, v6: bool) -> Option<IpMeta> {
        let k = key(p, v6);
        let mut c = self.cache.lock();
        let (h, m, exp) = c.get(&k)?.clone();
        if exp <= Instant::now() {
            return None;
        }
        if h != p.handle() {
            c.remove(&k);
            return None;
        }
        Some(m)
    }

    fn remember(&self, p: &dyn Proxy, v6: bool, m: &IpMeta) {
        // local proxies' dialers never change with the network, so their answers go stale sooner
        let ttl = if local(p.id()) {
            MIN_LIFETIME
        } else {
            MAX_LIFETIME
        };
        let mut c = self.cache.lock();
        if c.len() >= 256 {
            let now = Instant::now();
            c.retain(|_, (_, _, e)| *e > now);
        }
        c.insert(key(p, v6), (p.handle(), m.clone(), Instant::now() + ttl));
    }

    /// `Client.IP4()` (`v6` false) / `Client.IP6()`.
    pub async fn ip_metadata(&self, p: SharedProxy, v6: bool) -> Result<IpMeta, String> {
        if let Some(m) = self.cached(&*p, v6) {
            return Ok(m);
        }
        let st = p.status();
        if st != TOK && st != TKO {
            return Err(e("proxy: not active"));
        }
        if (!v6 && !p.ip4()) || (v6 && !p.ip6()) {
            return Err(e("proxy: no route to host"));
        }
        let pv = self.providers.read().clone();
        let mut meta = IpMeta {
            id: p.id().to_string(),
            ..Default::default()
        };
        let mullvad = if v6 { &pv.mullvad6 } else { &pv.mullvad4 };
        let mut errs = Vec::new();
        let found = 'found: {
            for (url, apply) in [
                (
                    &pv.ipinfo,
                    apply_ipinfo as fn(&mut IpMeta, &[u8]) -> Result<(), String>,
                ),
                (&pv.trace, apply_trace),
                (&pv.warp, apply_warp),
                (mullvad, apply_mullvad),
            ] {
                match self.fetch(&p, v6, url).await {
                    Ok(body) => match apply(&mut meta, &body) {
                        Ok(()) => {
                            meta.provider_url = url.clone();
                            break 'found true;
                        }
                        Err(x) => errs.push(x),
                    },
                    Err(x) => errs.push(x),
                }
            }
            false
        };
        let tag = if v6 { "tcp6" } else { "tcp4" };
        if !found || meta.ip.is_empty() {
            errs.insert(0, format!("proxy: client: {} {tag} lookup failed", p.id()));
            return Err(errs.join("\n"));
        }
        self.remember(&*p, v6, &meta);
        Ok(meta)
    }

    /// firestack `httpClient`'s dialer: the DNS of the proxy (or Default for Exit, and for Base unless looping
    /// back; else Preferred), falling back to Default when allowed; addresses of the family; the first that dials.
    async fn dial(
        &self,
        p: &SharedProxy,
        v6: bool,
        host: &str,
        port: u16,
    ) -> Result<fs_dialers::TcpConn, String> {
        let pid = p.id().to_string();
        let dnsid = if !p.dns().is_empty() {
            pid.clone()
        } else if p.typ() == INTERNET
            || (local(&pid) && !settings::LOOPINGBACK.load(Ordering::Relaxed))
        {
            "Default".to_string()
        } else {
            "Preferred".to_string()
        };
        let ips: Vec<IpAddr> = if let Ok(ip) = host.parse::<IpAddr>() {
            vec![ip]
        } else {
            let r = self
                .resolver
                .read()
                .clone()
                .ok_or_else(|| e("proxy: client: no resolver"))?;
            let mut ips = r(host.to_string(), dnsid.clone()).await;
            if ips.is_empty()
                && dnsid != "Default"
                && settings::DEFAULT_DNS_AS_FALLBACK.load(Ordering::Relaxed)
            {
                ips = r(host.to_string(), "Default".to_string()).await;
            }
            if ips.is_empty() {
                return Err(format!(
                    "proxy: client: {pid} resolve {dnsid} err {host}: no answer"
                ));
            }
            ips
        };
        let ips: Vec<IpAddr> = ips.into_iter().filter(|ip| ip.is_ipv6() == v6).collect();
        if ips.is_empty() {
            return Err(e("proxy: no suitable address"));
        }
        let mut last = String::new();
        for ip in ips {
            match p
                .dial_tcp(SocketAddr::new(ip, port), SHORT_HTTP_TIMEOUT)
                .await
            {
                Ok(c) => return Ok(c),
                Err(x) => last = format!("proxy: client: {pid} failed to dial {host} @ {ip}: {x}"),
            }
        }
        Err(last)
    }

    /// firestack `fetch`: an HTTPS (or, for tests, HTTP) GET over the proxy; a 2xx body of at most 128 KiB.
    async fn fetch(&self, p: &SharedProxy, v6: bool, url: &str) -> Result<Vec<u8>, String> {
        tokio::time::timeout(SHORT_HTTP_TIMEOUT, self.fetch_inner(p, v6, url))
            .await
            .map_err(|_| format!("proxy: client: ip lookup {url}: timeout"))?
    }

    async fn fetch_inner(&self, p: &SharedProxy, v6: bool, url: &str) -> Result<Vec<u8>, String> {
        let (tls, rest) = if let Some(r) = url.strip_prefix("https://") {
            (true, r)
        } else if let Some(r) = url.strip_prefix("http://") {
            (false, r)
        } else {
            return Err(format!("proxy: client: bad url {url}"));
        };
        let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
        let path = if path.is_empty() { "/" } else { path };
        let (host, port) = split_authority(authority, if tls { 443 } else { 80 })?;
        let c = self.dial(p, v6, &host, port).await?;
        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: Go-http-client/1.1\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        );
        let raw = if tls {
            let cfg = self
                .tls
                .read()
                .clone()
                .unwrap_or_else(|| fs_dns::tls::client_config(&[b"http/1.1"]));
            let sni =
                rustls_pki_types::ServerName::try_from(host.clone()).map_err(|x| x.to_string())?;
            let s = tokio_rustls::TlsConnector::from(cfg)
                .connect(sni, c)
                .await
                .map_err(|x| format!("proxy: client: tls {host}: {x}"))?;
            roundtrip(s, &req).await
        } else {
            roundtrip(c, &req).await
        }
        .map_err(|x| format!("proxy: client: ip lookup {url}: {x}"))?;
        let (status, body) = parse_response(&raw)?;
        if !(200..300).contains(&status) {
            return Err(format!("proxy: client: ip lookup {url}: status {status}"));
        }
        Ok(body)
    }
}

fn split_authority(a: &str, default: u16) -> Result<(String, u16), String> {
    if let Some(r) = a.strip_prefix('[') {
        let (h, t) = r.split_once(']').ok_or_else(|| format!("bad host {a}"))?;
        let port = t
            .strip_prefix(':')
            .map(|p| p.parse().map_err(|_| format!("bad port {a}")))
            .transpose()?;
        return Ok((h.to_string(), port.unwrap_or(default)));
    }
    match a.rsplit_once(':') {
        Some((h, p)) => Ok((
            h.to_string(),
            p.parse().map_err(|_| format!("bad port {a}"))?,
        )),
        None => Ok((a.to_string(), default)),
    }
}

async fn roundtrip<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    mut s: S,
    req: &str,
) -> io::Result<Vec<u8>> {
    s.write_all(req.as_bytes()).await?;
    s.flush().await?;
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match s.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                if out.len() > MAX_BODY + 16 * 1024 {
                    break; // headers plus the most firestack reads of a body
                }
            }
            // servers that close without a TLS close_notify
            Err(x) if x.kind() == io::ErrorKind::UnexpectedEof && !out.is_empty() => break,
            Err(x) => return Err(x),
        }
    }
    Ok(out)
}

/// The status and (de-chunked, capped) body of an HTTP/1.1 response.
fn parse_response(raw: &[u8]) -> Result<(u16, Vec<u8>), String> {
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| e("proxy: client: truncated response"))?;
    let head = std::str::from_utf8(&raw[..end]).map_err(|_| e("proxy: client: bad response"))?;
    let mut lines = head.split("\r\n");
    let status: u16 = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| e("proxy: client: bad status line"))?;
    let (mut chunked, mut len) = (false, None);
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            let (k, v) = (k.trim(), v.trim());
            if k.eq_ignore_ascii_case("transfer-encoding")
                && v.to_ascii_lowercase().contains("chunked")
            {
                chunked = true;
            } else if k.eq_ignore_ascii_case("content-length") {
                len = v.parse::<usize>().ok();
            }
        }
    }
    let mut body = &raw[end + 4..];
    let mut out = Vec::new();
    if chunked {
        while let Some(i) = body.windows(2).position(|w| w == b"\r\n") {
            let sz = std::str::from_utf8(&body[..i])
                .ok()
                .and_then(|s| {
                    usize::from_str_radix(s.split(';').next().unwrap_or("").trim(), 16).ok()
                })
                .ok_or_else(|| e("proxy: client: bad chunk"))?;
            if sz == 0 {
                break;
            }
            let start = i + 2;
            let stop = (start + sz).min(body.len());
            out.extend_from_slice(&body[start..stop]);
            if stop < start + sz {
                break;
            }
            body = body.get(stop + 2..).unwrap_or_default();
        }
    } else {
        if let Some(n) = len {
            body = &body[..n.min(body.len())];
        }
        out.extend_from_slice(body);
    }
    out.truncate(MAX_BODY);
    Ok((status, out))
}

fn json(body: &[u8]) -> Result<serde_json::Value, String> {
    serde_json::from_slice(body).map_err(|x| x.to_string())
}

fn jstr<'a>(v: &'a serde_json::Value, k: &str) -> &'a str {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("")
}

fn jf64(v: &serde_json::Value, k: &str) -> f64 {
    v.get(k).and_then(|x| x.as_f64()).unwrap_or(0.0)
}

fn set(dst: &mut String, v: &str) {
    if !v.is_empty() {
        *dst = v.to_string();
    }
}

/// firestack `fetchIPinfo` + `applyIPinfo` (`dl.rethinkdns.com/ip`).
fn apply_ipinfo(m: &mut IpMeta, body: &[u8]) -> Result<(), String> {
    let v = json(body)?;
    if jstr(&v, "ip").is_empty() {
        return Err(e("proxy: client: empty ipinfo response"));
    }
    set(&mut m.ip, jstr(&v, "ip"));
    set(&mut m.asn, jstr(&v, "asn"));
    set(&mut m.asn_org, jstr(&v, "as_name"));
    set(&mut m.asn_dom, jstr(&v, "as_domain"));
    set(&mut m.cc, &jstr(&v, "country_code").to_uppercase());
    Ok(())
}

/// firestack `fetchTrace` + `applyTrace` (Cloudflare's `key=value` trace).
fn apply_trace(m: &mut IpMeta, body: &[u8]) -> Result<(), String> {
    let s = String::from_utf8_lossy(body);
    let kv: HashMap<&str, &str> = s
        .split('\n')
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| l.split_once('='))
        .collect();
    if kv.is_empty() {
        return Err(e("proxy: client: empty trace response"));
    }
    if let Some(ip) = kv.get("ip") {
        m.ip = ip.to_string();
    }
    if let Some(cc) = kv.get("loc") {
        m.cc = cc.to_uppercase();
    }
    Ok(())
}

/// firestack `fetchWarp` + `applyWarp`.
fn apply_warp(m: &mut IpMeta, body: &[u8]) -> Result<(), String> {
    let v = json(body)?;
    if jstr(&v, "ip").is_empty() {
        return Err(e("proxy: client: empty warp response"));
    }
    m.ip = jstr(&v, "ip").to_string();
    set(&mut m.cc, &jstr(&v, "country").to_uppercase());
    if !jstr(&v, "city").is_empty() {
        m.city = jstr(&v, "city").to_string();
    } else {
        set(&mut m.city, jstr(&v, "region"));
    }
    set(&mut m.asn_org, jstr(&v, "asorg"));
    let (lat, lon) = (jf64(&v, "latitude"), jf64(&v, "longitude"));
    if lat != 0.0 {
        m.lat = lat;
    }
    if lon != 0.0 {
        m.lon = lon;
    }
    Ok(())
}

/// firestack `fetchMullvad` + `applyMullvad` (its country is a name, not a code: not used, as firestack).
fn apply_mullvad(m: &mut IpMeta, body: &[u8]) -> Result<(), String> {
    let v = json(body)?;
    if jstr(&v, "ip").is_empty() {
        return Err(e("proxy: client: empty mullvad response"));
    }
    set(&mut m.ip, jstr(&v, "ip"));
    set(&mut m.city, jstr(&v, "city"));
    set(&mut m.asn_org, jstr(&v, "organization"));
    let (lat, lon) = (jf64(&v, "latitude"), jf64(&v, "longitude"));
    if lat != 0.0 {
        m.lat = lat;
    }
    if lon != 0.0 {
        m.lon = lon;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_providers() {
        let mut m = IpMeta::default();
        apply_ipinfo(&mut m, br#"{"ip":"14.139.180.67","asn":"AS55824","as_name":"NKN","as_domain":"nkn.gov.in","country_code":"in"}"#).unwrap();
        assert_eq!(
            (
                m.ip.as_str(),
                m.asn.as_str(),
                m.asn_org.as_str(),
                m.asn_dom.as_str(),
                m.cc.as_str()
            ),
            ("14.139.180.67", "AS55824", "NKN", "nkn.gov.in", "IN")
        );
        assert!(apply_ipinfo(&mut IpMeta::default(), b"{}").is_err());

        let mut m = IpMeta::default();
        apply_trace(
            &mut m,
            b"fl=1\nh=sky.rethinkdns.com\nip=2001:db8::1\nloc=br\n",
        )
        .unwrap();
        assert_eq!((m.ip.as_str(), m.cc.as_str()), ("2001:db8::1", "BR"));

        let mut m = IpMeta::default();
        apply_warp(&mut m, br#"{"ip":"1.2.3.4","country":"br","city":"","region":"Sao Paulo State","asorg":"NET","latitude":1.5}"#).unwrap();
        assert_eq!(
            (m.city.as_str(), m.cc.as_str(), m.lat, m.lon),
            ("Sao Paulo State", "BR", 1.5, 0.0)
        );

        let mut m = IpMeta::default();
        apply_mullvad(&mut m, br#"{"ip":"5.6.7.8","country":"Brazil","city":"Sao Paulo","longitude":-46.6,"latitude":-23.5,"organization":"Org"}"#).unwrap();
        assert_eq!(
            (m.ip.as_str(), m.cc.as_str(), m.asn_org.as_str(), m.lon),
            ("5.6.7.8", "", "Org", -46.6)
        );
    }

    #[test]
    fn parses_http() {
        let (s, b) =
            parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello trailing").unwrap();
        assert_eq!((s, b.as_slice()), (200, &b"hello"[..]));
        let (s, b) = parse_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nwiki\r\n5;x=y\r\npedia\r\n0\r\n\r\n").unwrap();
        assert_eq!((s, b.as_slice()), (200, &b"wikipedia"[..]));
        assert_eq!(
            parse_response(b"HTTP/1.1 404 Not Found\r\n\r\n").unwrap().0,
            404
        );
        assert_eq!(
            split_authority("[::1]:8080", 443).unwrap(),
            ("::1".into(), 8080)
        );
        assert_eq!(
            split_authority("dl.rethinkdns.com", 443).unwrap(),
            ("dl.rethinkdns.com".into(), 443)
        );
    }
}
