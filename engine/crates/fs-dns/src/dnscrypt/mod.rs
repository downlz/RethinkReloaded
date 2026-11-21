// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2020 RethinkDNS and its authors.
// Copyright (c) 2018-2021 Frank Denis <j at pureftpd dot org>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/dnscrypt/multiserver.go (ISC portions: dnscrypt-proxy)
// Derived-From: celzero/firestack@d3d530ea3e:intra/dnscrypt/servers.go
// Derived-From: celzero/firestack@d3d530ea3e:intra/dnscrypt/certs.go
// Derived-From: celzero/firestack@d3d530ea3e:intra/dnscrypt/intercept.go
// Derived-From: celzero/firestack@d3d530ea3e:intra/dnscrypt/fresh.go

//! DNSCrypt v2 and anonymized DNSCrypt (firestack `DcMulti`): servers are registered by id and stamp, their
//! certificates fetched over Exit (never through relays) and refreshed every four hours. Queries go over UDP (two
//! tries, then TCP) to the server, or to a random relay with the anonymization header. A server's transport is a
//! by-id view (`ServerById`), so refreshed certificates take effect without re-adding it.

pub mod cert;
pub mod crypto;

use crate::msg;
use crate::stamp::{self, Stamp};
use crate::transport::{Answer, QueryError, Stats, TYPE_DNSCRYPT, Transport};
use crypto::{
    Construction, MAX_DNS_PACKET, MAX_DNS_UDP_PACKET, MIN_DNS_PACKET, RESPONSE_OVERHEAD, Session,
};
use fs_core::bridge::{BoxFuture, dns_status};
use fs_dialers::SharedDial;
use hickory_proto::op::{Edns, ResponseCode};
use hickory_proto::rr::{DNSClass, RData, RecordType};
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const TIMEOUT: Duration = Duration::from_secs(8);
const UDP_TRIES: usize = 2;
const CERT_REFRESH: Duration = Duration::from_secs(240 * 60);
const CERT_RETRY: Duration = Duration::from_secs(10);
/// certificates are fetched over Exit (firestack `proxy.exit`)
const CERT_PID: &str = "Exit";
/// TXT queries for certificates are padded so answers come back large enough (firestack `minsz`)
const CERT_QUERY_MIN: usize = 480;

fn now_unix() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

/// A DNSCrypt server with a valid certificate.
pub struct Server {
    host_name: String,
    orig_addr: String,
    addr: SocketAddr,
    session: Session,
    stats: Stats,
}

/// firestack `DcMulti`: the tunnel's DNSCrypt servers and relays.
pub struct DcMulti {
    sk: [u8; 32],
    pk: [u8; 32],
    dialer: SharedDial,
    registered: RwLock<HashMap<String, Stamp>>,
    servers: RwLock<HashMap<String, Arc<Server>>>,
    /// relay stamps (or `host:port`s), in the order added
    routes: Mutex<Vec<String>>,
    relays: RwLock<Vec<SocketAddr>>,
    ignore_ts: AtomicBool,
}

impl DcMulti {
    /// Must be called within a tokio runtime (it spawns the certificate refresher).
    pub fn new(dialer: SharedDial) -> Arc<Self> {
        let sk: [u8; 32] = crypto::random();
        let dc = Arc::new(DcMulti {
            pk: crypto::public_key(&sk),
            sk,
            dialer,
            registered: RwLock::new(HashMap::new()),
            servers: RwLock::new(HashMap::new()),
            routes: Mutex::new(Vec::new()),
            relays: RwLock::new(Vec::new()),
            ignore_ts: AtomicBool::new(false),
        });
        let me = Arc::downgrade(&dc);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(CERT_REFRESH).await;
                let Some(dc) = me.upgrade() else { return };
                dc.refresh_certs().await;
            }
        });
        dc
    }

    /// firestack `AddTransport`: registers `id` and fetches its certificate (failing when there is none).
    pub async fn add(self: &Arc<Self>, id: &str, stamp: &str) -> Result<Arc<ServerById>, String> {
        let st = Stamp::parse(stamp)
            .map_err(|e| format!("dnscrypt: stamp error for [{stamp}] def: [{e}]"))?;
        if st.proto == stamp::PROTO_DOH {
            return Err(format!("dnscrypt: doh not supported {stamp}"));
        }
        self.registered.write().insert(id.to_string(), st.clone());
        match self.refresh_one(id, &st).await {
            Ok(_) => Ok(Arc::new(ServerById {
                id: id.to_string(),
                dc: Arc::downgrade(self),
            })),
            Err(e) => {
                self.remove_server(id);
                Err(format!("dnscrypt: error refreshing cert: {e}"))
            }
        }
    }

    /// firestack `AddRelayTransport` / `AddGateways`.
    pub fn add_relay(&self, stamp: &str) -> Result<(), String> {
        if stamp.is_empty() {
            return Err("dnscrypt: specify atleast one route".into());
        }
        {
            let mut r = self.routes.lock();
            for s in stamp.split(',').filter(|s| !s.is_empty()) {
                if !r.iter().any(|x| x == s) {
                    r.push(s.to_string());
                }
            }
        }
        self.refresh_routes();
        Ok(())
    }

    /// firestack `Remove`: a server or a relay.
    pub fn remove(&self, id: &str) -> bool {
        let server = self.remove_server(id);
        let relay = {
            let mut r = self.routes.lock();
            let n = r.len();
            r.retain(|x| x != id);
            n != r.len()
        };
        if relay {
            self.refresh_routes();
        }
        server || relay
    }

    fn remove_server(&self, id: &str) -> bool {
        let a = self.registered.write().remove(id).is_some();
        let b = self.servers.write().remove(id).is_some();
        a || b
    }

    pub fn has_relay(&self, id: &str) -> bool {
        self.routes.lock().iter().any(|x| x == id)
    }

    /// Ids of servers with a valid certificate (firestack `LiveTransports`).
    pub fn live(&self) -> Vec<String> {
        self.servers.read().keys().cloned().collect()
    }

    fn server(&self, id: &str) -> Option<Arc<Server>> {
        self.servers.read().get(id).cloned()
    }

    /// firestack `route`: relay stamps (DNSCrypt or relay protocol) or bare `ip[:port]`s to addresses.
    fn refresh_routes(&self) {
        let routes = self.routes.lock().clone();
        let mut addrs = Vec::new();
        for r in routes {
            let st = Stamp::parse(&r).ok().filter(|s| {
                s.proto == stamp::PROTO_DNSCRYPT || s.proto == stamp::PROTO_DNSCRYPT_RELAY
            });
            let a = match st {
                Some(s) => host_port(&s.addr),
                None => host_port(&r),
            };
            // hostnames are not resolved here (stamps carry addresses)
            if let Some(a) = a {
                addrs.push(a);
            }
        }
        *self.relays.write() = addrs;
    }

    async fn refresh_one(&self, id: &str, st: &Stamp) -> Result<Arc<Server>, String> {
        let s = Arc::new(self.fetch(id, st).await?);
        self.servers.write().insert(id.to_string(), s.clone());
        Ok(s)
    }

    /// firestack's periodic refresh: re-fetches every registered certificate; when none is valid, retries with a
    /// growing delay, ignoring certificate timestamps (a clock that is off should not take DNS down).
    async fn refresh_certs(&self) {
        for attempt in 1..=10u32 {
            let reg: Vec<(String, Stamp)> = self
                .registered
                .read()
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            if reg.is_empty() {
                return;
            }
            let mut alive = 0;
            for (id, st) in &reg {
                if self.refresh_one(id, st).await.is_ok() {
                    alive += 1;
                }
            }
            if alive > 0 {
                self.ignore_ts.store(false, Ordering::Relaxed);
                return;
            }
            self.ignore_ts.store(true, Ordering::Relaxed);
            tokio::time::sleep(CERT_RETRY * attempt).await;
        }
    }

    /// firestack `fetchDNSCryptServerInfo`.
    async fn fetch(&self, id: &str, st: &Stamp) -> Result<Server, String> {
        let pk: [u8; 32] = match st.server_pk.len() {
            32 => st.server_pk.clone().try_into().unwrap(),
            _ => {
                // legacy: hex, possibly colon-separated
                let s = String::from_utf8_lossy(&st.server_pk).replace(':', "");
                let b: Option<Vec<u8>> = (0..s.len())
                    .step_by(2)
                    .map(|i| s.get(i..i + 2).and_then(|x| u8::from_str_radix(x, 16).ok()))
                    .collect();
                b.filter(|b| b.len() == 32)
                    .map(|b| b.try_into().unwrap())
                    .ok_or_else(|| format!("unsupported public key for [{id}]"))?
            }
        };
        let addr =
            host_port(&st.addr).ok_or_else(|| format!("dnscrypt: no ips for [{}]", st.addr))?;
        let provider = if st.provider_name.ends_with('.') {
            st.provider_name.clone()
        } else {
            format!("{}.", st.provider_name)
        };
        let records = self.cert_txt(&provider, addr).await?;
        let c = cert::pick(
            &pk,
            &records,
            now_unix(),
            self.ignore_ts.load(Ordering::Relaxed),
        )
        .ok_or_else(|| format!("no useable cert found for {}", st.addr))?;
        let shared_key = crypto::shared_key(c.construction, &self.sk, &c.server_pk);
        Ok(Server {
            host_name: st.provider_name.clone(),
            orig_addr: st.addr.clone(),
            addr,
            session: Session {
                construction: c.construction,
                shared_key,
                client_pk: self.pk,
                magic: c.magic,
            },
            stats: Stats::default(),
        })
    }

    /// firestack `dnsExchange`: the certificate TXT query, over UDP and TCP alternately (four attempts, 200 ms
    /// apart); the first answer wins.
    async fn cert_txt(&self, provider: &str, addr: SocketAddr) -> Result<Vec<Vec<u8>>, String> {
        let id: [u8; 2] = crypto::random();
        let mut q = msg::query(provider, RecordType::TXT, u16::from_be_bytes(id))
            .ok_or("dnscrypt: bad provider name")?;
        let pad = CERT_QUERY_MIN.saturating_sub(provider.len());
        let mut e = Edns::new();
        e.set_max_payload(4096);
        e.options_mut()
            .insert(hickory_proto::rr::rdata::opt::EdnsOption::Unknown(
                12,
                vec![0u8; pad],
            ));
        q.set_edns(e);
        let udp_q = msg::pack(&q).ok_or("dnscrypt: pack")?;
        q.edns = None;
        let tcp_q = msg::pack(&q).ok_or("dnscrypt: pack")?;
        let mut tasks = tokio::task::JoinSet::new();
        for attempt in 0..4u64 {
            let (dialer, udp_q, tcp_q) = (self.dialer.clone(), udp_q.clone(), tcp_q.clone());
            tasks.spawn(async move {
                tokio::time::sleep(Duration::from_millis(200 * attempt)).await;
                let r = if attempt % 2 == 0 {
                    udp_exchange(&dialer, CERT_PID, addr, &udp_q).await
                } else {
                    tcp_exchange(&dialer, CERT_PID, addr, &tcp_q).await
                };
                r.and_then(|b| {
                    msg::parse(&b).ok_or_else(|| "dnscrypt: bad cert answer".to_string())
                })
            });
        }
        let mut last = "dnscrypt: cannot reach server to fetch certs".to_string();
        while let Some(r) = tasks.join_next().await {
            match r {
                Ok(Ok(m)) => {
                    let txts = m
                        .answers
                        .iter()
                        .filter_map(|rr| match &rr.data {
                            RData::TXT(t) => {
                                Some(t.txt_data.iter().flat_map(|s| s.iter().copied()).collect())
                            }
                            _ => None,
                        })
                        .collect();
                    return Ok(txts);
                }
                Ok(Err(e)) => last = e,
                Err(e) => last = e.to_string(),
            }
        }
        Err(last)
    }
}

/// `ip:port` (`[v6]:port`), or a bare ip with port 443 (firestack `hostport`); hostnames are not resolved.
fn host_port(s: &str) -> Option<SocketAddr> {
    if let Ok(a) = s.parse::<SocketAddr>() {
        return Some(a);
    }
    s.trim_matches(['[', ']'])
        .parse::<IpAddr>()
        .ok()
        .map(|ip| SocketAddr::new(ip, 443))
}

async fn udp_exchange(
    dialer: &SharedDial,
    pid: &str,
    to: SocketAddr,
    q: &[u8],
) -> Result<Vec<u8>, String> {
    let sock = dialer.dial_udp(pid, to).await.map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; MAX_DNS_UDP_PACKET + RESPONSE_OVERHEAD + 64];
    let mut last = String::from("dnscrypt: no connection");
    for _ in 0..UDP_TRIES {
        sock.send(q).await.map_err(|e| e.to_string())?;
        match tokio::time::timeout(TIMEOUT, sock.recv(&mut buf)).await {
            Ok(Ok(n)) => return Ok(buf[..n].to_vec()),
            Ok(Err(e)) => last = e.to_string(),
            Err(_) => last = "dnscrypt: udp timeout".into(),
        }
    }
    Err(last)
}

async fn tcp_exchange(
    dialer: &SharedDial,
    pid: &str,
    to: SocketAddr,
    q: &[u8],
) -> Result<Vec<u8>, String> {
    let io = async {
        let mut s = dialer.dial_tcp(pid, to, TIMEOUT).await?;
        let mut framed = (q.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(q);
        s.write_all(&framed).await?;
        let mut len = [0u8; 2];
        s.read_exact(&mut len).await?;
        let n = u16::from_be_bytes(len) as usize;
        if n > MAX_DNS_PACKET + RESPONSE_OVERHEAD + 64 {
            return Err(std::io::Error::other("dnscrypt: response too large"));
        }
        let mut out = vec![0u8; n];
        s.read_exact(&mut out).await?;
        Ok::<_, std::io::Error>(out)
    };
    match tokio::time::timeout(TIMEOUT, io).await {
        Ok(r) => r.map_err(|e| e.to_string()),
        Err(_) => Err("dnscrypt: tcp timeout".into()),
    }
}

/// firestack `prepareForRelay`: `0xff×8 ‖ 0x0000 ‖ server ip (16 bytes) ‖ server port ‖ query`.
fn for_relay(server: SocketAddr, q: &[u8]) -> Vec<u8> {
    let mut out = vec![0xff; 8];
    out.extend_from_slice(&[0, 0]);
    let ip16 = match server.ip() {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    };
    out.extend_from_slice(&ip16.octets());
    out.extend_from_slice(&server.port().to_be_bytes());
    out.extend_from_slice(q);
    out
}

/// What the intercept decided for a query (firestack `intercept.handleRequest`).
enum Intercepted {
    /// forward this (re-packed) query
    Forward(Vec<u8>),
    /// answer locally (unqualified A/AAAA names: NXDOMAIN)
    Synth(Vec<u8>),
}

fn intercept_request(q: &[u8]) -> Result<Intercepted, String> {
    let mut m = msg::parse(q).ok_or("dnscrypt: query size too short")?;
    if m.queries.len() != 1 {
        return Err("unexpected number of questions".into());
    }
    let qn = msg::qname(&m);
    let question = &m.queries[0];
    if question.query_class() == DNSClass::IN
        && matches!(question.query_type(), RecordType::A | RecordType::AAAA)
        && !qn.contains('.')
    {
        let mut r = msg::empty_response(&m);
        r.metadata.response_code = ResponseCode::NXDomain;
        return Ok(Intercepted::Synth(msg::pack(&r).ok_or("dnscrypt: pack")?));
    }
    // getSetPayloadSize: advertise what the client can take over unencrypted UDP, less the response overhead
    let (mut client_safe, mut orig_max, mut dnssec) = (
        crypto::MAX_DNS_UDP_SAFE_PACKET as i64,
        512 - RESPONSE_OVERHEAD as i64,
        false,
    );
    let mut opts = None;
    if let Some(e) = &m.edns {
        client_safe = e.max_payload() as i64;
        orig_max = (client_safe - RESPONSE_OVERHEAD as i64).max(orig_max);
        dnssec = e.flags().dnssec_ok;
        if !e.options().as_ref().is_empty() {
            opts = Some(e.options().clone());
        }
    }
    let max = (client_safe - RESPONSE_OVERHEAD as i64)
        .min(orig_max.max(MAX_DNS_UDP_PACKET as i64 - RESPONSE_OVERHEAD as i64));
    if max > 512 {
        let mut e = Edns::new();
        e.set_max_payload(max as u16);
        e.flags_mut().dnssec_ok = dnssec;
        if let Some(o) = opts {
            *e.options_mut() = o;
        }
        m.set_edns(e);
    }
    Ok(Intercepted::Forward(msg::pack(&m).ok_or("dnscrypt: pack")?))
}

/// firestack `intercept.handleResponse`: drops EDNS options (truncation for UDP clients is not applied; see PARITY).
fn intercept_response(r: &[u8]) -> Result<Vec<u8>, String> {
    let mut m = msg::parse(r).ok_or("dnscrypt: bad response")?;
    if let Some(e) = m.edns.as_mut() {
        *e.options_mut() = Default::default();
    }
    msg::pack(&m).ok_or_else(|| "dnscrypt: pack".into())
}

impl Server {
    /// firestack `query` + `resolve`.
    async fn exchange(
        &self,
        dialer: &SharedDial,
        relays: &[SocketAddr],
        q: &[u8],
        pid: &str,
    ) -> Result<Answer, QueryError> {
        let start = Instant::now();
        let fail = |status: i32, m: String| QueryError {
            status,
            msg: m,
            server: self.host_name.clone(),
        };
        let fwd = match intercept_request(q).map_err(|e| fail(dns_status::BAD_QUERY, e))? {
            Intercepted::Synth(a) => {
                return Ok(Answer {
                    msg: a,
                    server: self.host_name.clone(),
                    pid: pid.to_string(),
                    ..Default::default()
                });
            }
            Intercepted::Forward(f) => f,
        };
        let relay = (!relays.is_empty())
            .then(|| relays[usize::from(crypto::random::<1>()[0]) % relays.len()]);
        let upstream = relay.unwrap_or(self.addr);
        let (enc, nonce) = crypto::encrypt(&self.session, &fwd, true, relay.is_some())
            .map_err(|e| fail(dns_status::INTERNAL_ERROR, e))?;
        let wire = |e: Vec<u8>| match relay {
            Some(_) => for_relay(self.addr, &e),
            None => e,
        };
        let mut r = udp_exchange(dialer, pid, upstream, &wire(enc))
            .await
            .and_then(|b| crypto::decrypt(&self.session, &b, &nonce));
        if r.is_err() {
            // TCP: padded differently, so encrypted afresh
            let (enc, nonce) = crypto::encrypt(&self.session, &fwd, false, relay.is_some())
                .map_err(|e| fail(dns_status::INTERNAL_ERROR, e))?;
            r = tcp_exchange(dialer, pid, upstream, &wire(enc))
                .await
                .and_then(|b| crypto::decrypt(&self.session, &b, &nonce));
        }
        let plain = r.map_err(|e| {
            self.stats.err(dns_status::SEND_FAILED);
            fail(dns_status::SEND_FAILED, e)
        })?;
        if plain.len() < MIN_DNS_PACKET || plain.len() > MAX_DNS_PACKET {
            self.stats.err(dns_status::BAD_RESPONSE);
            return Err(fail(
                dns_status::BAD_RESPONSE,
                "dnscrypt: response too large or too small".into(),
            ));
        }
        let ans = intercept_response(&plain).map_err(|e| {
            self.stats.err(dns_status::BAD_RESPONSE);
            fail(dns_status::BAD_RESPONSE, e)
        })?;
        let latency = start.elapsed();
        self.stats.ok(latency);
        Ok(Answer {
            msg: ans,
            server: self.host_name.clone(),
            // firestack reports the relay (when used) as the summary's pid
            pid: relay
                .map(|a| a.to_string())
                .unwrap_or_else(|| pid.to_string()),
            latency,
            ..Default::default()
        })
    }
}

/// firestack `severbyid`: a DNSCrypt transport that looks its server up on every query.
pub struct ServerById {
    id: String,
    dc: Weak<DcMulti>,
}

impl ServerById {
    fn server(&self) -> Option<(Arc<DcMulti>, Arc<Server>)> {
        let dc = self.dc.upgrade()?;
        let s = dc.server(&self.id)?;
        Some((dc, s))
    }
    /// The server's address as configured (firestack `OriginalAddr`).
    pub fn original_addr(&self) -> String {
        self.server()
            .map(|(_, s)| s.orig_addr.clone())
            .unwrap_or_default()
    }
    pub fn construction(&self) -> Construction {
        self.server()
            .map(|(_, s)| s.session.construction)
            .unwrap_or_default()
    }
}

impl Transport for ServerById {
    fn id(&self) -> &str {
        &self.id
    }
    fn typ(&self) -> &str {
        TYPE_DNSCRYPT
    }
    fn addr(&self) -> String {
        self.server()
            .map(|(_, s)| s.host_name.clone())
            .unwrap_or_default()
    }
    fn status(&self) -> i32 {
        // an unregistered server is as good as ended
        self.server()
            .map(|(_, s)| s.stats.status())
            .unwrap_or(dns_status::DEND)
    }
    fn p50(&self) -> i64 {
        self.server().map(|(_, s)| s.stats.p50()).unwrap_or(0)
    }
    fn query(self: Arc<Self>, q: Vec<u8>, pid: String) -> BoxFuture<Result<Answer, QueryError>> {
        Box::pin(async move {
            let (dc, s) = self.server().ok_or_else(|| {
                QueryError::new(dns_status::TRANSPORT_ERROR, "dnscrypt: server not found")
            })?;
            let relays = dc.relays.read().clone();
            s.exchange(&dc.dialer, &relays, &q, &pid).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_header() {
        let r = for_relay("1.2.3.4:443".parse().unwrap(), b"Q");
        assert_eq!(
            &r[..10],
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0]
        );
        assert_eq!(
            &r[10..26],
            &std::net::Ipv4Addr::new(1, 2, 3, 4)
                .to_ipv6_mapped()
                .octets()
        );
        assert_eq!(&r[26..], &[0x01, 0xbb, b'Q']);
    }

    #[test]
    fn intercepts() {
        let q = msg::pack(&msg::query("localhost.", RecordType::A, 7).unwrap()).unwrap();
        let Intercepted::Synth(a) = intercept_request(&q).unwrap() else {
            panic!("unqualified names are answered")
        };
        assert_eq!(
            msg::parse(&a).unwrap().metadata.response_code,
            ResponseCode::NXDomain
        );
        let q = msg::pack(&msg::query("example.com.", RecordType::A, 7).unwrap()).unwrap();
        let Intercepted::Forward(f) = intercept_request(&q).unwrap() else {
            panic!()
        };
        assert_eq!(
            msg::parse(&f).unwrap().edns.unwrap().max_payload(),
            1252 - RESPONSE_OVERHEAD as u16
        );
    }

    #[test]
    fn session_roundtrip() {
        // a server's response is its own box under the same shared key, with the server magic and full nonce
        for c in [
            Construction::XSalsa20Poly1305,
            Construction::XChaCha20Poly1305,
        ] {
            let (csk, ssk): ([u8; 32], [u8; 32]) = (crypto::random(), crypto::random());
            let s = Session {
                construction: c,
                shared_key: crypto::shared_key(c, &csk, &crypto::public_key(&ssk)),
                client_pk: crypto::public_key(&csk),
                magic: *b"magic123",
            };
            let q = msg::pack(&msg::query("example.com.", RecordType::A, 9).unwrap()).unwrap();
            let (enc, cn) = crypto::encrypt(&s, &q, true, false).unwrap();
            assert_eq!(enc.len(), crypto::MAX_DNS_UDP_SAFE_PACKET);
            // server side: same shared key from its secret and the client's key
            let sk = crypto::shared_key(c, &ssk, &s.client_pk);
            let mut nonce = [0u8; 24];
            nonce[..12].copy_from_slice(&enc[40..52]);
            let body = crypto::open(c, &sk, &nonce, &enc[52..]).unwrap();
            assert_eq!(crypto::unpad(&body).unwrap(), &q[..]);
            nonce[12..].copy_from_slice(&[5; 12]);
            let mut resp = crypto::SERVER_MAGIC.to_vec();
            resp.extend_from_slice(&nonce);
            resp.extend_from_slice(&crypto::seal(
                c,
                &sk,
                &nonce,
                &crypto::pad(q.clone(), q.len() + 40),
            ));
            assert_eq!(crypto::decrypt(&s, &resp, &cn).unwrap(), q);
            assert!(
                crypto::decrypt(&s, &resp, &[0; crypto::HALF_NONCE]).is_err(),
                "nonce must match"
            );
        }
    }
}
