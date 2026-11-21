// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/dns53/mdns.go (oneshot queries)

//! Multicast DNS (`Local`, RFC 6762 §5.1 one-shot queries): the question goes from unprotected-by-the-tunnel
//! (protected) unicast sockets to 224.0.0.251:5353 and [ff02::fb]:5353; responses are collected for three seconds and
//! the first one with an address for the queried name (or a CNAME target of it) answers. The answer is rebuilt
//! around the app's question (mDNS responses carry no question section and id 0). Families follow the link.

use crate::msg;
use crate::transport::{Answer, QueryError, Stats, TYPE_DNS53, Transport};
use fs_core::bridge::{BoxFuture, dns_status};
use fs_dialers::SharedDial;
use hickory_proto::rr::RData;
use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub const ID: &str = "mdns";
const ONESHOT_TIMEOUT: Duration = Duration::from_secs(3);
const MDNS4: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)), 5353);
const MDNS6: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb)),
    5353,
);

pub struct MdnsTransport {
    dialer: SharedDial,
    use4: AtomicBool,
    use6: AtomicBool,
    stats: Stats,
}

impl MdnsTransport {
    pub fn new(dialer: SharedDial) -> Self {
        MdnsTransport {
            dialer,
            use4: AtomicBool::new(true),
            use6: AtomicBool::new(true),
            stats: Stats::default(),
        }
    }

    /// firestack `RefreshProto`: `l3` is "4", "6" or "46".
    pub fn refresh_proto(&self, l3: &str) {
        self.use4.store(l3.contains('4'), Ordering::Relaxed);
        self.use6.store(l3.contains('6'), Ordering::Relaxed);
    }

    async fn oneshot(&self, q: &[u8]) -> Result<Vec<u8>, QueryError> {
        let qm = msg::parse(q)
            .ok_or_else(|| QueryError::new(dns_status::BAD_QUERY, "mdns: no query"))?;
        let qname = msg::qname(&qm);
        // firestack ExtractMDNSDomain: answers are expected for the service (the name without its last label)
        let svc = qname
            .rsplit_once('.')
            .map(|(s, _)| s)
            .unwrap_or(&qname)
            .to_string();
        let mut out_q = qm.clone();
        out_q.metadata.recursion_desired = false;
        out_q.metadata.id = 0;
        let wire = msg::pack(&out_q)
            .ok_or_else(|| QueryError::new(dns_status::BAD_QUERY, "mdns: pack"))?;
        let mut socks = Vec::new();
        for (on, dst, v6) in [
            (self.use4.load(Ordering::Relaxed), MDNS4, false),
            (self.use6.load(Ordering::Relaxed), MDNS6, true),
        ] {
            if !on {
                continue;
            }
            if let Ok(s) = self.dialer.announce_udp("Base", v6).await
                && s.send_to(&wire, dst).await.is_ok()
            {
                socks.push(s);
            }
        }
        if socks.is_empty() {
            return Err(QueryError::new(
                dns_status::TRANSPORT_ERROR,
                "mdns: no socket",
            ));
        }
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
        let mut readers = tokio::task::JoinSet::new();
        for s in socks {
            let tx = tx.clone();
            readers.spawn(async move {
                let mut b = vec![0u8; 9000];
                while let Ok((n, _)) = s.recv_from(&mut b).await {
                    if tx.send(b[..n].to_vec()).await.is_err() {
                        return;
                    }
                }
            });
        }
        drop(tx);
        let deadline = Instant::now() + ONESHOT_TIMEOUT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let Ok(Some(raw)) = tokio::time::timeout(left, rx.recv()).await else {
                break;
            };
            let Some(m) = msg::parse(&raw) else { continue };
            // names of interest: the service and whatever it is an alias of
            let mut names: HashSet<String> = HashSet::new();
            let mut answers = Vec::new();
            let mut has_ip = false;
            let rrs: Vec<_> = m.answers.iter().chain(m.additionals.iter()).collect();
            for rr in &rrs {
                let n = msg::normalize(&rr.name.to_ascii());
                if let RData::CNAME(c) = &rr.data
                    && (n.contains(&svc) || names.contains(&n))
                {
                    names.insert(msg::normalize(&c.0.to_ascii()));
                    answers.push((*rr).clone());
                }
            }
            for rr in &rrs {
                let n = msg::normalize(&rr.name.to_ascii());
                if !(n.contains(&svc) || names.contains(&n)) {
                    continue;
                }
                match &rr.data {
                    RData::A(_) | RData::AAAA(_) => {
                        has_ip = true;
                        let mut r = (*rr).clone();
                        r.dns_class = hickory_proto::rr::DNSClass::IN; // drop the cache-flush bit
                        answers.push(r);
                    }
                    RData::PTR(_) | RData::SRV(_) | RData::TXT(_) => answers.push((*rr).clone()),
                    _ => {}
                }
            }
            if !has_ip && !matches!(msg::qtype(&qm), 12 | 16 | 33) {
                continue;
            }
            if answers.is_empty() {
                continue;
            }
            let mut r = msg::empty_response(&qm);
            r.answers = answers;
            readers.abort_all();
            return msg::pack(&r)
                .ok_or_else(|| QueryError::new(dns_status::BAD_RESPONSE, "mdns: pack"));
        }
        Err(QueryError::new(dns_status::NO_RESPONSE, "mdns: no answer"))
    }
}

impl Transport for MdnsTransport {
    fn id(&self) -> &str {
        ID
    }
    fn typ(&self) -> &str {
        TYPE_DNS53
    }
    fn addr(&self) -> String {
        MDNS4.to_string()
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
            match self.oneshot(&q).await {
                Ok(a) => {
                    let latency = start.elapsed();
                    self.stats.ok(latency);
                    Ok(Answer {
                        msg: a,
                        server: MDNS4.to_string(),
                        pid,
                        latency,
                        ..Default::default()
                    })
                }
                Err(e) => {
                    self.stats.err(e.status);
                    Err(e)
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fs_dialers::{Datagram, Dial, Fut, TcpConn, UdpConn};
    use hickory_proto::op::{Message, MessageType, OpCode};
    use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
    use std::io;
    use std::net::IpAddr;

    /// A responder on the other end of every "multicast" send: answers `printer.local` the way devices do (id 0,
    /// no question, cache-flush class), after an unrelated announcement.
    struct Responder(tokio::sync::Mutex<Vec<Vec<u8>>>, tokio::sync::Notify);

    fn announce(name: &str, ip: [u8; 4]) -> Vec<u8> {
        let mut m = Message::new(0, MessageType::Response, OpCode::Query);
        m.metadata.authoritative = true;
        let mut r = Record::from_rdata(
            Name::from_ascii(name).unwrap(),
            120,
            RData::A(Ipv4Addr::from(ip).into()),
        );
        r.dns_class = DNSClass::for_opt(0x8001); // cache-flush bit set on IN
        m.answers.push(r);
        msg::pack(&m).unwrap()
    }

    impl Datagram for Responder {
        fn send<'a>(&'a self, _: &'a [u8]) -> Fut<'a, io::Result<usize>> {
            Box::pin(async { Err(io::Error::other("unconnected")) })
        }
        fn recv<'a>(&'a self, _: &'a mut [u8]) -> Fut<'a, io::Result<usize>> {
            Box::pin(async { Err(io::Error::other("unconnected")) })
        }
        fn send_to<'a>(&'a self, b: &'a [u8], to: SocketAddr) -> Fut<'a, io::Result<usize>> {
            Box::pin(async move {
                assert_eq!(to.port(), 5353);
                let q = msg::parse(b).unwrap();
                assert!(!q.metadata.recursion_desired);
                let mut out = self.0.lock().await;
                out.push(announce("tv.local.", [192, 168, 1, 9]));
                if msg::qname(&q) == "printer.local" {
                    out.push(announce("printer.local.", [192, 168, 1, 7]));
                }
                self.1.notify_waiters();
                Ok(b.len())
            })
        }
        fn recv_from<'a>(&'a self, b: &'a mut [u8]) -> Fut<'a, io::Result<(usize, SocketAddr)>> {
            Box::pin(async move {
                loop {
                    if let Some(p) = { self.0.lock().await.pop() } {
                        b[..p.len()].copy_from_slice(&p);
                        return Ok((p.len(), "192.168.1.7:5353".parse().unwrap()));
                    }
                    self.1.notified().await;
                }
            })
        }
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("0.0.0.0:5353".parse().unwrap())
        }
    }

    struct Lan;
    impl Dial for Lan {
        fn dial_tcp<'a>(
            &'a self,
            _: &'a str,
            _: SocketAddr,
            _: Duration,
        ) -> Fut<'a, io::Result<TcpConn>> {
            Box::pin(async { Err(io::Error::other("no")) })
        }
        fn dial_udp<'a>(&'a self, _: &'a str, _: SocketAddr) -> Fut<'a, io::Result<UdpConn>> {
            Box::pin(async { Err(io::Error::other("no")) })
        }
        fn announce_udp<'a>(&'a self, _: &'a str, v6: bool) -> Fut<'a, io::Result<UdpConn>> {
            Box::pin(async move {
                if v6 {
                    return Err(io::Error::other("v4-only lan"));
                }
                Ok(UdpConn::Dyn(Arc::new(Responder(
                    Default::default(),
                    Default::default(),
                ))))
            })
        }
        fn probe_icmp<'a>(&'a self, _: &'a str, _: IpAddr) -> Fut<'a, io::Result<UdpConn>> {
            Box::pin(async { Err(io::Error::other("no")) })
        }
    }

    #[tokio::test]
    async fn resolves_from_responses() {
        let t = Arc::new(MdnsTransport::new(Arc::new(Lan)));
        let q = msg::pack(&msg::query("printer.local.", RecordType::A, 0x4d4d).unwrap()).unwrap();
        let a = t.clone().query(q, "Base".into()).await.unwrap();
        let m = msg::parse(&a.msg).unwrap();
        assert_eq!(m.metadata.id, 0x4d4d, "the app's id");
        assert_eq!(msg::qname(&m), "printer.local", "the app's question");
        assert_eq!(
            msg::a_answers(&m),
            [IpAddr::from([192, 168, 1, 7])],
            "not the unrelated announcement"
        );
        let q = msg::pack(&msg::query("nothere.local.", RecordType::A, 1).unwrap()).unwrap();
        let e = t.query(q, "Base".into()).await.unwrap_err();
        assert_eq!(e.status, dns_status::NO_RESPONSE);
    }
}
