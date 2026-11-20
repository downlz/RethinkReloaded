// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/dns53/upstream.go

//! Plain DNS: UDP to each server in turn (15 s timeout, as firestack), TCP only when the UDP dial itself fails
//! (no automatic retry on truncation: the client retries over TCP, as with firestack).

use crate::msg;
use crate::transport::{Answer, QueryError, Stats, TYPE_DNS53, Transport};
use fs_core::bridge::{BoxFuture, dns_status};
use fs_dialers::Protector;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const TIMEOUT: Duration = Duration::from_secs(15);

pub struct Dns53Transport {
    id: String,
    servers: Vec<SocketAddr>,
    protector: Protector,
    stats: Stats,
}

impl Dns53Transport {
    pub fn new(id: &str, servers: Vec<SocketAddr>, protector: Protector) -> Self {
        Dns53Transport {
            id: id.to_string(),
            servers,
            protector,
            stats: Stats::default(),
        }
    }

    /// Parses an `ip[:port]` csv (port defaults to 53; "localhost" = 127.0.0.1, ::1).
    pub fn parse_servers(csv: &str) -> Vec<SocketAddr> {
        let mut out = Vec::new();
        for s in csv.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            if s == "localhost" {
                out.push("127.0.0.1:53".parse().unwrap());
                out.push("[::1]:53".parse().unwrap());
            } else if let Ok(sa) = s.parse::<SocketAddr>() {
                out.push(sa);
            } else if let Ok(ip) = s.trim_matches(['[', ']']).parse::<std::net::IpAddr>() {
                out.push(SocketAddr::new(ip, 53));
            }
        }
        out
    }

    async fn udp(
        &self,
        server: SocketAddr,
        q: &[u8],
        id: u16,
        pid: &str,
    ) -> Result<Vec<u8>, (bool, String)> {
        let sock = self
            .protector
            .dial_udp(pid, server)
            .await
            .map_err(|e| (true, e.to_string()))?;
        sock.send(q).await.map_err(|e| (false, e.to_string()))?;
        let mut buf = vec![0u8; 4096];
        let deadline = Instant::now() + TIMEOUT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match tokio::time::timeout(left, sock.recv(&mut buf)).await {
                Ok(Ok(n)) if n >= 2 && u16::from_be_bytes([buf[0], buf[1]]) == id => {
                    return Ok(buf[..n].to_vec());
                }
                Ok(Ok(_)) => continue,
                Ok(Err(e)) => return Err((false, e.to_string())),
                Err(_) => return Err((false, "dns53: timeout".into())),
            }
        }
    }

    async fn tcp(&self, server: SocketAddr, q: &[u8], pid: &str) -> Result<Vec<u8>, String> {
        let mut s = self
            .protector
            .dial_tcp(pid, server, fs_dialers::DIAL_TIMEOUT)
            .await
            .map_err(|e| e.to_string())?;
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
        match tokio::time::timeout(TIMEOUT, io).await {
            Ok(r) => r.map_err(|e| e.to_string()),
            Err(_) => Err("dns53: tcp timeout".into()),
        }
    }
}

impl Transport for Arc<Dns53Transport> {
    fn id(&self) -> &str {
        &self.id
    }
    fn typ(&self) -> &str {
        TYPE_DNS53
    }
    fn addr(&self) -> String {
        self.servers
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join(",")
    }
    fn status(&self) -> i32 {
        self.stats.status()
    }
    fn p50(&self) -> i64 {
        self.stats.p50()
    }
    fn query(&self, q: Vec<u8>, pid: String) -> BoxFuture<Result<Answer, QueryError>> {
        let me = self.clone();
        Box::pin(async move {
            let start = Instant::now();
            if q.len() < 12 || msg::parse(&q).is_none() {
                return Err(QueryError::new(
                    dns_status::BAD_QUERY,
                    "dns53: unparsable query",
                ));
            }
            let id = u16::from_be_bytes([q[0], q[1]]);
            let mut last = QueryError::new(dns_status::SEND_FAILED, "dns53: no servers");
            for server in me.servers.clone() {
                let r = match me.udp(server, &q, id, &pid).await {
                    Ok(a) => Ok(a),
                    Err((true, _)) => me.tcp(server, &q, &pid).await,
                    Err((false, e)) => Err(e),
                };
                match r {
                    Ok(ans) if msg::parse(&ans).is_some() => {
                        let latency = start.elapsed();
                        me.stats.ok(latency);
                        return Ok(Answer {
                            msg: ans,
                            server: server.to_string(),
                            pid,
                            latency,
                        });
                    }
                    Ok(_) => {
                        last = QueryError {
                            status: dns_status::BAD_RESPONSE,
                            msg: "dns53: bad answer".into(),
                            server: server.to_string(),
                        }
                    }
                    Err(e) => {
                        last = QueryError {
                            status: dns_status::SEND_FAILED,
                            msg: e,
                            server: server.to_string(),
                        }
                    }
                }
            }
            me.stats.err(last.status);
            Err(last)
        })
    }
}

/// `BlockAll`: answers every query with firestack's synthesized blocked response.
pub struct BlockAll {
    stats: Stats,
}

impl Default for BlockAll {
    fn default() -> Self {
        let s = Stats::default();
        s.ok(Duration::ZERO);
        BlockAll { stats: s }
    }
}

impl Transport for Arc<BlockAll> {
    fn id(&self) -> &str {
        crate::ids::BLOCK_ALL
    }
    fn typ(&self) -> &str {
        TYPE_DNS53
    }
    fn addr(&self) -> String {
        String::new()
    }
    fn status(&self) -> i32 {
        self.stats.status()
    }
    fn p50(&self) -> i64 {
        0
    }
    fn query(&self, q: Vec<u8>, pid: String) -> BoxFuture<Result<Answer, QueryError>> {
        Box::pin(async move {
            let m = msg::parse(&q)
                .ok_or_else(|| QueryError::new(dns_status::BAD_QUERY, "blockall: bad query"))?;
            let r = msg::refused_response(&m)
                .ok_or_else(|| QueryError::new(dns_status::BAD_QUERY, "blockall: no question"))?;
            Ok(Answer {
                msg: msg::pack(&r).unwrap_or_default(),
                server: String::new(),
                pid,
                latency: Duration::ZERO,
            })
        })
    }
}
