// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/icmp.go
// Derived-From: celzero/firestack@d3d530ea3e:intra/netstack/icmp.go (echo interception, reply synthesis)
// Derived-From: celzero/firestack@d3d530ea3e:intra/core/ping.go (Echo)

//! ICMP echo: requests are intercepted before the stack, decided (`flow`, protocol 1 / 58), then either answered
//! with destination-unreachable (blocked) or probed through a protected unprivileged ICMP socket, after which the
//! reply is synthesized from the request. As firestack, the reply is synthesized whenever the probe socket could
//! be opened, even if the remote did not answer within 3 s (see engine/PARITY.md). Sources sending more than 10
//! pings in 10 s are stalled for 5 s.

use crate::flow::{self, BLOCK};
use crate::tunnel::Shared;
use fs_core::bridge::{FlowSummary, Mark, PROTO_ICMP, PROTO_ICMP6};
use fs_netstack::Netstack;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

const ECHO_TIMEOUT: Duration = Duration::from_secs(3);
const FLOOD_WINDOW: Duration = Duration::from_secs(10);
const FLOOD_MAX: u32 = 10;
const FLOOD_STALL: Duration = Duration::from_secs(5);

/// A parsed echo request.
#[derive(Debug, Clone)]
pub struct Echo {
    pub src: IpAddr,
    pub dst: IpAddr,
    /// the ICMP message (type, code, checksum, id, seq, payload)
    pub icmp: Vec<u8>,
    /// the whole packet (for unreachable replies)
    pub packet: Vec<u8>,
}

fn csum(data: &[u8], init: u32) -> u16 {
    let mut sum = init;
    for c in data.chunks(2) {
        sum += u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn v6_pseudo(src: &Ipv6Addr, dst: &Ipv6Addr, len: usize) -> u32 {
    let mut s = 0u32;
    for b in [src.octets(), dst.octets()] {
        for c in b.chunks(2) {
            s += u16::from_be_bytes([c[0], c[1]]) as u32;
        }
    }
    s + (len as u32 >> 16) + (len as u32 & 0xffff) + 58
}

/// Parses an ICMPv4 echo request (type 8) or ICMPv6 echo request (type 128, no extension headers).
pub fn parse_echo(p: &[u8]) -> Option<Echo> {
    match p.first()? >> 4 {
        4 => {
            let ihl = ((p[0] & 0x0f) as usize) * 4;
            if ihl < 20 || p.len() < ihl + 8 || p[9] != 1 || p[ihl] != 8 || p[ihl + 1] != 0 {
                return None;
            }
            let total = (u16::from_be_bytes([p[2], p[3]]) as usize).min(p.len());
            // a total length shorter than the headers is malformed (any app can write one into the tunnel)
            if total < ihl + 8 {
                return None;
            }
            Some(Echo {
                src: IpAddr::V4(Ipv4Addr::new(p[12], p[13], p[14], p[15])),
                dst: IpAddr::V4(Ipv4Addr::new(p[16], p[17], p[18], p[19])),
                icmp: p[ihl..total].to_vec(),
                packet: p[..total].to_vec(),
            })
        }
        6 => {
            if p.len() < 48 || p[6] != 58 || p[40] != 128 || p[41] != 0 {
                return None;
            }
            let src: [u8; 16] = p[8..24].try_into().ok()?;
            let dst: [u8; 16] = p[24..40].try_into().ok()?;
            let total = (40 + u16::from_be_bytes([p[4], p[5]]) as usize).min(p.len());
            if total < 48 {
                return None; // payload shorter than the echo header
            }
            Some(Echo {
                src: IpAddr::V6(Ipv6Addr::from(src)),
                dst: IpAddr::V6(Ipv6Addr::from(dst)),
                icmp: p[40..total].to_vec(),
                packet: p[..total].to_vec(),
            })
        }
        _ => None,
    }
}

/// Echo reply to the app: addresses swapped, type 0 / 129, checksums recomputed.
pub fn echo_reply(e: &Echo) -> Vec<u8> {
    build(e.dst, e.src, &{
        let mut m = e.icmp.clone();
        m[0] = if e.src.is_ipv4() { 0 } else { 129 };
        m
    })
}

/// Destination unreachable to the app (v4: type 3 code 1 host unreachable; v6: type 1 code 3 address
/// unreachable), carrying as much of the offending packet as fits.
pub fn unreachable(e: &Echo) -> Vec<u8> {
    let mut m = if e.src.is_ipv4() {
        vec![3, 1, 0, 0, 0, 0, 0, 0]
    } else {
        vec![1, 3, 0, 0, 0, 0, 0, 0]
    };
    let quote = if e.src.is_ipv4() { 28 } else { 1232 };
    m.extend_from_slice(&e.packet[..e.packet.len().min(quote)]);
    build(e.dst, e.src, &m)
}

/// Wraps an ICMP message (checksum field ignored, recomputed) in an IP header from `src` to `dst`.
fn build(src: IpAddr, dst: IpAddr, icmp: &[u8]) -> Vec<u8> {
    let mut m = icmp.to_vec();
    m[2] = 0;
    m[3] = 0;
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let c = csum(&m, 0);
            m[2..4].copy_from_slice(&c.to_be_bytes());
            let total = 20 + m.len();
            let mut h = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 1, 0, 0];
            h[2..4].copy_from_slice(&(total as u16).to_be_bytes());
            h.extend_from_slice(&s.octets());
            h.extend_from_slice(&d.octets());
            let hc = csum(&h, 0);
            h[10..12].copy_from_slice(&hc.to_be_bytes());
            h.extend_from_slice(&m);
            h
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let c = csum(&m, v6_pseudo(&s, &d, m.len()));
            m[2..4].copy_from_slice(&c.to_be_bytes());
            let mut h = vec![0x60, 0, 0, 0];
            h.extend_from_slice(&(m.len() as u16).to_be_bytes());
            h.extend_from_slice(&[58, 64]);
            h.extend_from_slice(&s.octets());
            h.extend_from_slice(&d.octets());
            h.extend_from_slice(&m);
            h
        }
        _ => Vec::new(),
    }
}

/// Per-source ping rate tracking (flood stall).
#[derive(Default)]
pub struct Flood {
    m: Mutex<HashMap<IpAddr, (u32, Instant)>>,
}

impl Flood {
    fn stall(&self, src: IpAddr) -> Option<Duration> {
        let mut m = self.m.lock();
        let now = Instant::now();
        let e = m.entry(src).or_insert((0, now));
        if now.duration_since(e.1) > FLOOD_WINDOW {
            *e = (0, now);
        }
        e.0 += 1;
        (e.0 > FLOOD_MAX).then_some(FLOOD_STALL)
    }
}

pub async fn handle(sh: Arc<Shared>, ns: Arc<Netstack>, flood: Arc<Flood>, e: Echo) {
    let start = Instant::now();
    if let Some(d) = flood.stall(e.src) {
        tokio::time::sleep(d).await;
    }
    let proto = if e.src.is_ipv4() {
        PROTO_ICMP
    } else {
        PROTO_ICMP6
    };
    let (src, dst) = (SocketAddr::new(e.src, 0), SocketAddr::new(e.dst, 0));
    let v = flow::decide(&sh.bridge, &sh.resolver, proto, src, dst).await;
    // firestack oneRealIPPort: the destination unless it was an ALG address, else a real address
    let target = flow::xlat(&sh, flow::targets(&v, dst))[0].ip();
    let mut smm = FlowSummary {
        proto: "icmp".into(),
        id: v.mark.cid.clone(),
        uid: v.uid.clone(),
        source: e.src.to_string(),
        target: target.to_string(),
        msg: "no error".into(),
        tx: e.icmp.len() as i64,
        ..Default::default()
    };
    if v.blocked() {
        smm.pid = BLOCK.into();
        smm.msg = "icmp: firewalled".into();
        let _ = ns.write_to_tun(&unreachable(&e)).await;
        smm.duration = start.elapsed().as_millis() as i64;
        sh.bridge.postflow(smm);
        return;
    }
    let probe = match flow::proxy(&sh, &v, SocketAddr::new(target, 0), "icmp").await {
        Ok(p) => {
            smm.pid = p.id().to_string();
            smm.rpid = flow::via_id(&p);
            p.probe_icmp(target).await
        }
        Err(e) => Err(std::io::Error::other(e)),
    };
    match probe {
        Ok(sock) => {
            sh.bridge.flowing(Mark {
                pidcsv: smm.pid.clone(),
                cid: v.mark.cid.clone(),
                uid: v.uid.clone(),
                ip: smm.target.clone(),
            });
            let t0 = Instant::now();
            if sock
                .send_to(&e.icmp, SocketAddr::new(target, 0))
                .await
                .is_ok()
            {
                let mut buf = [0u8; 1500];
                match tokio::time::timeout(ECHO_TIMEOUT, sock.recv(&mut buf)).await {
                    Ok(Ok(n)) => {
                        smm.rx = n as i64;
                        smm.rtt = t0.elapsed().as_millis() as i64;
                    }
                    _ => smm.msg = "icmp: no echo reply".into(),
                }
            }
            // firestack: reply whenever the probe could be sent
            let _ = ns.write_to_tun(&echo_reply(&e)).await;
        }
        Err(err) => {
            smm.msg = err.to_string();
            let _ = ns.write_to_tun(&unreachable(&e)).await;
        }
    }
    smm.duration = start.elapsed().as_millis() as i64;
    sh.bridge.postflow(smm);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4_echo() -> Vec<u8> {
        let icmp = vec![8, 0, 0, 0, 0x12, 0x34, 0, 1, b'h', b'i'];
        build(
            "10.111.222.1".parse().unwrap(),
            "1.1.1.1".parse().unwrap(),
            &icmp,
        )
    }

    #[test]
    fn malformed_echoes_are_ignored() {
        // fuzzer finds: total length below the header, short IHL, IPv6 echo without payload
        let short_total = [
            0x45, 0x1c, 0, 0, 0, 0, 0, 0, 0x40, 1, 0, 0, 10, 111, 59, 1, 1, 1, 1, 1, 8, 0, 0, 0, 1,
            0, 1, 1,
        ];
        assert!(parse_echo(&short_total).is_none());
        let mut small_ihl = short_total;
        small_ihl[0] = 0x41;
        assert!(parse_echo(&small_ihl).is_none());
        let mut v6 = vec![0u8; 48];
        v6[0] = 0x60;
        v6[6] = 58;
        v6[40] = 128;
        assert!(parse_echo(&v6).is_none(), "payload length 0");
    }

    #[test]
    fn parse_and_reply_v4() {
        let p = v4_echo();
        assert_eq!(csum(&p[..20], 0), 0, "ip header checksum valid");
        let e = parse_echo(&p).unwrap();
        assert_eq!(
            (e.src.to_string(), e.dst.to_string()),
            ("10.111.222.1".into(), "1.1.1.1".into())
        );
        let r = echo_reply(&e);
        assert_eq!(&r[12..16], &[1, 1, 1, 1]);
        assert_eq!(r[20], 0, "echo reply type");
        assert_eq!(csum(&r[20..], 0), 0, "icmp checksum valid");
        assert_eq!(&r[24..], &e.icmp[4..], "id/seq/payload echoed");
        let u = unreachable(&e);
        assert_eq!((u[20], u[21]), (3, 1));
        assert_eq!(csum(&u[20..], 0), 0);
    }

    #[test]
    fn parse_and_reply_v6() {
        let (s, d): (Ipv6Addr, Ipv6Addr) = (
            "fd66:f83a:c650::1".parse().unwrap(),
            "2606:4700::1111".parse().unwrap(),
        );
        let p = build(
            IpAddr::V6(s),
            IpAddr::V6(d),
            &[128, 0, 0, 0, 0, 7, 0, 1, 1, 2, 3],
        );
        let e = parse_echo(&p).unwrap();
        let r = echo_reply(&e);
        assert_eq!(r[40], 129);
        assert_eq!(
            csum(&r[40..], v6_pseudo(&d, &s, r.len() - 40)),
            0,
            "icmpv6 checksum valid"
        );
        assert!(parse_echo(&r).is_none(), "replies are not echo requests");
    }
}
