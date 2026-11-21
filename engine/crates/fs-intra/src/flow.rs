// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/common.go (onFlow, undoAlg, makeIPPorts, judge, stall)

//! Per-connection policy: `preflow` (5 s) for the uid; the DNS gateway maps the destination back to its real
//! addresses, names and blocklists (undoing ALG translations, re-resolving expired ones); then `flow` (15 s) for
//! the verdict (`Mark`) and the firestack judgement of the proxy list (any `Block` blocks; empty means `Exit`).

use fs_core::bridge::{FlowArgs, Mark, SharedBridge};
use fs_core::settings;
use fs_dnsx::Resolver;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

pub const PREFLOW_TIMEOUT: Duration = Duration::from_secs(5);
pub const FLOW_TIMEOUT: Duration = Duration::from_secs(15);

pub const BLOCK: &str = "Block";
pub const BASE: &str = "Base";
pub const EXIT: &str = "Exit";
pub const AUTO: &str = "Auto";

/// The decision for one flow.
#[derive(Debug, Clone, Default)]
pub struct Verdict {
    pub mark: Mark,
    /// proxy ids in order; `[Block]` when blocked
    pub pids: Vec<String>,
    pub uid: String,
    /// the destination was an ALG address
    pub undid_alg: bool,
    /// real addresses behind the destination (the destination itself when nothing is known)
    pub realips: Vec<IpAddr>,
    pub domains: String,
}

impl Verdict {
    pub fn blocked(&self) -> bool {
        self.pids.first().map(String::as_str) == Some(BLOCK)
    }
    pub fn has(&self, pid: &str) -> bool {
        self.pids.iter().any(|p| p == pid)
    }
}

/// firestack `undoAlg`: (was ALG, real addresses, names, probable names, blocklists) for a destination.
pub fn undo_alg(
    resolver: &Resolver,
    dst: IpAddr,
    uid: &str,
) -> (bool, Vec<IpAddr>, String, String, String) {
    if dst.is_unspecified() {
        return (
            false,
            Vec::new(),
            String::new(),
            String::new(),
            String::new(),
        );
    }
    let gw = resolver.gateway();
    let (domains, forced) = gw.ptr(dst, uid, "", false);
    let pdoms = if !forced && domains.is_empty() {
        gw.ptr(dst, uid, "", true).0
    } else {
        String::new()
    };
    let (ips, undid) = gw.x(dst, uid, &[]);
    (undid, ips, domains, pdoms, gw.rdnsbl(dst))
}

/// firestack `onFlow` + `judge`.
pub async fn decide(
    bridge: &SharedBridge,
    resolver: &Resolver,
    protocol: i32,
    src: SocketAddr,
    dst: SocketAddr,
) -> Verdict {
    let block_mode = settings::BLOCK_MODE.load(Ordering::Relaxed);
    let preset = Mark {
        pidcsv: if block_mode == settings::BLOCK_MODE_NONE {
            EXIT
        } else {
            BLOCK
        }
        .into(),
        ..Default::default()
    };
    if block_mode == settings::BLOCK_MODE_SINK {
        return judge(preset);
    }

    // FilterProc (Android 9 and older): the owner comes from /proc/net; otherwise Kotlin finds it in preflow
    let mut uid: i32 = -1;
    let mut preuid = "-1".to_string();
    if block_mode == settings::BLOCK_MODE_FILTER_PROC {
        let proto = match protocol {
            fs_core::bridge::PROTO_TCP => "tcp",
            fs_core::bridge::PROTO_UDP => "udp",
            _ => "",
        };
        if !proto.is_empty()
            && let Ok(Some(u)) =
                tokio::task::spawn_blocking(move || crate::netstat::find_uid(proto, src, dst)).await
        {
            uid = u as i32;
            preuid = uid.to_string();
        }
    }
    let pre = tokio::time::timeout(
        PREFLOW_TIMEOUT,
        bridge.preflow(protocol, uid, src.to_string(), dst.to_string()),
    )
    .await
    .ok()
    .flatten();
    if let Some(pm) = &pre
        && let Ok(u) = pm.uid.parse::<i32>()
    {
        uid = u;
        // the gateway keys our own process by its uid (firestack SELF_UID)
        preuid = if pm.is_uid_self {
            resolver.gateway().my_uid().to_string()
        } else {
            pm.uid.clone()
        };
    }

    let (undid_alg, mut realips, domains, pdoms, blocklists) =
        undo_alg(resolver, dst.ip(), &preuid);
    if undid_alg && realips.is_empty() {
        // an expired translation: resolve its name again for this uid
        if pre.is_some() {
            for d in domains.split(',').filter(|d| !d.is_empty()) {
                let fresh = resolver.resolve_for(d, &preuid).await;
                if !fresh.is_empty() {
                    realips = fresh;
                    break;
                }
            }
        }
        if pre.is_none() || realips.is_empty() {
            let mut v = judge(preset);
            v.undid_alg = true;
            v.domains = domains;
            return v;
        }
    }

    let args = FlowArgs {
        protocol,
        uid,
        src: src.to_string(),
        dst: dst.to_string(),
        origdsts: realips
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(","),
        domains: domains.clone(),
        probable_domains: pdoms,
        blocklists,
        dst_is_alg: undid_alg,
    };
    let mark = match tokio::time::timeout(FLOW_TIMEOUT, bridge.flow(args)).await {
        Ok(Some(m)) => m,
        _ => Mark {
            pidcsv: BLOCK.into(),
            uid: uid.to_string(),
            ..Default::default()
        }, // timeout or nil: block
    };
    let mut v = judge(mark);
    v.undid_alg = undid_alg;
    v.realips = realips;
    v.domains = domains;
    v
}

/// firestack `makeIPPorts` (both address families usable): the destination (after a `Mark.IP` override) first
/// unless it was an ALG address, then the other real addresses in random order.
pub fn targets(v: &Verdict, dst: SocketAddr) -> Vec<SocketAddr> {
    let orig = target(v, dst);
    let include_orig = !v.undid_alg;
    let mut out: Vec<SocketAddr> = v
        .realips
        .iter()
        .filter(|ip| !ip.is_unspecified() && !(include_orig && **ip == orig.ip()))
        .map(|ip| SocketAddr::new(*ip, orig.port()))
        .collect();
    out.dedup();
    shuffle(&mut out);
    if include_orig || out.is_empty() {
        out.insert(0, orig);
    }
    out
}

fn shuffle<T>(v: &mut [T]) {
    for i in (1..v.len()).rev() {
        let j = (jitter("shuffle", i as u32) % (i as u64 + 1)) as usize;
        v.swap(i, j);
    }
}

/// firestack `retryTimeout`: dialing moves on to the next real address until this much time has passed.
pub const RETRY_TIMEOUT: Duration = Duration::from_secs(15);

/// firestack `judge`: empty → Exit; any Block → [Block]; uid defaults to "-1".
pub fn judge(mut mark: Mark) -> Verdict {
    if mark.pidcsv.trim().is_empty() {
        mark.pidcsv = EXIT.into();
    }
    let mut pids: Vec<String> = mark
        .pidcsv
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if pids.iter().any(|p| p == BLOCK) {
        pids = vec![BLOCK.into()];
    }
    let uid = if mark.uid.is_empty() {
        "-1".to_string()
    } else {
        mark.uid.clone()
    };
    Verdict {
        mark,
        pids,
        uid,
        ..Default::default()
    }
}

/// The dial owner (`who`) for the Phase 1 proxies: Base or Exit (other proxies arrive in Phase 2 and fall back to
/// Exit, i.e. a direct protected connection).
pub fn who(v: &Verdict) -> &'static str {
    match v.pids.first().map(String::as_str) {
        Some(BASE) => BASE,
        _ => EXIT,
    }
}

/// Destination after the `Mark.IP` override (keeps the port).
pub fn target(v: &Verdict, dst: SocketAddr) -> SocketAddr {
    v.mark
        .ip
        .parse()
        .map(|ip| SocketAddr::new(ip, dst.port()))
        .unwrap_or(dst)
}

/// firestack stall before closing blocked flows: none on the first hit of a key, then 1–5 s while the recent
/// hit count is low, else the count in seconds (capped at 30 s). Discourages apps from hammering retries.
#[derive(Default)]
pub struct Stall {
    hits: Mutex<HashMap<String, (u32, Instant)>>,
}

impl Stall {
    pub fn delay(&self, key: &str) -> Duration {
        let mut m = self.hits.lock();
        let now = Instant::now();
        if m.len() > 4096 {
            m.retain(|_, (_, t)| now.duration_since(*t) < Duration::from_secs(60));
        }
        let e = m.entry(key.to_string()).or_insert((0, now));
        if now.duration_since(e.1) > Duration::from_secs(60) {
            *e = (0, now);
        }
        e.0 += 1;
        e.1 = now;
        match e.0 {
            1 => Duration::ZERO,
            n if n < 5 => Duration::from_millis(1000 + jitter(key, n) % 4000),
            n => Duration::from_secs(n.min(30) as u64),
        }
    }
}

/// Cheap randomness for stall jitter: a randomly-keyed hash of (key, count, time).
fn jitter(key: &str, n: u32) -> u64 {
    use std::hash::BuildHasher;
    std::collections::hash_map::RandomState::new().hash_one((key, n, std::time::SystemTime::now()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn judgement() {
        let v = judge(Mark::default());
        assert_eq!(
            (v.pids.clone(), v.uid.as_str()),
            (vec!["Exit".to_string()], "-1")
        );
        assert!(
            judge(Mark {
                pidcsv: "wg0,Block".into(),
                ..Default::default()
            })
            .blocked()
        );
        let b = judge(Mark {
            pidcsv: "Base".into(),
            uid: "10123".into(),
            ip: "1.2.3.4".into(),
            ..Default::default()
        });
        assert_eq!(who(&b), "Base");
        assert_eq!(
            target(&b, "9.9.9.9:443".parse().unwrap()),
            "1.2.3.4:443".parse().unwrap()
        );
        // dial order (firestack makeIPPorts): the destination first unless it was an ALG address
        let dst: SocketAddr = "93.184.215.14:443".parse().unwrap();
        let real: Vec<IpAddr> = vec!["93.184.215.14".parse().unwrap(), "93.184.215.15".parse().unwrap()];
        let mut v = Verdict { realips: real.clone(), ..Default::default() };
        let t = targets(&v, dst);
        assert_eq!((t[0], t.len()), (dst, 2));
        v.undid_alg = true;
        let alg: SocketAddr = "100.80.1.2:443".parse().unwrap();
        let t = targets(&v, alg);
        assert_eq!(t.len(), 2);
        assert!(t.iter().all(|a| real.contains(&a.ip()) && a.port() == 443));
        v.realips = vec!["0.0.0.0".parse().unwrap()];
        assert_eq!(targets(&v, alg), vec![alg], "nothing dialable: the destination as-is");
        let s = Stall::default();
        assert_eq!(s.delay("k"), Duration::ZERO);
        assert!(s.delay("k") >= Duration::from_secs(1));
    }
}
