// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/common.go (onFlow, judge, stall)

//! Per-connection policy: `preflow` (5 s) for the uid, then `flow` (15 s) for the verdict (`Mark`), then the
//! firestack judgement of the proxy list (any `Block` blocks; empty means `Exit`).

use fs_core::bridge::{FlowArgs, Mark, SharedBridge};
use fs_core::settings;
use fs_dnsx::Resolver;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

pub const PREFLOW_TIMEOUT: Duration = Duration::from_secs(5);
pub const FLOW_TIMEOUT: Duration = Duration::from_secs(15);

pub const BLOCK: &str = "Block";
pub const BASE: &str = "Base";
pub const EXIT: &str = "Exit";
pub const AUTO: &str = "Auto";

/// The decision for one flow.
#[derive(Debug, Clone)]
pub struct Verdict {
    pub mark: Mark,
    /// proxy ids in order; `[Block]` when blocked
    pub pids: Vec<String>,
    pub uid: String,
}

impl Verdict {
    pub fn blocked(&self) -> bool {
        self.pids.first().map(String::as_str) == Some(BLOCK)
    }
    pub fn has(&self, pid: &str) -> bool {
        self.pids.iter().any(|p| p == pid)
    }
}

/// firestack `onFlow` + `judge`. With translation (ALG) off: realips = dst ip; domains = names that recently
/// resolved to the dst ip (the resolver's reverse map). Blocklists and /proc/net uid lookup are still to come.
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

    let mut uid: i32 = -1; // FilterProc (/proc/net lookup) arrives in Phase 1C
    let pre = tokio::time::timeout(
        PREFLOW_TIMEOUT,
        bridge.preflow(protocol, uid, src.to_string(), dst.to_string()),
    )
    .await;
    if let Ok(Some(pm)) = pre
        && let Ok(u) = pm.uid.parse::<i32>()
    {
        uid = u;
    }

    let args = FlowArgs {
        protocol,
        uid,
        src: src.to_string(),
        dst: dst.to_string(),
        origdsts: dst.ip().to_string(),
        domains: resolver.domains_for(dst.ip()),
        probable_domains: String::new(),
        blocklists: String::new(),
        dst_is_alg: false,
    };
    let mark = match tokio::time::timeout(FLOW_TIMEOUT, bridge.flow(args)).await {
        Ok(Some(m)) => m,
        _ => Mark {
            pidcsv: BLOCK.into(),
            uid: uid.to_string(),
            ..Default::default()
        }, // timeout or nil: block
    };
    judge(mark)
}

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
    Verdict { mark, pids, uid }
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
        let s = Stall::default();
        assert_eq!(s.delay("k"), Duration::ZERO);
        assert!(s.delay("k") >= Duration::from_secs(1));
    }
}
