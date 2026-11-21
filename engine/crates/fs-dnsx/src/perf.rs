// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2025 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/dnsx/transport.go (Perf)

//! `DNSTransport.measure(mid, n, seconds)` (firestack `Perf`): rounds of `n` concurrent queries (A for even, AAAA for
//! odd slots) over Exit for `seconds` (clamped to 10..60; `n` to 1..20), summarized as min / max / p50 / p95,
//! jitter (RMSSD of consecutive latencies) and the success percentage. Preset domains stand in for firestack's
//! sampled hosts.

use fs_dns::msg;
use fs_dns::transport::Transport;
use hickory_proto::rr::RecordType;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

const PRESET: [&str; 7] = [
    "example.com",
    "mozilla.com",
    "fsf.org",
    "ietf.org",
    "wikipedia.org",
    "dns.quad9.net",
    "grapheneos.org",
];

/// `backend.DNSMeasurement`
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Measurement {
    pub mid: String,
    pub max: i64,
    pub min: i64,
    pub p50: i64,
    pub p95: i64,
    pub jitter: i64,
    pub success: i32,
    pub seconds: i32,
    pub domains: String,
    pub errors: String,
    pub addrs: String,
}

fn pct(sorted: &[i64], q: f64) -> i64 {
    if sorted.is_empty() {
        return 0;
    }
    sorted[((sorted.len() - 1) as f64 * q).round() as usize]
}

pub async fn measure(
    t: Option<Arc<dyn Transport>>,
    mid: &str,
    n: i32,
    seconds: i32,
) -> Measurement {
    let mid = if mid.is_empty() {
        format!(
            "{:016x}",
            u64::from_le_bytes(fs_dns::dnscrypt::crypto::random())
        )
    } else {
        mid.to_string()
    };
    let Some(t) = t else {
        return Measurement {
            mid,
            errors: "dns: no such transport".into(),
            ..Default::default()
        };
    };
    let (n, seconds) = (n.clamp(1, 20) as usize, seconds.clamp(10, 60) as u64);
    let start = Instant::now();
    let deadline = start + Duration::from_secs(seconds);
    let (mut total, mut ok) = (0i64, 0i64);
    let (mut lats, mut errs, mut doms) = (Vec::<i64>::new(), BTreeSet::new(), BTreeSet::new());
    while Instant::now() < deadline {
        let mut round = tokio::task::JoinSet::new();
        for i in 0..n {
            let (t, dom) = (t.clone(), PRESET[i % PRESET.len()]);
            let qt = if i % 2 == 1 {
                RecordType::AAAA
            } else {
                RecordType::A
            };
            round.spawn(async move {
                let q = msg::query(&format!("{dom}."), qt, i as u16)
                    .and_then(|m| msg::pack(&m))
                    .unwrap_or_default();
                let at = Instant::now();
                let r = t.query(q, "Exit".into()).await;
                (dom, at.elapsed(), r.map(|_| ()).map_err(|e| e.msg))
            });
        }
        let left = deadline.saturating_duration_since(Instant::now());
        let results = tokio::time::timeout(left, async {
            let mut v = Vec::new();
            while let Some(r) = round.join_next().await {
                v.extend(r.ok());
            }
            v
        })
        .await
        .unwrap_or_default();
        if results.is_empty() {
            break;
        }
        for (dom, lat, r) in results {
            total += 1;
            doms.insert(dom.to_string());
            match r {
                Ok(()) => {
                    ok += 1;
                    lats.push(lat.as_millis() as i64);
                }
                Err(e) => {
                    errs.insert(e);
                }
            }
        }
    }
    let jitter = if lats.len() > 1 {
        let s: f64 = lats
            .windows(2)
            .map(|w| ((w[1] - w[0]) as f64).powi(2))
            .sum();
        (s / (lats.len() - 1) as f64).sqrt() as i64
    } else {
        0
    };
    let mut sorted = lats.clone();
    sorted.sort_unstable();
    Measurement {
        mid,
        max: sorted.last().copied().unwrap_or(0),
        min: sorted.first().copied().unwrap_or(0),
        p50: pct(&sorted, 0.5),
        p95: pct(&sorted, 0.95),
        jitter,
        success: if total > 0 {
            (ok * 100 / total) as i32
        } else {
            0
        },
        seconds: start.elapsed().as_secs() as i32,
        domains: doms.into_iter().collect::<Vec<_>>().join(","),
        errors: errs.into_iter().collect::<Vec<_>>().join(","),
        addrs: t.addr(),
    }
}
