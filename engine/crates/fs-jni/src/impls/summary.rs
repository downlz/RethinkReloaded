// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/core/fmtstr.go (FmtBytes, FmtPeriod, FmtMillis, FmtSecsFloat)
// Derived-From: celzero/firestack@d3d530ea3e:intra/backend/dnsx_listener.go (DNSSummary.String, DNSOpts.Copy, DomainOpts.Copy)
// Derived-From: celzero/firestack@d3d530ea3e:intra/backend/ipn_pipkeygen.go (Strx)
// Derived-From: celzero/firestack@d3d530ea3e:intra/listener.go (FlowSummary.String)
// Derived-From: celzero/firestack@d3d530ea3e:intra/settings/dialeropts.go (DialerOpts.String)

//! `String()` and `Copy()` of the summary and option structs, with firestack's formatting.

use crate::rt::{self, FsResult};
use jni::JNIEnv;
use jni::objects::JObject;

const UNITS: [&str; 4] = ["b", "kb", "mb", "gb"];

/// firestack `core.FmtBytes`.
pub fn fmt_bytes(val: u64) -> String {
    let mut i = 0;
    let mut target = 0u64;
    for (j, _) in UNITS.iter().enumerate() {
        i = j;
        target = 1u64 << (10 * (j + 1));
        if val < target {
            break;
        }
    }
    if i > 0 {
        format!("{:.2}{}", val as f64 / (target as f64 / 1024.0), UNITS[i])
    } else {
        format!("{val} bytes")
    }
}

/// firestack `core.FmtPeriod` of a Go `time.Duration` (nanoseconds).
pub fn fmt_period(ns: i64) -> String {
    let p = if ns < 0 { "-" } else { "" };
    let d = ns.unsigned_abs();
    const US: u64 = 1_000;
    const MS: u64 = 1_000_000;
    const S: u64 = 1_000_000_000;
    let secs = d / S;
    if d < US {
        format!("{p}{d}ns")
    } else if d < MS {
        format!("{p}{}µs", d / US)
    } else if d < S {
        format!("{p}{}ms", d / MS)
    } else if d < 60 * S {
        format!("{p}{:.6}s", d as f64 / S as f64)
    } else if d < 3600 * S {
        format!("{p}{}m {}s", secs / 60, secs % 60)
    } else if d < 86400 * S {
        format!("{p}{}h {}m {}s", secs / 3600, (secs / 60) % 60, secs % 60)
    } else {
        format!(
            "{p}{}d {}h {}m {}s",
            secs / 86400,
            (secs / 3600) % 24,
            (secs / 60) % 60,
            secs % 60
        )
    }
}

/// firestack `core.FmtMillis`.
pub fn fmt_millis(ms: i64) -> String {
    fmt_period(ms.saturating_mul(1_000_000))
}

/// firestack `core.FmtSecsFloat` (Go converts to a Duration, truncating toward zero).
pub fn fmt_secs_float(s: f64) -> String {
    fmt_period((s * 1e9) as i64)
}

fn dns_summary_string(s: &rt::Struct) -> String {
    format!(
        "id: {} (fid: {} / {} by {}), t: {}, q: {} (do? {}), a: {} (cache? {} / ad? {}), code: {}, ttl: {}, by: {} / via: {} / relay: {}, status: {}, blocklists: {} / upstreamBlocks? {}, msg: {}, loc: {}",
        s.str("ID"),
        s.str("FID"),
        s.str("Type"),
        s.str("Origin"),
        fmt_secs_float(match s.get("Latency") {
            rt::Field::F64(v) => v,
            _ => 0.0,
        }),
        s.str("QName"),
        s.bool("DO"),
        s.str("RData"),
        s.bool("Cached"),
        s.bool("AD"),
        s.i64("RCode"),
        s.i64("RTtl"),
        s.str("Server"),
        s.str("PID"),
        s.str("RPID"),
        s.i64("Status"),
        s.str("Blocklists"),
        s.bool("UpstreamBlocks"),
        s.str("Msg"),
        s.str("Region"),
    )
}

fn flow_summary_string(s: &rt::Struct) -> String {
    format!(
        "{}: id={} pid={}:{} uid={} to={} down={} up={} dur={} synack={} msg={}",
        s.str("Proto"),
        s.str("ID"),
        s.str("PID"),
        s.str("RPID"),
        s.str("UID"),
        s.str("Target"),
        fmt_bytes(s.i64("Rx") as u64),
        fmt_bytes(s.i64("Tx") as u64),
        fmt_millis(s.i64("Duration")),
        fmt_millis(s.i64("Rtt")),
        s.str("Msg"),
    )
}

fn dialer_opts_string(d: &rt::Struct) -> String {
    let strat = match d.i64("Strat") {
        0 => "SplitAuto",
        1 => "SplitTCPOrTLS",
        2 => "SplitTCP",
        3 => "SplitDesync",
        4 => "SplitNever",
        _ => "Unknown",
    };
    let retry = match d.i64("Retry") {
        0 => "RetryAfterSplit",
        1 => "RetryWithSplit",
        2 => "RetryNever",
        _ => "Unknown",
    };
    let (r, w) = (d.i64("ReadBufferSize"), d.i64("WriteBufferSize"));
    let sz = if r != w {
        format!("r: {r}b w: {w}b")
    } else {
        format!("rw: {r}b")
    };
    let ka = if d.bool("LowerKeepAlive") {
        "LowerKeepAlive"
    } else {
        "DefaultKeepAlive"
    };
    let tmo = format!("{}s,{}s", d.i64("ReadTimeoutSec"), d.i64("WriteTimeoutSec"));
    [strat, retry, &sz, ka, &tmo].join(",")
}

pub fn dns_summary(env: &mut JNIEnv, this: &JObject) -> FsResult<String> {
    Ok(dns_summary_string(&*rt::struct_of(env, this)?))
}
pub fn flow_summary(env: &mut JNIEnv, this: &JObject) -> FsResult<String> {
    Ok(flow_summary_string(&*rt::struct_of(env, this)?))
}
pub fn dialer_opts(env: &mut JNIEnv, this: &JObject) -> FsResult<String> {
    Ok(dialer_opts_string(&*rt::struct_of(env, this)?))
}

/// `DNSOpts.copy()` / `DomainOpts.copy()`: every field is copied, as firestack's Copy does.
pub fn copy<'l>(env: &mut JNIEnv<'l>, this: &JObject) -> FsResult<JObject<'l>> {
    let s = rt::struct_of(env, this)?;
    rt::new_struct_object(env, s.copy())
}

/// `Strx.s()`: Strx is opaque (its string is unexported) and no API returns one, so a new Strx is empty.
pub fn strx_s(env: &mut JNIEnv, this: &JObject) -> FsResult<String> {
    Ok(rt::struct_of(env, this)?.str("_s"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rt::{Field, Struct};

    #[test]
    fn formats_as_firestack() {
        assert_eq!(fmt_bytes(512), "512 bytes");
        assert_eq!(fmt_bytes(1536), "1.50kb");
        assert_eq!(fmt_bytes(3 << 20), "3.00mb");
        assert_eq!(fmt_millis(0), "0ns");
        assert_eq!(fmt_millis(250), "250ms");
        assert_eq!(fmt_millis(1500), "1.500000s");
        assert_eq!(fmt_millis(-61_000), "-1m 1s");
        assert_eq!(fmt_millis(3_723_000), "1h 2m 3s");
        assert_eq!(fmt_millis(90_061_000), "1d 1h 1m 1s");
        assert_eq!(fmt_secs_float(0.0123), "12ms");
        assert_eq!(fmt_secs_float(0.0000015), "1µs");

        let f = Struct::new("x");
        f.set("Proto", Field::Str("tcp".into()));
        f.set("ID", Field::Str("c1".into()));
        f.set("Rx", Field::I64(2048));
        f.set("Duration", Field::I64(42));
        assert_eq!(
            flow_summary_string(&f),
            "tcp: id=c1 pid=: uid= to= down=2.00kb up=0 bytes dur=42ms synack=0ns msg="
        );

        let d = Struct::new("x");
        d.set("Strat", Field::I32(3));
        d.set("Retry", Field::I32(1));
        d.set("ReadBufferSize", Field::I32(4096));
        d.set("WriteBufferSize", Field::I32(4096));
        d.set("ReadTimeoutSec", Field::I32(30));
        assert_eq!(
            dialer_opts_string(&d),
            "SplitDesync,RetryWithSplit,rw: 4096b,DefaultKeepAlive,30s,0s"
        );

        let s = Struct::new("x");
        s.set("QName", Field::Str("example.com".into()));
        s.set("Latency", Field::F64(0.25));
        s.set("RCode", Field::I64(3));
        s.set("Cached", Field::Bool(true));
        let out = dns_summary_string(&s);
        assert!(out.starts_with("id:  (fid:  /  by ), t: 250ms, q: example.com (do? false), a:  (cache? true / ad? false), code: 3,"), "{out}");

        let c = s.copy();
        s.set("QName", Field::Str("changed".into()));
        assert_eq!(c.str("QName"), "example.com", "a copy, not an alias");
    }
}
