// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/settings/config.go
// Derived-From: celzero/firestack@d3d530ea3e:intra/settings/dialeropts.go
// Derived-From: celzero/firestack@d3d530ea3e:intra/settings/tunopts.go
// Derived-From: celzero/firestack@d3d530ea3e:intra/settings/dsopts.go
// Derived-From: celzero/firestack@d3d530ea3e:intra/settings/dnsopts.go (Plus strategy)
// Derived-From: celzero/firestack@d3d530ea3e:intra/settings/proxyopts.go (Auto mode)

//! Engine-wide settings (`com.celzero.firestack.settings.Settings` and related globals).

use parking_lot::RwLock;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

// ---------------------------------------------------------------- config.go

pub static DEBUG: AtomicBool = AtomicBool::new(false);
pub static SUPPORT_HAPPY_EYEBALLS: AtomicBool = AtomicBool::new(false);
pub static LOOPINGBACK: AtomicBool = AtomicBool::new(false);
pub static EXPERIMENTAL_WIREGUARD: AtomicBool = AtomicBool::new(false);
pub static FLOOD_WIREGUARD: AtomicBool = AtomicBool::new(false);
pub static ENDPOINT_INDEPENDENT_MAPPING: AtomicBool = AtomicBool::new(false);
pub static ENDPOINT_INDEPENDENT_FILTERING: AtomicBool = AtomicBool::new(false);
pub static SYSTEM_DNS_FOR_UNDELEGATED_DOMAINS: AtomicBool = AtomicBool::new(false);
pub static DEFAULT_DNS_AS_FALLBACK: AtomicBool = AtomicBool::new(false);
/// When true, the engine owns the TUN fd (Kotlin detached it); see [`dup_tun_fd`].
pub static OWN_TUN_FD: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------- dialeropts.go

pub const SPLIT_AUTO: i32 = 0;
pub const SPLIT_TCP_OR_TLS: i32 = 1;
pub const SPLIT_TCP: i32 = 2;
pub const SPLIT_DESYNC: i32 = 3;
pub const SPLIT_NEVER: i32 = 4;

pub const RETRY_AFTER_SPLIT: i32 = 0;
pub const RETRY_WITH_SPLIT: i32 = 1;
pub const RETRY_NEVER: i32 = 2;

const DEFAULT_BUFFER_SIZE: i32 = 2 * 1024 * 1024;

/// Dialer behaviour (split / desync strategy, retries, buffers, timeouts, keepalive).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DialerOpts {
    pub strat: i32,
    pub retry: i32,
    pub lower_keep_alive: bool,
    pub read_timeout_sec: i32,
    pub write_timeout_sec: i32,
    pub write_buffer_size: i32,
    pub read_buffer_size: i32,
}

impl std::fmt::Display for DialerOpts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self.strat {
            SPLIT_AUTO => "SplitAuto",
            SPLIT_TCP => "SplitTCP",
            SPLIT_TCP_OR_TLS => "SplitTCPOrTLS",
            SPLIT_DESYNC => "SplitDesync",
            SPLIT_NEVER => "SplitNever",
            _ => "Unknown",
        };
        let r = match self.retry {
            RETRY_NEVER => "RetryNever",
            RETRY_WITH_SPLIT => "RetryWithSplit",
            RETRY_AFTER_SPLIT => "RetryAfterSplit",
            _ => "Unknown",
        };
        let sz = if self.read_buffer_size != self.write_buffer_size {
            format!(
                "r: {}b w: {}b",
                self.read_buffer_size, self.write_buffer_size
            )
        } else {
            format!("rw: {}b", self.read_buffer_size)
        };
        let ka = if self.lower_keep_alive {
            "LowerKeepAlive"
        } else {
            "DefaultKeepAlive"
        };
        write!(
            f,
            "{s},{r},{sz},{ka},{}s,{}s",
            self.read_timeout_sec, self.write_timeout_sec
        )
    }
}

static DIALER_OPTS: RwLock<DialerOpts> = RwLock::new(DialerOpts {
    strat: 0,
    retry: 0,
    lower_keep_alive: false,
    read_timeout_sec: 0,
    write_timeout_sec: 0,
    write_buffer_size: 0,
    read_buffer_size: 0,
});

/// `Settings.setDialerOpts`: returns false (and falls back to defaults) for unknown strat / retry values.
pub fn set_dialer_opts(
    strat: i32,
    retry: i32,
    size_bytes: i32,
    timeout_sec: i32,
    keepalive: bool,
) -> bool {
    let mut ok = true;
    let strat = match strat {
        SPLIT_TCP | SPLIT_TCP_OR_TLS | SPLIT_DESYNC | SPLIT_AUTO | SPLIT_NEVER => strat,
        _ => {
            ok = false;
            SPLIT_AUTO
        }
    };
    let retry = match retry {
        RETRY_NEVER | RETRY_WITH_SPLIT | RETRY_AFTER_SPLIT => retry,
        _ => {
            ok = false;
            RETRY_AFTER_SPLIT
        }
    };
    let timeout = timeout_sec.max(0);
    let size = size_bytes.min(DEFAULT_BUFFER_SIZE);
    *DIALER_OPTS.write() = DialerOpts {
        strat,
        retry,
        lower_keep_alive: keepalive,
        read_timeout_sec: timeout,
        write_timeout_sec: timeout,
        read_buffer_size: size,
        write_buffer_size: size,
    };
    ok
}

pub fn dialer_opts() -> DialerOpts {
    *DIALER_OPTS.read()
}

// ---------------------------------------------------------------- tunopts.go

pub const DNS_MODE_NONE: i32 = 0;
pub const DNS_MODE_IP: i32 = 1;
pub const DNS_MODE_PORT: i32 = 2;

pub const BLOCK_MODE_NONE: i32 = 0;
pub const BLOCK_MODE_FILTER: i32 = 1;
pub const BLOCK_MODE_SINK: i32 = 2;
pub const BLOCK_MODE_FILTER_PROC: i32 = 3;

pub const PT_MODE_AUTO: i32 = 0;
pub const PT_MODE_FORCE64: i32 = 1;
pub const PT_MODE_NONE: i32 = 2;
pub const PT_MODE_FORCE46: i32 = 3;
pub const PT_MODE_FORCE: i32 = 4;

// firestack's init() calls DefaultTunMode(): DNSModeIP, BlockModeNone, PtModeNone
pub static DNS_MODE: AtomicI32 = AtomicI32::new(DNS_MODE_IP);
pub static BLOCK_MODE: AtomicI32 = AtomicI32::new(BLOCK_MODE_NONE);
pub static PT_MODE: AtomicI32 = AtomicI32::new(PT_MODE_NONE);

/// `Settings.mode2String(typ, mode)`, e.g. `"dns ip 1"`.
pub fn mode2string(typ: &str, mode: i32) -> String {
    let s = match (typ.to_lowercase().as_str(), mode) {
        ("dns", DNS_MODE_NONE) => "none",
        ("dns", DNS_MODE_IP) => "ip",
        ("dns", DNS_MODE_PORT) => "port",
        ("block", BLOCK_MODE_NONE) => "none",
        ("block", BLOCK_MODE_FILTER) => "filter",
        ("block", BLOCK_MODE_SINK) => "sink",
        ("block", BLOCK_MODE_FILTER_PROC) => "filterproc",
        ("pt", PT_MODE_AUTO) => "auto",
        ("pt", PT_MODE_FORCE64) => "force64",
        ("pt", PT_MODE_FORCE46) => "force46",
        ("pt", PT_MODE_FORCE) => "force",
        ("pt", PT_MODE_NONE) => "nopt",
        _ => "unknown",
    };
    format!("{typ} {s} {mode}")
}

pub fn set_tun_mode(dns: i32, block: i32, pt: i32) {
    DNS_MODE.store(dns, Ordering::SeqCst);
    BLOCK_MODE.store(block, Ordering::SeqCst);
    PT_MODE.store(pt, Ordering::SeqCst);
}

pub fn default_tun_mode() {
    set_tun_mode(DNS_MODE_IP, BLOCK_MODE_NONE, PT_MODE_NONE);
}

/// `Settings.dupTunFd(yn)`: yn=true means the engine dups the TUN fd (Kotlin keeps ownership).
/// Returns the previous "dup" setting.
pub fn dup_tun_fd(yn: bool) -> bool {
    !OWN_TUN_FD.swap(!yn, Ordering::SeqCst)
}

// ---------------------------------------------------------------- dsopts.go

pub const NS4: i64 = 0b010;
pub const NS46: i64 = 0b110;
pub const NS6: i64 = 0b100;

/// `Settings.l3(engine)`
pub fn l3(engine: i64) -> &'static str {
    match engine {
        NS46 => "46",
        NS6 => "6",
        _ => "4",
    }
}

/// `Settings.engine(l3)`
pub fn engine(l3: &str) -> i64 {
    match l3 {
        "46" => NS46,
        "6" => NS6,
        _ => NS4,
    }
}

// ---------------------------------------------------------------- dnsopts.go (Plus)

pub const PLUS_ORDER_SAFEST: i64 = 0;
pub const PLUS_ORDER_RANDOM: i64 = 1;
pub const PLUS_ORDER_FASTEST: i64 = 2;
pub const PLUS_ORDER_ROBUST: i64 = 3;

pub static PLUS_STRAT: AtomicI32 = AtomicI32::new(0);
pub static PLUS_FILTER: AtomicI32 = AtomicI32::new(0);

/// `Settings.setPlusStrategy(ord, filter)`: false for an invalid order (filter is not validated, as in Go).
pub fn set_plus_strategy(ord: i64, filter: i64) -> bool {
    if !(PLUS_ORDER_SAFEST..=PLUS_ORDER_ROBUST).contains(&ord) {
        return false;
    }
    PLUS_STRAT.store(ord as i32, Ordering::SeqCst);
    PLUS_FILTER.store(filter as i32, Ordering::SeqCst);
    true
}

// ---------------------------------------------------------------- proxyopts.go (Auto)

pub const AUTO_MODE_LOCAL: i32 = 0;
pub const AUTO_MODE_REMOTE: i32 = 1;
pub const AUTO_MODE_HYBRID: i32 = 2;

pub static AUTO_MODE: AtomicI32 = AtomicI32::new(AUTO_MODE_LOCAL);
pub static AUTO_DIALS_PARALLEL: AtomicBool = AtomicBool::new(false);

/// `Settings.setAutoMode(m)`: clamps to local..hybrid; returns the previous mode.
pub fn set_auto_mode(m: i32) -> i32 {
    AUTO_MODE.swap(m.clamp(AUTO_MODE_LOCAL, AUTO_MODE_HYBRID), Ordering::SeqCst)
}

pub fn auto_mode_str() -> &'static str {
    match AUTO_MODE.load(Ordering::SeqCst) {
        AUTO_MODE_LOCAL => "local",
        AUTO_MODE_REMOTE => "remote",
        AUTO_MODE_HYBRID => "hybrid",
        _ => "unknown",
    }
}

pub fn auto_always_remote() -> bool {
    AUTO_MODE.load(Ordering::SeqCst) == AUTO_MODE_REMOTE
}

pub fn auto_active() -> bool {
    AUTO_MODE.load(Ordering::SeqCst) != AUTO_MODE_LOCAL
}

/// `Settings.setAutoDialsParallel(y)`: returns the previous value.
pub fn set_auto_dials_parallel(y: bool) -> bool {
    AUTO_DIALS_PARALLEL.swap(y, Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dialer_opts_validation() {
        assert!(set_dialer_opts(SPLIT_DESYNC, RETRY_NEVER, 4096, 10, true));
        assert_eq!(
            dialer_opts().to_string(),
            "SplitDesync,RetryNever,rw: 4096b,LowerKeepAlive,10s,10s"
        );
        assert!(!set_dialer_opts(99, 99, i32::MAX, -5, false));
        let d = dialer_opts();
        assert_eq!(
            (d.strat, d.retry, d.read_buffer_size, d.read_timeout_sec),
            (SPLIT_AUTO, RETRY_AFTER_SPLIT, 2 << 20, 0)
        );
    }

    #[test]
    fn modes() {
        assert_eq!(mode2string("dns", DNS_MODE_IP), "dns ip 1");
        assert_eq!(mode2string("PT", PT_MODE_NONE), "PT nopt 2");
        assert_eq!(mode2string("x", 0), "x unknown 0");
        assert_eq!(
            (l3(NS46), l3(99), engine("6"), engine("?")),
            ("46", "4", NS6, NS4)
        );
        assert_eq!(set_auto_mode(9), AUTO_MODE_LOCAL);
        assert_eq!(auto_mode_str(), "hybrid");
        assert!(auto_active() && !auto_always_remote());
        assert!(!set_plus_strategy(4, 0) && set_plus_strategy(PLUS_ORDER_FASTEST, 2));
        assert!(dup_tun_fd(false)); // default: engine does not own the fd -> previous "dup" = true
        assert!(!dup_tun_fd(true));
    }
}
