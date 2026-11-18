// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/tun2socks.go (package-level toggles, Build, LogLevel)

//! `com.celzero.firestack.intra.Intra` package-level functions.

use crate::impls::log;
use crate::rt::FsResult;
use jni::JNIEnv;
use jni::objects::{GlobalRef, JObject};
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};

static CONSOLE: Mutex<Option<GlobalRef>> = Mutex::new(None);
static SELF_UID: Mutex<String> = Mutex::new(String::new());

/// Engine-wide toggles set by Kotlin (consumed by the netstack / dialers / WireGuard once ported).
pub struct Toggles {
    pub low_mem_bytes: AtomicI64,
    pub slowdown: AtomicBool,
    pub loopback: AtomicBool,
    pub undelegated_domains: AtomicBool,
    pub default_dns_as_fallback: AtomicBool,
    pub experimental_wireguard: AtomicBool,
    pub flood_wireguard: AtomicBool,
    pub eim: AtomicBool,
    pub eif: AtomicBool,
}

pub static TOGGLES: Toggles = Toggles {
    low_mem_bytes: AtomicI64::new(0),
    slowdown: AtomicBool::new(false),
    loopback: AtomicBool::new(false),
    undelegated_domains: AtomicBool::new(false),
    default_dns_as_fallback: AtomicBool::new(false),
    experimental_wireguard: AtomicBool::new(false),
    flood_wireguard: AtomicBool::new(false),
    eim: AtomicBool::new(false),
    eif: AtomicBool::new(false),
};

/// `Intra.build(full)`: engine identity shown in About and bug reports.
pub fn build(_env: &mut JNIEnv, full: bool) -> FsResult<String> {
    let base = format!(
        "rethinkreloaded-rust/{} (firestack-api@{})",
        env!("CARGO_PKG_VERSION"),
        crate::exports::FIRESTACK_PIN
    );
    if !full {
        return Ok(base);
    }
    Ok(format!(
        "{base}; target={}-{}; natives={}/{} implemented; refs={}",
        std::env::consts::ARCH,
        std::env::consts::OS,
        crate::exports::implemented_count(),
        crate::exports::NATIVE_COUNT,
        crate::rt::live_refnums()
    ))
}

/// `Intra.logLevel(goLevel, consoleLevel, callerDepth)`
pub fn log_level(_env: &mut JNIEnv, level: i32, console: i32, _depth: i32) -> FsResult<()> {
    log::LEVEL.store(level, Ordering::Relaxed);
    log::CONSOLE_LEVEL.store(console, Ordering::Relaxed);
    Ok(())
}

/// `Intra.setupConsole(Console)`: Kotlin sink for user-visible logs (wired to the logger in Phase 3).
pub fn setup_console(env: &mut JNIEnv, console: JObject) -> FsResult<()> {
    *CONSOLE.lock() = if console.is_null() {
        None
    } else {
        Some(env.new_global_ref(console)?)
    };
    Ok(())
}

/// `Intra.setCrashOutput(fp1, fp2)`: files that receive panic reports.
pub fn set_crash_output(_env: &mut JNIEnv, fp1: String, fp2: String) -> FsResult<bool> {
    log::set_crash_outputs(vec![fp1, fp2]);
    Ok(true)
}

pub fn get_self_uid(_env: &mut JNIEnv) -> FsResult<String> {
    Ok(SELF_UID.lock().clone())
}

pub fn set_self_uid(_env: &mut JNIEnv, uid: String) -> FsResult<()> {
    *SELF_UID.lock() = uid;
    Ok(())
}

pub fn low_mem(_env: &mut JNIEnv, bytes: i64) -> FsResult<()> {
    TOGGLES.low_mem_bytes.store(bytes, Ordering::Relaxed);
    Ok(())
}

macro_rules! toggle {
    ($fn:ident, $field:ident) => {
        pub fn $fn(_env: &mut JNIEnv, on: bool) -> FsResult<()> {
            TOGGLES.$field.store(on, Ordering::Relaxed);
            Ok(())
        }
    };
}
toggle!(slowdown, slowdown);
toggle!(loopback, loopback);
toggle!(undelegated_domains, undelegated_domains);
toggle!(default_dns_as_fallback, default_dns_as_fallback);
toggle!(experimental_wireguard, experimental_wireguard);
toggle!(flood_wireguard, flood_wireguard);

/// `Intra.transparency(eim, eif)`: endpoint-independent mapping / filtering for UDP.
pub fn transparency(_env: &mut JNIEnv, eim: bool, eif: bool) -> FsResult<()> {
    TOGGLES.eim.store(eim, Ordering::Relaxed);
    TOGGLES.eif.store(eif, Ordering::Relaxed);
    Ok(())
}
