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
use fs_core::settings;
use jni::JNIEnv;
use jni::objects::{GlobalRef, JObject};
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};

static CONSOLE: Mutex<Option<GlobalRef>> = Mutex::new(None);
static SELF_UID: Mutex<String> = Mutex::new(String::new());

/// `Intra.lowMem(bytes)`: memory limit hint (consumed by buffer pools once the netstack is ported).
pub static LOW_MEM_BYTES: AtomicI64 = AtomicI64::new(0);
/// `Intra.slowdown(bool)`: throttle hint for the netstack.
pub static SLOWDOWN: AtomicBool = AtomicBool::new(false);

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
/// `Intra.setupConsole(console)`: engine logs at or above the console level go to Kotlin (memfd when possible).
pub fn setup_console(env: &mut JNIEnv, console: JObject) -> FsResult<()> {
    if console.is_null() {
        return Ok(());
    }
    let g = env.new_global_ref(console)?;
    *CONSOLE.lock() = Some(g.clone());
    // the memfd handshake upcalls Kotlin: off this (app) thread, so setupConsole returns promptly
    std::thread::spawn(move || crate::impls::console::setup(g));
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
    LOW_MEM_BYTES.store(bytes, Ordering::Relaxed);
    Ok(())
}

macro_rules! toggle {
    ($fn:ident, $flag:expr) => {
        pub fn $fn(_env: &mut JNIEnv, on: bool) -> FsResult<()> {
            $flag.store(on, Ordering::SeqCst);
            Ok(())
        }
    };
}
toggle!(slowdown, SLOWDOWN);
toggle!(loopback, settings::LOOPINGBACK);
toggle!(
    undelegated_domains,
    settings::SYSTEM_DNS_FOR_UNDELEGATED_DOMAINS
);
toggle!(default_dns_as_fallback, settings::DEFAULT_DNS_AS_FALLBACK);
toggle!(experimental_wireguard, settings::EXPERIMENTAL_WIREGUARD);
toggle!(flood_wireguard, settings::FLOOD_WIREGUARD);

/// `Intra.transparency(eim, eif)`: endpoint-independent mapping / filtering for UDP.
pub fn transparency(_env: &mut JNIEnv, eim: bool, eif: bool) -> FsResult<()> {
    settings::ENDPOINT_INDEPENDENT_MAPPING.store(eim, Ordering::SeqCst);
    settings::ENDPOINT_INDEPENDENT_FILTERING.store(eif, Ordering::SeqCst);
    Ok(())
}
