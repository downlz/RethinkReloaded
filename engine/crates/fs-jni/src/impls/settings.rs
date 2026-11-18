// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/settings/*.go

//! `com.celzero.firestack.settings.Settings` package-level natives; state lives in `fs_core::settings`.

use crate::rt::FsResult;
use fs_core::settings as s;
use jni::JNIEnv;
use std::sync::atomic::Ordering;

pub fn set_dialer_opts(
    _: &mut JNIEnv,
    strat: i32,
    retry: i32,
    size: i32,
    timeout: i32,
    ka: bool,
) -> FsResult<bool> {
    Ok(s::set_dialer_opts(strat, retry, size, timeout, ka))
}
pub fn set_auto_mode(_: &mut JNIEnv, m: i32) -> FsResult<i32> {
    Ok(s::set_auto_mode(m))
}
pub fn set_auto_dials_parallel(_: &mut JNIEnv, y: bool) -> FsResult<bool> {
    Ok(s::set_auto_dials_parallel(y))
}
pub fn auto_mode_str(_: &mut JNIEnv) -> FsResult<String> {
    Ok(s::auto_mode_str().to_string())
}
pub fn auto_active(_: &mut JNIEnv) -> FsResult<bool> {
    Ok(s::auto_active())
}
pub fn auto_always_remote(_: &mut JNIEnv) -> FsResult<bool> {
    Ok(s::auto_always_remote())
}
pub fn set_tun_mode(_: &mut JNIEnv, dns: i32, block: i32, pt: i32) -> FsResult<()> {
    s::set_tun_mode(dns, block, pt);
    Ok(())
}
pub fn default_tun_mode(_: &mut JNIEnv) -> FsResult<()> {
    s::default_tun_mode();
    Ok(())
}
pub fn dup_tun_fd(_: &mut JNIEnv, yn: bool) -> FsResult<bool> {
    Ok(s::dup_tun_fd(yn))
}
pub fn set_plus_strategy(_: &mut JNIEnv, ord: i64, filter: i64) -> FsResult<bool> {
    Ok(s::set_plus_strategy(ord, filter))
}
pub fn mode2string(_: &mut JNIEnv, typ: String, mode: i32) -> FsResult<String> {
    Ok(s::mode2string(&typ, mode))
}
pub fn l3(_: &mut JNIEnv, engine: i64) -> FsResult<String> {
    Ok(s::l3(engine).to_string())
}
pub fn engine(_: &mut JNIEnv, l3: String) -> FsResult<i64> {
    Ok(s::engine(&l3))
}
pub fn get_debug(_: &mut JNIEnv) -> FsResult<bool> {
    Ok(s::DEBUG.load(Ordering::SeqCst))
}
pub fn set_debug(_: &mut JNIEnv, v: bool) -> FsResult<()> {
    s::DEBUG.store(v, Ordering::SeqCst);
    Ok(())
}
pub fn get_support_happy_eyeballs(_: &mut JNIEnv) -> FsResult<bool> {
    Ok(s::SUPPORT_HAPPY_EYEBALLS.load(Ordering::SeqCst))
}
pub fn set_support_happy_eyeballs(_: &mut JNIEnv, v: bool) -> FsResult<()> {
    s::SUPPORT_HAPPY_EYEBALLS.store(v, Ordering::SeqCst);
    Ok(())
}
