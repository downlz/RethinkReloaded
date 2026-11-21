// Copyright (c) 2026 RethinkReloaded contributors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! `go.Seq` natives.

use crate::rt::FsResult;
use jni::objects::{GlobalRef, JObject};
use jni::{JNIEnv, JavaVM};
use std::sync::OnceLock;

static VM: OnceLock<JavaVM> = OnceLock::new();
static CONTEXT: OnceLock<GlobalRef> = OnceLock::new();

/// The JVM, for attaching engine threads that call back into Kotlin.
pub fn vm() -> Option<&'static JavaVM> {
    VM.get()
}

/// `Seq.init()`: called once from `Seq`'s static initializer right after `System.loadLibrary("gojni")`.
pub fn init(env: &mut JNIEnv) -> FsResult<()> {
    if VM.get().is_none() {
        let _ = VM.set(env.get_java_vm()?);
    }
    // Seq's static initializer runs on an app thread: resolve every class the engine instantiates now, so that
    // native-attached threads (callback executor) never need FindClass.
    let mut names: Vec<&str> = crate::exports::STRUCT_CLASSES.to_vec();
    names.extend(crate::exports::PROXY_CLASSES.iter().map(|(_, p)| *p));
    crate::rt::preload_classes(env, &names);
    fs_core::log::set_sink(|level, msg| match level {
        ..=2 => crate::impls::log::debug(msg),
        3 => crate::impls::log::info(msg),
        4 => crate::impls::log::warn(msg),
        _ => crate::impls::log::error(msg),
    });
    crate::impls::log::info("rust engine loaded (libgojni)");
    Ok(())
}

/// `Seq.setContext(Object)`: the Android application context.
pub fn set_context(env: &mut JNIEnv, ctx: JObject) -> FsResult<()> {
    if !ctx.is_null() && CONTEXT.get().is_none() {
        let _ = CONTEXT.set(env.new_global_ref(ctx)?);
    }
    Ok(())
}
