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
