// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/backend/core_radixtree.go

//! `com.celzero.firestack.backend.Backend` natives (tries, keys, …).

use crate::rt::{self, FsResult};
use fs_iptree::RadixTree;
use jni::JNIEnv;
use jni::objects::JObject;
use std::sync::Arc;

const RADIX_TREE: &str = "com/celzero/firestack/backend/RadixTree";

/// `Backend.newRadixTree()`
pub fn new_radix_tree<'l>(env: &mut JNIEnv<'l>) -> FsResult<JObject<'l>> {
    rt::new_iface_proxy(env, RADIX_TREE, Arc::new(RadixTree::new()))
}

fn radix(env: &mut JNIEnv, this: &JObject) -> FsResult<Arc<RadixTree>> {
    rt::obj_of::<RadixTree>(env, this)
}

pub fn radix_add(env: &mut JNIEnv, this: &JObject, k: String) -> FsResult<bool> {
    Ok(radix(env, this)?.add(&k))
}
pub fn radix_set(env: &mut JNIEnv, this: &JObject, k: String, v: String) -> FsResult<()> {
    radix(env, this)?.set(&k, &v);
    Ok(())
}
pub fn radix_del(env: &mut JNIEnv, this: &JObject, k: String) -> FsResult<bool> {
    Ok(radix(env, this)?.del(&k))
}
pub fn radix_get(env: &mut JNIEnv, this: &JObject, k: String) -> FsResult<String> {
    Ok(radix(env, this)?.get(&k))
}
pub fn radix_has(env: &mut JNIEnv, this: &JObject, k: String) -> FsResult<bool> {
    Ok(radix(env, this)?.has(&k))
}
pub fn radix_get_any(env: &mut JNIEnv, this: &JObject, k: String) -> FsResult<String> {
    Ok(radix(env, this)?.get_any(&k))
}
pub fn radix_has_any(env: &mut JNIEnv, this: &JObject, k: String) -> FsResult<bool> {
    Ok(radix(env, this)?.has_any(&k))
}
pub fn radix_del_all(env: &mut JNIEnv, this: &JObject, prefix: String) -> FsResult<i32> {
    Ok(radix(env, this)?.del_all(&prefix))
}
pub fn radix_clear(env: &mut JNIEnv, this: &JObject) -> FsResult<()> {
    radix(env, this)?.clear();
    Ok(())
}
pub fn radix_len(env: &mut JNIEnv, this: &JObject) -> FsResult<i64> {
    Ok(radix(env, this)?.len() as i64)
}
