// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/backend/core_radixtree.go
// Derived-From: celzero/firestack@d3d530ea3e:intra/backend/core_iptree.go

//! `com.celzero.firestack.backend.Backend` natives (tries, keys, …).

use crate::rt::{self, FsResult};
use fs_iptree::{IpTree, RadixTree};
use fs_wg::WgKey;
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

// ---------------------------------------------------------------- IpTree
// Derived-From: celzero/firestack@d3d530ea3e:intra/backend/core_iptree.go

const IP_TREE: &str = "com/celzero/firestack/backend/IpTree";

/// `Backend.newIpTree()`
pub fn new_ip_tree<'l>(env: &mut JNIEnv<'l>) -> FsResult<JObject<'l>> {
    rt::new_iface_proxy(env, IP_TREE, Arc::new(IpTree::new()))
}

fn iptree(env: &mut JNIEnv, this: &JObject) -> FsResult<Arc<IpTree>> {
    rt::obj_of::<IpTree>(env, this)
}

pub fn ip_add(env: &mut JNIEnv, this: &JObject, cidr: String, v: String) -> FsResult<()> {
    Ok(iptree(env, this)?.add(&cidr, &v)?)
}
pub fn ip_set(env: &mut JNIEnv, this: &JObject, cidr: String, v: String) -> FsResult<()> {
    Ok(iptree(env, this)?.set(&cidr, &v)?)
}
pub fn ip_esc(env: &mut JNIEnv, this: &JObject, cidr: String, v: String) -> FsResult<bool> {
    Ok(iptree(env, this)?.esc(&cidr, &v))
}
pub fn ip_del(env: &mut JNIEnv, this: &JObject, cidr: String) -> FsResult<bool> {
    Ok(iptree(env, this)?.del(&cidr))
}
pub fn ip_get(env: &mut JNIEnv, this: &JObject, cidr: String) -> FsResult<String> {
    Ok(iptree(env, this)?.get(&cidr)?)
}
pub fn ip_has(env: &mut JNIEnv, this: &JObject, cidr: String) -> FsResult<bool> {
    Ok(iptree(env, this)?.has(&cidr)?)
}
pub fn ip_routes(env: &mut JNIEnv, this: &JObject, cidr: String) -> FsResult<String> {
    Ok(iptree(env, this)?.routes(&cidr))
}
pub fn ip_values(env: &mut JNIEnv, this: &JObject, cidr: String) -> FsResult<String> {
    Ok(iptree(env, this)?.values(&cidr))
}
pub fn ip_get_any(env: &mut JNIEnv, this: &JObject, cidr: String) -> FsResult<String> {
    Ok(iptree(env, this)?.get_any(&cidr)?)
}
pub fn ip_has_any(env: &mut JNIEnv, this: &JObject, cidr: String) -> FsResult<bool> {
    Ok(iptree(env, this)?.has_any(&cidr)?)
}
pub fn ip_esc_like(env: &mut JNIEnv, this: &JObject, cidr: String, like: String) -> FsResult<i32> {
    Ok(iptree(env, this)?.esc_like(&cidr, &like))
}
pub fn ip_routes_like(
    env: &mut JNIEnv,
    this: &JObject,
    cidr: String,
    like: String,
) -> FsResult<String> {
    Ok(iptree(env, this)?.routes_like(&cidr, &like))
}
pub fn ip_values_like(
    env: &mut JNIEnv,
    this: &JObject,
    cidr: String,
    like: String,
) -> FsResult<String> {
    Ok(iptree(env, this)?.values_like(&cidr, &like))
}
pub fn ip_get_like(
    env: &mut JNIEnv,
    this: &JObject,
    cidr: String,
    like: String,
) -> FsResult<String> {
    Ok(iptree(env, this)?.get_like(&cidr, &like))
}
pub fn ip_get_all(env: &mut JNIEnv, this: &JObject, cidr: String) -> FsResult<String> {
    Ok(iptree(env, this)?.get_all(&cidr)?)
}
pub fn ip_del_all(env: &mut JNIEnv, this: &JObject, cidr: String) -> FsResult<i32> {
    Ok(iptree(env, this)?.del_all(&cidr))
}
pub fn ip_clear(env: &mut JNIEnv, this: &JObject) -> FsResult<()> {
    iptree(env, this)?.clear();
    Ok(())
}
pub fn ip_len(env: &mut JNIEnv, this: &JObject) -> FsResult<i64> {
    Ok(iptree(env, this)?.len() as i64)
}

// ---------------------------------------------------------------- WgKey
// Derived-From: celzero/firestack@d3d530ea3e:intra/backend/ipn_wgkeygen.go

const WG_KEY: &str = "com/celzero/firestack/backend/WgKey";

/// `Backend.newWgPrivateKey()`
pub fn new_wg_private_key<'l>(env: &mut JNIEnv<'l>) -> FsResult<JObject<'l>> {
    let k = WgKey::new_private()?;
    rt::new_iface_proxy(env, WG_KEY, Arc::new(k))
}

/// `Backend.newWgPrivateKeyOf(b64)`
pub fn new_wg_private_key_of<'l>(env: &mut JNIEnv<'l>, b64: String) -> FsResult<JObject<'l>> {
    let k = WgKey::from_base64(&b64)?;
    rt::new_iface_proxy(env, WG_KEY, Arc::new(k))
}

fn wgkey(env: &mut JNIEnv, this: &JObject) -> FsResult<Arc<WgKey>> {
    rt::obj_of::<WgKey>(env, this)
}

pub fn wg_base64(env: &mut JNIEnv, this: &JObject) -> FsResult<String> {
    Ok(wgkey(env, this)?.base64())
}
pub fn wg_hex(env: &mut JNIEnv, this: &JObject) -> FsResult<String> {
    Ok(wgkey(env, this)?.hex())
}
pub fn wg_is_zero(env: &mut JNIEnv, this: &JObject) -> FsResult<bool> {
    Ok(wgkey(env, this)?.is_zero())
}
pub fn wg_mult<'l>(env: &mut JNIEnv<'l>, this: &JObject) -> FsResult<JObject<'l>> {
    let p = wgkey(env, this)?.mult();
    rt::new_iface_proxy(env, WG_KEY, Arc::new(p))
}
