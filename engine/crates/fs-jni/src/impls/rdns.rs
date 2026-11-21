// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2022 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/dnsx/wall.go (Set/GetRdnsLocal/Remote)
// Derived-From: celzero/firestack@d3d530ea3e:intra/dnsx/rethinkdns.go (RDNS)

//! RethinkDNS blocklist natives: `DNSResolver.setRdnsLocal/setRdnsRemote/getRdnsLocal/getRdnsRemote` (on both
//! `DNSResolver` and `RDNSResolver` proxies) and the `RDNS` object (blockstamps). The local `RDNS` shares its
//! stamp with the resolver, so `setStamp` takes effect on the next query.

use crate::impls::tunnel::ResolverRef;
use crate::rt::{self, FsError, FsResult};
use fs_blocklist::stamp::Rdns;
use jni::JNIEnv;
use jni::objects::JObject;
use std::sync::Arc;

const C_RDNS: &str = "com/celzero/firestack/backend/RDNS";
const ERR_NO_RDNS: &str = "dns: no rdns";

pub struct RdnsRef(pub Arc<Rdns>);

fn resolver(env: &mut JNIEnv, this: &JObject) -> FsResult<Arc<fs_intra::Tunnel>> {
    Ok(rt::obj_of::<ResolverRef>(env, this)?.0.clone())
}

fn rdns(env: &mut JNIEnv, this: &JObject) -> FsResult<Arc<Rdns>> {
    Ok(rt::obj_of::<RdnsRef>(env, this)?.0.clone())
}

/// `setRdnsLocal(td, rd, basicconfig, filetag)`: empty (or null) td/rd unsets the local blocklists.
pub fn set_local(
    env: &mut JNIEnv,
    this: &JObject,
    td: String,
    rd: String,
    conf: String,
    filetag: String,
) -> FsResult<()> {
    let t = resolver(env, this)?;
    t.resolver()
        .set_rdns_local(&td, &rd, &conf, &filetag)
        .map_err(FsError::new)
}

/// `setRdnsRemote(filetag)`: empty (or null) unsets.
pub fn set_remote(env: &mut JNIEnv, this: &JObject, filetag: String) -> FsResult<()> {
    let t = resolver(env, this)?;
    t.resolver().set_rdns_remote(&filetag).map_err(FsError::new)
}

pub fn get_local<'l>(env: &mut JNIEnv<'l>, this: &JObject) -> FsResult<JObject<'l>> {
    let r = resolver(env, this)?
        .resolver()
        .rdns_local()
        .ok_or_else(|| FsError::new(ERR_NO_RDNS))?;
    rt::new_iface_proxy(env, C_RDNS, Arc::new(RdnsRef(r)))
}

pub fn get_remote<'l>(env: &mut JNIEnv<'l>, this: &JObject) -> FsResult<JObject<'l>> {
    let r = resolver(env, this)?
        .resolver()
        .rdns_remote()
        .ok_or_else(|| FsError::new(ERR_NO_RDNS))?;
    rt::new_iface_proxy(env, C_RDNS, Arc::new(RdnsRef(r)))
}

pub fn flags_to_stamp(env: &mut JNIEnv, this: &JObject, csv: String, enc: i64) -> FsResult<String> {
    rdns(env, this)?
        .flags_to_stamp(&csv, enc)
        .map_err(FsError::new)
}

pub fn get_stamp(env: &mut JNIEnv, this: &JObject) -> FsResult<String> {
    rdns(env, this)?.get_stamp().map_err(FsError::new)
}

pub fn set_stamp(env: &mut JNIEnv, this: &JObject, stamp: String) -> FsResult<()> {
    rdns(env, this)?.set_stamp(&stamp).map_err(FsError::new)
}

pub fn stamp_to_flags(env: &mut JNIEnv, this: &JObject, stamp: String) -> FsResult<String> {
    rdns(env, this)?
        .stamp_to_flags(&stamp)
        .map_err(FsError::new)
}

pub fn stamp_to_names(env: &mut JNIEnv, this: &JObject, stamp: String) -> FsResult<String> {
    rdns(env, this)?
        .stamp_to_names(&stamp)
        .map_err(FsError::new)
}
