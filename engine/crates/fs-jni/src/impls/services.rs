// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/rnet/servers.go (x.Services, x.Server)

//! Natives of `Services` and `Server` over the tunnel's local proxy servers.

use crate::impls::proxies::ProxyRef;
use crate::rt::{self, FsError, FsResult};
use fs_intra::Tunnel;
use fs_rnet::{Server, Services};
use jni::JNIEnv;
use jni::objects::JObject;
use std::sync::Arc;

const C_SERVICES: &str = "com/celzero/firestack/backend/Services";
const C_SERVER: &str = "com/celzero/firestack/backend/Server";

pub struct ServicesRef(pub Arc<Tunnel>);
pub struct ServerRef(pub Arc<Server>);

/// `Tunnel.getServices()`
pub fn services_obj<'l>(env: &mut JNIEnv<'l>, t: Arc<Tunnel>) -> FsResult<JObject<'l>> {
    rt::new_iface_proxy(env, C_SERVICES, Arc::new(ServicesRef(t)))
}

fn services(env: &mut JNIEnv, this: &JObject) -> FsResult<Arc<Services>> {
    Ok(rt::obj_of::<ServicesRef>(env, this)?.0.services().clone())
}

fn server(env: &mut JNIEnv, this: &JObject) -> FsResult<Arc<Server>> {
    Ok(rt::obj_of::<ServerRef>(env, this)?.0.clone())
}

fn server_obj<'l>(env: &mut JNIEnv<'l>, s: Arc<Server>) -> FsResult<JObject<'l>> {
    rt::new_iface_proxy(env, C_SERVER, Arc::new(ServerRef(s)))
}

pub fn add_server<'l>(
    env: &mut JNIEnv<'l>,
    this: &JObject,
    typ: String,
    id: String,
    url: String,
) -> FsResult<JObject<'l>> {
    let s = services(env, this)?
        .add_server(&typ, &id, &url)
        .map_err(FsError::new)?;
    server_obj(env, s)
}
pub fn bridge(env: &mut JNIEnv, this: &JObject, sid: String, pid: String) -> FsResult<()> {
    services(env, this)?
        .bridge(&sid, &pid)
        .map_err(FsError::new)
}
pub fn get_server<'l>(env: &mut JNIEnv<'l>, this: &JObject, id: String) -> FsResult<JObject<'l>> {
    let s = services(env, this)?.get_server(&id).map_err(FsError::new)?;
    server_obj(env, s)
}
pub fn refresh_servers(env: &mut JNIEnv, this: &JObject) -> FsResult<String> {
    Ok(services(env, this)?.refresh_servers())
}
pub fn remove_all(env: &mut JNIEnv, this: &JObject) -> FsResult<()> {
    services(env, this)?.remove_all();
    Ok(())
}
pub fn remove_server(env: &mut JNIEnv, this: &JObject, id: String) -> FsResult<bool> {
    Ok(services(env, this)?.remove_server(&id))
}

pub fn s_get_addr(env: &mut JNIEnv, this: &JObject) -> FsResult<String> {
    Ok(server(env, this)?.addr())
}
/// `hop(Proxy)`: a proxy from this engine, or null to unbridge.
pub fn s_hop(env: &mut JNIEnv, this: &JObject, p: JObject) -> FsResult<()> {
    let s = server(env, this)?;
    let px = if p.is_null() {
        None
    } else {
        Some(
            rt::obj_of::<ProxyRef>(env, &p)
                .map_err(|_| FsError::new("svc: not a proxy"))?
                .0
                .clone(),
        )
    };
    s.hop(px).map_err(FsError::new)
}
pub fn s_id(env: &mut JNIEnv, this: &JObject) -> FsResult<String> {
    Ok(server(env, this)?.id().to_string())
}
pub fn s_refresh(env: &mut JNIEnv, this: &JObject) -> FsResult<()> {
    server(env, this)?.refresh().map_err(FsError::new)
}
pub fn s_start(env: &mut JNIEnv, this: &JObject) -> FsResult<()> {
    server(env, this)?.start().map_err(FsError::new)
}
pub fn s_status(env: &mut JNIEnv, this: &JObject) -> FsResult<i32> {
    Ok(server(env, this)?.status())
}
pub fn s_stop(env: &mut JNIEnv, this: &JObject) -> FsResult<()> {
    server(env, this)?.stop();
    Ok(())
}
pub fn s_type(env: &mut JNIEnv, this: &JObject) -> FsResult<String> {
    Ok(server(env, this)?.typ().to_string())
}
