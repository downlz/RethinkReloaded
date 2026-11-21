// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2025 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/dnsx/plus.go (TransportMult)
// Derived-From: celzero/firestack@d3d530ea3e:intra/dnscrypt/multiserver.go (TransportMult)

//! `DNSResolver.getMult(id)` and the `DNSTransportMult` natives: Rethink Plus (`Plus`) and the DNSCrypt
//! multi-server (`DcProxy`).

use crate::impls::tunnel::{ResolverRef, TransportRef};
use crate::rt::{self, FsError, FsResult};
use fs_dns::transport::Transport;
use fs_intra::Tunnel;
use jni::JNIEnv;
use jni::objects::JObject;
use std::sync::Arc;

const C_MULT: &str = "com/celzero/firestack/backend/DNSTransportMult";
const C_TRANSPORT: &str = "com/celzero/firestack/backend/DNSTransport";
const DC_PROXY: &str = "DcProxy";

pub enum MultRef {
    Plus(Arc<Tunnel>),
    DnsCrypt(Arc<Tunnel>),
}

/// `DNSResolver.getMult(id)`
pub fn get_mult<'l>(env: &mut JNIEnv<'l>, this: &JObject, id: String) -> FsResult<JObject<'l>> {
    let t = rt::obj_of::<ResolverRef>(env, this)?.0.clone();
    let m = match id.as_str() {
        fs_dnsx::plus::PLUS => MultRef::Plus(t),
        DC_PROXY => MultRef::DnsCrypt(t),
        _ => return Err(FsError::new("dns: transport is not a multi-transport")),
    };
    rt::new_iface_proxy(env, C_MULT, Arc::new(m))
}

fn mult(env: &mut JNIEnv, this: &JObject) -> FsResult<Arc<MultRef>> {
    rt::obj_of::<MultRef>(env, this)
}

fn member(m: &MultRef, id: &str) -> Option<Arc<dyn Transport>> {
    match m {
        MultRef::Plus(t) => t.resolver().plus().get(id),
        MultRef::DnsCrypt(t) => t
            .dnscrypt()
            .live()
            .iter()
            .any(|x| x == id)
            .then(|| t.resolver().get(id))
            .flatten(),
    }
}

/// Plus takes any transport created by this engine; the DNSCrypt multi-server takes none (firestack: no-op).
pub fn m_add(env: &mut JNIEnv, this: &JObject, tr: JObject) -> FsResult<bool> {
    let m = mult(env, this)?;
    if tr.is_null() {
        return Ok(false);
    }
    let Ok(t) = rt::obj_of::<TransportRef>(env, &tr) else {
        return Ok(false);
    };
    Ok(match &*m {
        MultRef::Plus(tun) => tun.resolver().plus().add(t.0.clone()),
        MultRef::DnsCrypt(_) => false,
    })
}
pub fn m_get<'l>(env: &mut JNIEnv<'l>, this: &JObject, id: String) -> FsResult<JObject<'l>> {
    let m = mult(env, this)?;
    let t = member(&m, &id).ok_or_else(|| FsError::new(format!("dns: no such transport {id}")))?;
    rt::new_iface_proxy(env, C_TRANSPORT, Arc::new(TransportRef(t)))
}
pub fn m_get_ips(env: &mut JNIEnv, this: &JObject, id: String) -> FsResult<String> {
    let m = mult(env, this)?;
    Ok(member(&m, &id).map(|t| t.addr()).unwrap_or_default())
}
pub fn m_live_transports(env: &mut JNIEnv, this: &JObject) -> FsResult<String> {
    Ok(match &*mult(env, this)? {
        MultRef::Plus(t) => t.resolver().plus().live().join(","),
        MultRef::DnsCrypt(t) => {
            let mut l = t.dnscrypt().live();
            l.sort();
            l.join(",")
        }
    })
}
pub fn m_refresh(env: &mut JNIEnv, this: &JObject) -> FsResult<String> {
    Ok(match &*mult(env, this)? {
        MultRef::Plus(t) => t.resolver().plus().refresh(),
        MultRef::DnsCrypt(_) => DC_PROXY.to_string(),
    })
}
pub fn m_remove(env: &mut JNIEnv, this: &JObject, id: String) -> FsResult<bool> {
    Ok(match &*mult(env, this)? {
        MultRef::Plus(t) => t.resolver().plus().remove(&id),
        MultRef::DnsCrypt(t) => t.remove_transport(&id),
    })
}
