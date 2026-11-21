// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/ipn/proxies.go (x.Proxies, x.Router of the proxifier)
// Derived-From: celzero/firestack@d3d530ea3e:intra/ipn/proxy.go (AddProxy)

//! Natives of `Proxies`, `Proxy` and `Router` over the engine's proxy registry.

use crate::impls::tunnel::ProxiesRef;
use crate::rt::{self, Field, FsError, FsResult, Struct};
use fs_intra::Tunnel;
use fs_proxy::{Proxifier, RouterStats, SharedProxy};
use jni::JNIEnv;
use jni::objects::JObject;
use std::sync::Arc;

const C_ROUTER: &str = "com/celzero/firestack/backend/Router";
const C_PROXY: &str = "com/celzero/firestack/backend/Proxy";
const C_ROUTER_STATS: &str = "com/celzero/firestack/backend/RouterStats";
const C_CLIENT: &str = "com/celzero/firestack/backend/Client";
const C_IPMETA: &str = "com/celzero/firestack/backend/IPMetadata";

/// `Proxy.client()`: IP metadata lookups over that proxy.
pub struct ClientRef(pub SharedProxy);

pub struct ProxyRef(pub SharedProxy);

/// The router of one proxy, or of all of them (`Proxies.router()`).
pub enum RouterRef {
    All(Arc<Tunnel>),
    Of(SharedProxy),
}

fn registry(env: &mut JNIEnv, this: &JObject) -> FsResult<Arc<Proxifier>> {
    Ok(rt::obj_of::<ProxiesRef>(env, this)?.0.proxies().clone())
}

fn proxy_obj<'l>(env: &mut JNIEnv<'l>, p: SharedProxy) -> FsResult<JObject<'l>> {
    rt::new_iface_proxy(env, C_PROXY, Arc::new(ProxyRef(p)))
}

/// `addProxy(id, txt)`: a config-less proxy for empty `txt`; SOCKS5, HTTP and WireGuard arrive with their ports.
pub fn add_proxy<'l>(
    env: &mut JNIEnv<'l>,
    this: &JObject,
    id: String,
    txt: String,
) -> FsResult<JObject<'l>> {
    let px = registry(env, this)?;
    let p = fs_proxy::add_proxy(&px, &id, &txt).map_err(FsError::new)?;
    proxy_obj(env, p)
}
pub fn get_proxy<'l>(env: &mut JNIEnv<'l>, this: &JObject, id: String) -> FsResult<JObject<'l>> {
    let p = registry(env, this)?.proxy_for(&id).map_err(FsError::new)?;
    proxy_obj(env, p)
}
pub fn has_proxy(env: &mut JNIEnv, this: &JObject, id: String) -> FsResult<bool> {
    Ok(registry(env, this)?.has_proxy(&id))
}
pub fn remove_proxy(env: &mut JNIEnv, this: &JObject, id: String) -> FsResult<bool> {
    Ok(registry(env, this)?.remove_proxy(&id))
}
pub fn refresh_proxies(env: &mut JNIEnv, this: &JObject) -> FsResult<String> {
    Ok(registry(env, this)?.refresh_proxies())
}
pub fn hop(env: &mut JNIEnv, this: &JObject, via: String, origin: String) -> FsResult<()> {
    registry(env, this)?
        .hop(&via, &origin, false)
        .map_err(FsError::new)
}
pub fn test_hop(env: &mut JNIEnv, this: &JObject, via: String, origin: String) -> FsResult<String> {
    Ok(registry(env, this)?.test_hop(&via, &origin))
}
pub fn router<'l>(env: &mut JNIEnv<'l>, this: &JObject) -> FsResult<JObject<'l>> {
    let t = rt::obj_of::<ProxiesRef>(env, this)?.0.clone();
    rt::new_iface_proxy(env, C_ROUTER, Arc::new(RouterRef::All(t)))
}

// ------------------------------------------------------------------ Proxy

fn proxy(env: &mut JNIEnv, this: &JObject) -> FsResult<SharedProxy> {
    Ok(rt::obj_of::<ProxyRef>(env, this)?.0.clone())
}

pub fn p_id(env: &mut JNIEnv, this: &JObject) -> FsResult<String> {
    Ok(proxy(env, this)?.id().to_string())
}
pub fn p_type(env: &mut JNIEnv, this: &JObject) -> FsResult<String> {
    Ok(proxy(env, this)?.typ().to_string())
}
pub fn p_get_addr(env: &mut JNIEnv, this: &JObject) -> FsResult<String> {
    Ok(proxy(env, this)?.addr())
}
pub fn p_status(env: &mut JNIEnv, this: &JObject) -> FsResult<i32> {
    Ok(proxy(env, this)?.status())
}
pub fn p_dns(env: &mut JNIEnv, this: &JObject) -> FsResult<String> {
    Ok(proxy(env, this)?.dns())
}
pub fn p_router<'l>(env: &mut JNIEnv<'l>, this: &JObject) -> FsResult<JObject<'l>> {
    let p = proxy(env, this)?;
    rt::new_iface_proxy(env, C_ROUTER, Arc::new(RouterRef::Of(p)))
}
pub fn p_ping(env: &mut JNIEnv, this: &JObject) -> FsResult<bool> {
    Ok(proxy(env, this)?.ping())
}
pub fn p_pause(env: &mut JNIEnv, this: &JObject) -> FsResult<bool> {
    Ok(proxy(env, this)?.pause())
}
pub fn p_resume(env: &mut JNIEnv, this: &JObject) -> FsResult<bool> {
    Ok(proxy(env, this)?.resume())
}
pub fn p_refresh(env: &mut JNIEnv, this: &JObject) -> FsResult<()> {
    proxy(env, this)?.refresh().map_err(FsError::new)
}
pub fn p_stop(env: &mut JNIEnv, this: &JObject) -> FsResult<()> {
    proxy(env, this)?.stop();
    Ok(())
}

// ------------------------------------------------------------------ Router

fn with_router<T>(
    env: &mut JNIEnv,
    this: &JObject,
    f: impl FnOnce(&RouterRef) -> T,
) -> FsResult<T> {
    let r = rt::obj_of::<RouterRef>(env, this)?;
    Ok(f(&r))
}

pub fn rt_ip4(env: &mut JNIEnv, this: &JObject) -> FsResult<bool> {
    with_router(env, this, |r| match r {
        RouterRef::All(t) => t.proxies().router_ip4(),
        RouterRef::Of(p) => p.ip4(),
    })
}
pub fn rt_ip6(env: &mut JNIEnv, this: &JObject) -> FsResult<bool> {
    with_router(env, this, |r| match r {
        RouterRef::All(t) => t.proxies().router_ip6(),
        RouterRef::Of(p) => p.ip6(),
    })
}
pub fn rt_mtu(env: &mut JNIEnv, this: &JObject) -> FsResult<i64> {
    with_router(env, this, |r| match r {
        RouterRef::All(t) => t.proxies().router_mtu(),
        RouterRef::Of(p) => p.mtu(),
    })?
    .ok_or_else(|| FsError::new("proxy: missing mtu"))
}
pub fn rt_reaches(env: &mut JNIEnv, this: &JObject, csv: String) -> FsResult<bool> {
    with_router(env, this, |r| match r {
        RouterRef::All(t) => t.proxies().router_reaches(&csv),
        RouterRef::Of(p) => p.reaches(&csv),
    })
}
pub fn rt_contains(
    env: &mut JNIEnv,
    this: &JObject,
    who: String,
    prefix: String,
) -> FsResult<bool> {
    with_router(env, this, |r| match r {
        RouterRef::All(t) => t.proxies().router_contains(&who, &prefix),
        RouterRef::Of(p) => p.contains(&who, &prefix),
    })
}
pub fn rt_self(env: &mut JNIEnv, this: &JObject, ip: String) -> FsResult<bool> {
    with_router(env, this, |r| match r {
        RouterRef::All(t) => t.proxies().router_self(&ip),
        RouterRef::Of(p) => p.is_self(&ip),
    })
}
pub fn rt_stat<'l>(env: &mut JNIEnv<'l>, this: &JObject) -> FsResult<JObject<'l>> {
    let s = with_router(env, this, |r| match r {
        RouterRef::All(t) => t.proxies().router_stat(),
        RouterRef::Of(p) => p.stat(),
    })?;
    rt::new_struct_object(env, stats_struct(&s))
}
/// `via()`: the proxy this router hops through; an error when it does not hop (firestack `errNop`).
pub fn rt_via<'l>(env: &mut JNIEnv<'l>, this: &JObject) -> FsResult<JObject<'l>> {
    let v = with_router(env, this, |r| match r {
        RouterRef::All(_) => None,
        RouterRef::Of(p) => p.via(),
    })?;
    match v {
        Some(v) => proxy_obj(env, v),
        None => Err(FsError::new("proxy: nop")),
    }
}

fn stats_struct(s: &RouterStats) -> Arc<Struct> {
    let o = Struct::new(C_ROUTER_STATS);
    for (k, v) in [
        ("Hdl", &s.hdl),
        ("Addrs", &s.addrs),
        ("LastErr", &s.last_err),
        ("LastRxErr", &s.last_rx_err),
        ("LastTxErr", &s.last_tx_err),
        ("Status", &s.status),
        ("StatusReason", &s.status_reason),
        ("Extra", &s.extra),
    ] {
        o.set(k, Field::Str(v.clone()));
    }
    for (k, v) in [
        ("Rx", s.rx),
        ("Tx", s.tx),
        ("ErrRx", s.err_rx),
        ("ErrTx", s.err_tx),
        ("LastTx", s.last_tx),
        ("LastRx", s.last_rx),
        ("LastGoodRx", s.last_good_rx),
        ("LastGoodTx", s.last_good_tx),
        ("LastOK", s.last_ok),
        ("LastRefresh", s.last_refresh),
        ("LastOpen", s.last_open),
        ("Since", s.since),
    ] {
        o.set(k, Field::I64(v));
    }
    o
}

fn controller(env: &mut JNIEnv, c: &JObject) -> FsResult<fs_dialers::Protector> {
    if c.is_null() {
        return Err(FsError::new("proxy: nil controller"));
    }
    let b =
        crate::impls::bridge::JniBridge::new(env, c).map_err(|e| FsError::new(e.to_string()))?;
    Ok(fs_dialers::Protector::new(Arc::new(b)))
}

/// `Proxies.underlay(id, controller)`: an untracked Base-like proxy whose sockets go to `controller`.
pub fn underlay<'l>(
    env: &mut JNIEnv<'l>,
    _this: &JObject,
    id: String,
    c: JObject,
) -> FsResult<JObject<'l>> {
    let p = fs_proxy::builtin::Direct::basic(&id, controller(env, &c)?);
    proxy_obj(env, p)
}

/// `Intra.controlledRouter(controller, id, addrport)`: the router of an untracked Exit using `controller`.
pub fn controlled_router<'l>(
    env: &mut JNIEnv<'l>,
    c: JObject,
    id: String,
    addrport: String,
) -> FsResult<JObject<'l>> {
    let p: SharedProxy =
        fs_proxy::builtin::Direct::exit_with_id(&id, &addrport, controller(env, &c)?);
    rt::new_iface_proxy(env, C_ROUTER, Arc::new(RouterRef::Of(p)))
}

pub fn p_client<'l>(env: &mut JNIEnv<'l>, this: &JObject) -> FsResult<JObject<'l>> {
    let p = proxy(env, this)?;
    rt::new_iface_proxy(env, C_CLIENT, Arc::new(ClientRef(p)))
}

fn ip_meta<'l>(env: &mut JNIEnv<'l>, this: &JObject, v6: bool) -> FsResult<JObject<'l>> {
    let p = rt::obj_of::<ClientRef>(env, this)?.0.clone();
    let m = fs_intra::runtime()
        .block_on(fs_proxy::client::client().ip_metadata(p, v6))
        .map_err(FsError::new)?;
    let s = Struct::new(C_IPMETA);
    for (k, v) in [
        ("ID", m.id),
        ("ProviderURL", m.provider_url),
        ("IP", m.ip),
        ("ASN", m.asn),
        ("ASNOrg", m.asn_org),
        ("ASNDom", m.asn_dom),
        ("CC", m.cc),
        ("City", m.city),
        ("Addr", m.addr),
    ] {
        s.set(k, Field::Str(v));
    }
    s.set("Lat", Field::F64(m.lat));
    s.set("Lon", Field::F64(m.lon));
    rt::new_struct_object(env, s)
}
pub fn c_ip4<'l>(env: &mut JNIEnv<'l>, this: &JObject) -> FsResult<JObject<'l>> {
    ip_meta(env, this, false)
}
pub fn c_ip6<'l>(env: &mut JNIEnv<'l>, this: &JObject) -> FsResult<JObject<'l>> {
    ip_meta(env, this, true)
}
