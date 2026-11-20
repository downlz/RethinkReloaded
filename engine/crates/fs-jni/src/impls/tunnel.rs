// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/tun2socks.go
// Derived-From: celzero/firestack@d3d530ea3e:intra/tunnel.go
// Derived-From: celzero/firestack@d3d530ea3e:intra/dns.go (Add*Transport)

//! Natives of `Intra` (connect, transports), `Tunnel`, `DNSResolver`, `DNSTransport`, `DefaultDNS`, and the
//! Phase 1 `Proxies` / `Router` / `Proxy` objects (built-in Base / Exit / Block / Auto only).

use crate::impls::bridge::JniBridge;
use crate::rt::{self, FsError, FsResult, Struct};
use fs_core::bridge::{SharedBridge, dns_status};
use fs_dns::transport::Transport;
use fs_intra::{DefaultDnsSpec, Tunnel, runtime};
use jni::JNIEnv;
use jni::objects::JObject;
use std::sync::Arc;

const C_TUNNEL: &str = "com/celzero/firestack/intra/Tunnel";
const C_DEFAULT_DNS: &str = "com/celzero/firestack/intra/DefaultDNS";
const C_RESOLVER: &str = "com/celzero/firestack/backend/DNSResolver";
const C_TRANSPORT: &str = "com/celzero/firestack/backend/DNSTransport";
const C_PROXIES: &str = "com/celzero/firestack/backend/Proxies";
const C_ROUTER: &str = "com/celzero/firestack/backend/Router";
const C_PROXY: &str = "com/celzero/firestack/backend/Proxy";
const C_ROUTER_STATS: &str = "com/celzero/firestack/backend/RouterStats";

/// proxy status `TOK` (backend constant)
const TOK: i32 = -1;
const BUILTIN_PROXIES: &[&str] = &["Base", "Exit", "Block", "Auto"];

pub struct TunnelRef(pub Arc<Tunnel>);
pub struct ResolverRef(pub Arc<Tunnel>);
pub struct TransportRef(pub Arc<dyn Transport>);
pub struct DefaultDnsRef(pub DefaultDnsSpec);
pub struct ProxiesRef(pub Arc<Tunnel>);
pub struct RouterRef(pub Arc<Tunnel>);
pub struct ProxyRef(pub Arc<Tunnel>, pub String);

fn tunnel_of(env: &mut JNIEnv, t: &JObject) -> FsResult<Arc<Tunnel>> {
    Ok(rt::obj_of::<TunnelRef>(env, t)?.0.clone())
}

// ------------------------------------------------------------------ Intra

/// `Intra.newDefaultDNS(typ, url, ips)`
pub fn new_default_dns<'l>(
    env: &mut JNIEnv<'l>,
    typ: String,
    url: String,
    ips: String,
) -> FsResult<JObject<'l>> {
    let spec = DefaultDnsSpec { typ, url, ips };
    spec.validate()?;
    rt::new_iface_proxy(env, C_DEFAULT_DNS, Arc::new(DefaultDnsRef(spec)))
}

/// `Intra.newBuiltinDefaultDNS()`: the system resolver.
pub fn new_builtin_default_dns<'l>(env: &mut JNIEnv<'l>) -> FsResult<JObject<'l>> {
    rt::new_iface_proxy(
        env,
        C_DEFAULT_DNS,
        Arc::new(DefaultDnsRef(DefaultDnsSpec::default())),
    )
}

#[allow(clippy::too_many_arguments)]
fn do_connect<'l>(
    env: &mut JNIEnv<'l>,
    fd: i64,
    link_mtu: i64,
    tun_mtu: i64,
    ifaddrs: &str,
    fakedns: &str,
    dtr: &JObject,
    bridge: &JObject,
) -> FsResult<JObject<'l>> {
    if bridge.is_null() {
        return Err(FsError::new("connect: nil bridge"));
    }
    let spec = if dtr.is_null() {
        None
    } else {
        Some(rt::obj_of::<DefaultDnsRef>(env, dtr)?.0.clone())
    };
    let b: SharedBridge = Arc::new(JniBridge::new(env, bridge)?);
    let fakedns = if fakedns.is_empty() {
        "10.111.222.3:53,[fd66:f83a:c650::3]:53"
    } else {
        fakedns
    };
    let _rt = runtime().enter();
    let t = Tunnel::connect(
        fd as i32,
        link_mtu as i32,
        tun_mtu as i32,
        ifaddrs,
        fakedns,
        spec,
        b,
    )?;
    crate::impls::log::info(&format!(
        "tunnel: connected (fd {fd}, mtu {tun_mtu}/{link_mtu}, fakedns {fakedns})"
    ));
    rt::new_iface_proxy(env, C_TUNNEL, Arc::new(TunnelRef(t)))
}

/// `Intra.connect(fd, linkmtu, tunmtu, ifaddrs, fakedns, dtr, bdg)`
#[allow(clippy::too_many_arguments)]
pub fn connect<'l>(
    env: &mut JNIEnv<'l>,
    fd: i64,
    link_mtu: i64,
    tun_mtu: i64,
    ifaddrs: String,
    fakedns: String,
    dtr: JObject<'l>,
    bridge: JObject<'l>,
) -> FsResult<JObject<'l>> {
    // firestack builds two tunnels when linkmtu <= 0 (leaking one); here linkmtu <= 0 just means "= tunmtu"
    let lm = if link_mtu > 0 { link_mtu } else { tun_mtu };
    do_connect(env, fd, lm, tun_mtu, &ifaddrs, &fakedns, &dtr, &bridge)
}

/// `Intra.connect2(fd, tunmtu, dtr, bdg)` (firestack ignores `dtr` here; we honour it, see engine/PARITY.md)
pub fn connect2<'l>(
    env: &mut JNIEnv<'l>,
    fd: i64,
    tun_mtu: i64,
    dtr: JObject<'l>,
    bridge: JObject<'l>,
) -> FsResult<JObject<'l>> {
    do_connect(env, fd, tun_mtu, tun_mtu, "", "", &dtr, &bridge)
}

/// `Intra.connect3(fd, tunmtu, bdg)`
pub fn connect3<'l>(
    env: &mut JNIEnv<'l>,
    fd: i64,
    tun_mtu: i64,
    bridge: JObject<'l>,
) -> FsResult<JObject<'l>> {
    do_connect(env, fd, tun_mtu, tun_mtu, "", "", &JObject::null(), &bridge)
}

/// `Intra.newTunnel(fd, mtu, ifaddrs, fakedns, dtr, bdg)`
#[allow(clippy::too_many_arguments)]
pub fn new_tunnel<'l>(
    env: &mut JNIEnv<'l>,
    fd: i64,
    mtu: i64,
    ifaddrs: String,
    fakedns: String,
    dtr: JObject<'l>,
    bridge: JObject<'l>,
) -> FsResult<JObject<'l>> {
    do_connect(env, fd, mtu, mtu, &ifaddrs, &fakedns, &dtr, &bridge)
}

/// `Intra.newTunnel2(fd, linkmtu, tunmtu, ifaddrs, fakedns, dtr, bdg)`
#[allow(clippy::too_many_arguments)]
pub fn new_tunnel2<'l>(
    env: &mut JNIEnv<'l>,
    fd: i64,
    link_mtu: i64,
    tun_mtu: i64,
    ifaddrs: String,
    fakedns: String,
    dtr: JObject<'l>,
    bridge: JObject<'l>,
) -> FsResult<JObject<'l>> {
    do_connect(
        env, fd, link_mtu, tun_mtu, &ifaddrs, &fakedns, &dtr, &bridge,
    )
}

/// `Intra.addDoHTransport(t, id, url, ipcsv)`
pub fn add_doh(
    env: &mut JNIEnv,
    t: JObject,
    id: String,
    url: String,
    ipcsv: String,
) -> FsResult<()> {
    Ok(tunnel_of(env, &t)?.add_doh(&id, &url, &ipcsv)?)
}

/// `Intra.addDoHTransport2(t, id, url, ipurl, ipcsv)`: `ipurl` (a separate IP-info endpoint) is not used yet.
pub fn add_doh2(
    env: &mut JNIEnv,
    t: JObject,
    id: String,
    url: String,
    _ipurl: String,
    ipcsv: String,
) -> FsResult<()> {
    Ok(tunnel_of(env, &t)?.add_doh(&id, &url, &ipcsv)?)
}

/// `Intra.addDNSProxy(t, id, ipportcsv)`
pub fn add_dns_proxy(env: &mut JNIEnv, t: JObject, id: String, csv: String) -> FsResult<()> {
    Ok(tunnel_of(env, &t)?.add_dns53(&id, &csv)?)
}

/// `Intra.setSystemDNS(t, ipcsv)`
pub fn set_system_dns(env: &mut JNIEnv, t: JObject, csv: String) -> FsResult<()> {
    Ok(tunnel_of(env, &t)?.add_dns53(fs_dns::ids::SYSTEM, &csv)?)
}

/// `Intra.addDefaultTransport(t, typ, url, ips)`: all empty = system resolver.
pub fn add_default_transport(
    env: &mut JNIEnv,
    t: JObject,
    typ: String,
    url: String,
    ips: String,
) -> FsResult<()> {
    Ok(tunnel_of(env, &t)?.set_default_dns(DefaultDnsSpec { typ, url, ips })?)
}

// ------------------------------------------------------------------ Tunnel

fn this_tunnel(env: &mut JNIEnv, this: &JObject) -> FsResult<Arc<Tunnel>> {
    tunnel_of(env, this)
}

pub fn t_is_connected(env: &mut JNIEnv, this: &JObject) -> FsResult<bool> {
    Ok(this_tunnel(env, this)?.is_connected())
}
pub fn t_enabled(env: &mut JNIEnv, this: &JObject) -> FsResult<bool> {
    Ok(this_tunnel(env, this)?.enabled())
}
pub fn t_disconnect(env: &mut JNIEnv, this: &JObject) -> FsResult<()> {
    this_tunnel(env, this)?.disconnect();
    crate::impls::log::info("tunnel: disconnected");
    Ok(())
}
pub fn t_unlink(env: &mut JNIEnv, this: &JObject) -> FsResult<()> {
    this_tunnel(env, this)?.unlink();
    Ok(())
}
pub fn t_mtu(env: &mut JNIEnv, this: &JObject) -> FsResult<i32> {
    Ok(this_tunnel(env, this)?.mtu())
}
pub fn t_set_link_mtu(env: &mut JNIEnv, this: &JObject, m: i64) -> FsResult<bool> {
    Ok(this_tunnel(env, this)?.set_link_mtu(m as i32))
}
/// `setLinkAndRoutes(fd, mtu, engine)`
pub fn t_set_link_and_routes(
    env: &mut JNIEnv,
    this: &JObject,
    fd: i64,
    mtu: i64,
    engine: i64,
) -> FsResult<()> {
    let t = this_tunnel(env, this)?;
    let _rt = runtime().enter();
    Ok(t.set_link_and_routes(fd as i32, mtu as i32, mtu as i32, engine)?)
}
/// `setLinkAndRoutes2(fd, tunmtu, linkmtu, engine)`
pub fn t_set_link_and_routes2(
    env: &mut JNIEnv,
    this: &JObject,
    fd: i64,
    tun_mtu: i64,
    link_mtu: i64,
    engine: i64,
) -> FsResult<()> {
    let t = this_tunnel(env, this)?;
    let _rt = runtime().enter();
    Ok(t.set_link_and_routes(fd as i32, tun_mtu as i32, link_mtu as i32, engine)?)
}
/// `restart(fd, linkmtu, tunmtu, engine)` (note the argument order differs from setLinkAndRoutes2)
pub fn t_restart(
    env: &mut JNIEnv,
    this: &JObject,
    fd: i64,
    link_mtu: i64,
    tun_mtu: i64,
    engine: i64,
) -> FsResult<()> {
    let t = this_tunnel(env, this)?;
    let _rt = runtime().enter();
    Ok(t.restart(fd as i32, link_mtu as i32, tun_mtu as i32, engine)?)
}
pub fn t_close_conns(env: &mut JNIEnv, this: &JObject, csv: String) -> FsResult<String> {
    Ok(this_tunnel(env, this)?.close_conns(&csv))
}
/// `setPcap(path)`: packet capture is not ported yet (Phase 3); accepted and ignored except to log it.
pub fn t_set_pcap(env: &mut JNIEnv, this: &JObject, path: String) -> FsResult<()> {
    this_tunnel(env, this)?;
    if !path.is_empty() {
        crate::impls::log::warn(&format!("tunnel: pcap not supported yet ({path})"));
    }
    Ok(())
}
pub fn t_get_resolver<'l>(env: &mut JNIEnv<'l>, this: &JObject) -> FsResult<JObject<'l>> {
    let t = this_tunnel(env, this)?;
    if !t.is_connected() {
        return Err(FsError::new("tunnel closed"));
    }
    rt::new_iface_proxy(env, C_RESOLVER, Arc::new(ResolverRef(t)))
}
pub fn t_get_proxies<'l>(env: &mut JNIEnv<'l>, this: &JObject) -> FsResult<JObject<'l>> {
    let t = this_tunnel(env, this)?;
    if !t.is_connected() {
        return Err(FsError::new("tunnel closed"));
    }
    rt::new_iface_proxy(env, C_PROXIES, Arc::new(ProxiesRef(t)))
}

// ------------------------------------------------------------------ DNSResolver

fn resolver(env: &mut JNIEnv, this: &JObject) -> FsResult<Arc<Tunnel>> {
    Ok(rt::obj_of::<ResolverRef>(env, this)?.0.clone())
}

pub fn r_get<'l>(env: &mut JNIEnv<'l>, this: &JObject, id: String) -> FsResult<JObject<'l>> {
    let t = resolver(env, this)?;
    let tr = t
        .resolver()
        .get(&id)
        .ok_or_else(|| FsError::new(format!("dns: no such transport {id}")))?;
    rt::new_iface_proxy(env, C_TRANSPORT, Arc::new(TransportRef(tr)))
}
pub fn r_remove(env: &mut JNIEnv, this: &JObject, id: String) -> FsResult<bool> {
    Ok(resolver(env, this)?.resolver().remove(&id))
}
/// `add(DNSTransport)`: only transports created by this engine can be (re-)added.
pub fn r_add(env: &mut JNIEnv, this: &JObject, t: JObject) -> FsResult<bool> {
    let tun = resolver(env, this)?;
    if t.is_null() {
        return Ok(false);
    }
    match rt::obj_of::<TransportRef>(env, &t) {
        Ok(tr) => Ok(tun.resolver().add(tr.0.clone())),
        Err(_) => Ok(false),
    }
}
pub fn r_get_ips(env: &mut JNIEnv, this: &JObject, id: String) -> FsResult<String> {
    let t = resolver(env, this)?;
    Ok(t.resolver()
        .get(&id)
        .map(|tr| tr.addr())
        .unwrap_or_default())
}
pub fn r_live_transports(env: &mut JNIEnv, this: &JObject) -> FsResult<String> {
    Ok(resolver(env, this)?.resolver().live_transports())
}
/// `refresh()`: clears the cache (transports re-dial lazily); returns the live transport ids.
pub fn r_refresh(env: &mut JNIEnv, this: &JObject) -> FsResult<String> {
    let t = resolver(env, this)?;
    t.resolver().clear_cache();
    Ok(t.resolver().live_transports())
}
pub fn r_status(env: &mut JNIEnv, this: &JObject) -> FsResult<i32> {
    let t = resolver(env, this)?;
    Ok(if t.is_connected() {
        dns_status::COMPLETE
    } else {
        dns_status::DEND
    })
}
/// `translate(alg, fix)`: ALG (fake-IP translation) arrives in Phase 1C; with translation off (Kotlin's default in
/// DNS mode) this is a no-op.
pub fn r_translate(env: &mut JNIEnv, this: &JObject, _alg: bool, _fix: bool) -> FsResult<()> {
    resolver(env, this)?;
    Ok(())
}

// ------------------------------------------------------------------ DNSTransport / DefaultDNS

enum AnyTransport {
    T(Arc<dyn Transport>),
    D(DefaultDnsSpec),
}

fn transport(env: &mut JNIEnv, this: &JObject) -> FsResult<AnyTransport> {
    let r = rt::refnum_of(env, this)?;
    let o = rt::lookup(r).ok_or_else(|| FsError::new("unknown transport"))?;
    if let Some(t) = o.downcast_ref::<TransportRef>() {
        return Ok(AnyTransport::T(t.0.clone()));
    }
    if let Some(d) = o.downcast_ref::<DefaultDnsRef>() {
        return Ok(AnyTransport::D(d.0.clone()));
    }
    Err(FsError::new("not a transport"))
}

pub fn tr_id(env: &mut JNIEnv, this: &JObject) -> FsResult<String> {
    Ok(match transport(env, this)? {
        AnyTransport::T(t) => t.id().to_string(),
        AnyTransport::D(_) => fs_dns::ids::DEFAULT.into(),
    })
}
pub fn tr_type(env: &mut JNIEnv, this: &JObject) -> FsResult<String> {
    Ok(match transport(env, this)? {
        AnyTransport::T(t) => t.typ().to_string(),
        AnyTransport::D(d) => {
            if d.typ.is_empty() {
                fs_dns::transport::TYPE_DNS53.into()
            } else {
                d.typ
            }
        }
    })
}
pub fn tr_addr(env: &mut JNIEnv, this: &JObject) -> FsResult<String> {
    Ok(match transport(env, this)? {
        AnyTransport::T(t) => t.addr(),
        AnyTransport::D(d) => d.url,
    })
}
pub fn tr_status(env: &mut JNIEnv, this: &JObject) -> FsResult<i32> {
    Ok(match transport(env, this)? {
        AnyTransport::T(t) => t.status(),
        AnyTransport::D(_) => dns_status::START,
    })
}
pub fn tr_p50(env: &mut JNIEnv, this: &JObject) -> FsResult<i64> {
    Ok(match transport(env, this)? {
        AnyTransport::T(t) => t.p50(),
        AnyTransport::D(_) => 0,
    })
}

// ------------------------------------------------------------------ Proxies / Router / Proxy (built-ins)

fn proxies(env: &mut JNIEnv, this: &JObject) -> FsResult<Arc<Tunnel>> {
    Ok(rt::obj_of::<ProxiesRef>(env, this)?.0.clone())
}

pub fn px_router<'l>(env: &mut JNIEnv<'l>, this: &JObject) -> FsResult<JObject<'l>> {
    let t = proxies(env, this)?;
    rt::new_iface_proxy(env, C_ROUTER, Arc::new(RouterRef(t)))
}
pub fn px_get_proxy<'l>(env: &mut JNIEnv<'l>, this: &JObject, id: String) -> FsResult<JObject<'l>> {
    let t = proxies(env, this)?;
    if !BUILTIN_PROXIES.contains(&id.as_str()) {
        return Err(FsError::new(format!("proxy: {id} not found")));
    }
    rt::new_iface_proxy(env, C_PROXY, Arc::new(ProxyRef(t, id)))
}
pub fn px_has_proxy(env: &mut JNIEnv, this: &JObject, id: String) -> FsResult<bool> {
    proxies(env, this)?;
    Ok(BUILTIN_PROXIES.contains(&id.as_str()))
}
pub fn px_remove_proxy(env: &mut JNIEnv, this: &JObject, _id: String) -> FsResult<bool> {
    proxies(env, this)?;
    Ok(false)
}
pub fn px_refresh_proxies(env: &mut JNIEnv, this: &JObject) -> FsResult<String> {
    proxies(env, this)?;
    Ok(BUILTIN_PROXIES.join(","))
}
pub fn px_test_hop(
    env: &mut JNIEnv,
    this: &JObject,
    _via: String,
    _origin: String,
) -> FsResult<String> {
    proxies(env, this)?;
    Ok("hop: unsupported in phase 1".into())
}

fn router(env: &mut JNIEnv, this: &JObject) -> FsResult<Arc<Tunnel>> {
    let r = rt::refnum_of(env, this)?;
    let o = rt::lookup(r).ok_or_else(|| FsError::new("unknown router"))?;
    if let Some(r) = o.downcast_ref::<RouterRef>() {
        return Ok(r.0.clone());
    }
    Err(FsError::new("not a router"))
}

/// The direct (Exit/Base) path is dual-stack.
pub fn rt_ip4(env: &mut JNIEnv, this: &JObject) -> FsResult<bool> {
    router(env, this)?;
    Ok(true)
}
pub fn rt_ip6(env: &mut JNIEnv, this: &JObject) -> FsResult<bool> {
    router(env, this)?;
    Ok(true)
}
pub fn rt_mtu(env: &mut JNIEnv, this: &JObject) -> FsResult<i64> {
    Ok(router(env, this)?.link_mtu() as i64)
}
pub fn rt_reaches(env: &mut JNIEnv, this: &JObject, _csv: String) -> FsResult<bool> {
    router(env, this)?;
    Ok(true)
}
pub fn rt_contains(
    env: &mut JNIEnv,
    this: &JObject,
    _who: String,
    _prefix: String,
) -> FsResult<bool> {
    router(env, this)?;
    Ok(false)
}
pub fn rt_self(env: &mut JNIEnv, this: &JObject, _ip: String) -> FsResult<bool> {
    router(env, this)?;
    Ok(false)
}
pub fn rt_stat<'l>(env: &mut JNIEnv<'l>, this: &JObject) -> FsResult<JObject<'l>> {
    router(env, this)?;
    rt::new_struct_object(env, Struct::new(C_ROUTER_STATS))
}

fn proxy(env: &mut JNIEnv, this: &JObject) -> FsResult<(Arc<Tunnel>, String)> {
    let p = rt::obj_of::<ProxyRef>(env, this)?;
    Ok((p.0.clone(), p.1.clone()))
}

pub fn p_id(env: &mut JNIEnv, this: &JObject) -> FsResult<String> {
    Ok(proxy(env, this)?.1)
}
pub fn p_type(env: &mut JNIEnv, this: &JObject) -> FsResult<String> {
    let (_, id) = proxy(env, this)?;
    Ok(if id == "Block" {
        "noop".into()
    } else {
        "net".into()
    })
}
pub fn p_get_addr(env: &mut JNIEnv, this: &JObject) -> FsResult<String> {
    proxy(env, this)?;
    Ok(String::new())
}
pub fn p_status(env: &mut JNIEnv, this: &JObject) -> FsResult<i32> {
    proxy(env, this)?;
    Ok(TOK)
}
pub fn p_router<'l>(env: &mut JNIEnv<'l>, this: &JObject) -> FsResult<JObject<'l>> {
    let (t, _) = proxy(env, this)?;
    rt::new_iface_proxy(env, C_ROUTER, Arc::new(RouterRef(t)))
}
pub fn p_dns(env: &mut JNIEnv, this: &JObject) -> FsResult<String> {
    proxy(env, this)?;
    Ok(String::new())
}
pub fn p_ping(env: &mut JNIEnv, this: &JObject) -> FsResult<bool> {
    proxy(env, this)?;
    Ok(true)
}
pub fn p_pause(env: &mut JNIEnv, this: &JObject) -> FsResult<bool> {
    proxy(env, this)?;
    Ok(false)
}
pub fn p_resume(env: &mut JNIEnv, this: &JObject) -> FsResult<bool> {
    proxy(env, this)?;
    Ok(false)
}
pub fn p_refresh(env: &mut JNIEnv, this: &JObject) -> FsResult<()> {
    proxy(env, this)?;
    Ok(())
}
pub fn p_stop(env: &mut JNIEnv, this: &JObject) -> FsResult<()> {
    proxy(env, this)?;
    Ok(())
}
