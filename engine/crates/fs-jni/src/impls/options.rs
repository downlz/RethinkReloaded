// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/settings/config.go (DNSOptions, ProxyOptions)

//! `settings.DNSOptions` and `settings.ProxyOptions` (and their `Settings.new…` constructors), as firestack parses
//! them. Neither is consumed by the engine; Kotlin may build them.

use crate::rt::{self, Field, FsError, FsResult, Struct};
use jni::JNIEnv;
use jni::objects::JObject;
use std::net::{IpAddr, SocketAddr};

const C_DNSOPTS: &str = "com/celzero/firestack/settings/DNSOptions";
const C_PROXYOPTS: &str = "com/celzero/firestack/settings/ProxyOptions";

/// Go `net.SplitHostPort`.
fn split_host_port(s: &str) -> Result<(String, String), String> {
    if let Some(rest) = s.strip_prefix('[') {
        let (h, tail) = rest.split_once(']').ok_or_else(|| format!("address {s}: missing ']' in address"))?;
        let port = tail.strip_prefix(':').ok_or_else(|| format!("address {s}: missing port in address"))?;
        return Ok((h.to_string(), port.to_string()));
    }
    match s.rsplit_once(':') {
        None => Err(format!("address {s}: missing port in address")),
        Some((h, _)) if h.contains(':') => Err(format!("address {s}: too many colons in address")),
        Some((h, p)) => Ok((h.to_string(), p.to_string())),
    }
}

/// Go `net.JoinHostPort`.
fn join_host_port(h: &str, p: &str) -> String {
    if h.contains(':') { format!("[{h}]:{p}") } else { format!("{h}:{p}") }
}

fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

/// firestack `addrport(ip, port)`: `ip` with `port`, or `ip` itself an ip:port.
fn addrport(ip: &str, port: &str) -> Result<SocketAddr, String> {
    if let Ok(a) = ip.parse::<IpAddr>() {
        let p: i64 = port.parse().map_err(|e| format!("strconv.Atoi: parsing {port:?}: {e}"))?;
        return Ok(SocketAddr::new(unmap(a), p as u16));
    }
    ip.parse::<SocketAddr>().map_err(|e| e.to_string())
}

fn dns_opts(addr: String, ips: String, port: u16) -> std::sync::Arc<Struct> {
    let s = Struct::new(C_DNSOPTS);
    s.set("_addr", Field::Str(addr));
    s.set("_ips", Field::Str(ips));
    s.set("_port", Field::I32(port as i32));
    s
}

/// firestack `NewDNSOptions(ipport)`.
fn new_dns(ipport: &str) -> Result<std::sync::Arc<Struct>, String> {
    let (ip, port) = split_host_port(ipport)?;
    let a = addrport(&ip, &port)?;
    Ok(dns_opts(a.to_string(), String::new(), a.port()))
}

/// firestack `NewDNSOptionsFromHostname(idOrHostOrHostPort, ipOrIPPortCsv)`.
fn new_dns_from_hostname(host: &str, csv: &str) -> Result<std::sync::Arc<Struct>, String> {
    if host.is_empty() {
        return Err("dnsopt: invalid args".into());
    }
    let (mut id, mut port) = split_host_port(host).unwrap_or_default();
    if id.is_empty() {
        id = host.to_string();
    }
    let mut from_hostport = !port.is_empty();
    let mut p16 = 53u16;
    if from_hostport {
        match port.parse::<u16>() {
            Ok(x) if x > 0 => p16 = x,
            _ => {
                port = "53".into();
                from_hostport = false;
            }
        }
    }
    let (mut ips, mut ports) = (Vec::new(), Vec::new());
    for x in csv.split(',') {
        if let Ok(a) = x.parse::<SocketAddr>() {
            ips.push(a.ip().to_string());
            if a.port() > 0 {
                ports.push(a.port());
            }
        } else if let Ok(a) = x.parse::<IpAddr>() {
            ips.push(a.to_string());
        }
    }
    if from_hostport {
    } else if let Some(p) = ports.first() {
        port = p.to_string();
        p16 = *p;
    } else {
        port = "53".into();
        p16 = 53;
    }
    Ok(dns_opts(join_host_port(&id, &port), ips.join(","), p16))
}

fn dns_struct(env: &mut JNIEnv, this: &JObject) -> FsResult<std::sync::Arc<Struct>> {
    rt::struct_of(env, this)
}

/// `new DNSOptions(ipport)` (no error path in the Java constructor: an unparsable address leaves it empty)
pub fn dns_new(_env: &mut JNIEnv, ipport: String) -> FsResult<i32> {
    Ok(rt::alloc_refnum(new_dns(&ipport).unwrap_or_else(|_| dns_opts(String::new(), String::new(), 53))))
}
pub fn dns_new_from_hostname(_env: &mut JNIEnv, host: String, csv: String) -> FsResult<i32> {
    Ok(rt::alloc_refnum(new_dns_from_hostname(&host, &csv).unwrap_or_else(|_| dns_opts(String::new(), String::new(), 53))))
}
pub fn settings_new_dns<'l>(env: &mut JNIEnv<'l>, ipport: String) -> FsResult<JObject<'l>> {
    let s = new_dns(&ipport).map_err(FsError::new)?;
    rt::new_struct_object(env, s)
}
pub fn settings_new_dns_from_hostname<'l>(env: &mut JNIEnv<'l>, host: String, csv: String) -> FsResult<JObject<'l>> {
    let s = new_dns_from_hostname(&host, &csv).map_err(FsError::new)?;
    rt::new_struct_object(env, s)
}
pub fn dns_addr_port(env: &mut JNIEnv, this: &JObject) -> FsResult<String> {
    Ok(dns_struct(env, this)?.str("_addr"))
}
pub fn dns_resolved_addrs(env: &mut JNIEnv, this: &JObject) -> FsResult<String> {
    Ok(dns_struct(env, this)?.str("_ips"))
}
pub fn dns_string(env: &mut JNIEnv, this: &JObject) -> FsResult<String> {
    dns_addr_port(env, this)
}

/// firestack `NewAuthProxyOptions("", "", "", ip, port, nil)`; None when neither an address nor a port is given.
fn new_proxy_opts(ip: &str, port: &str) -> Option<std::sync::Arc<Struct>> {
    let ip = ip.trim_end_matches('/');
    let ippstr;
    let (mut ipstr, mut host, mut port) = (String::new(), String::new(), port.to_string());
    match addrport(ip, &port) {
        Ok(a) => {
            ippstr = a.to_string();
            ipstr = a.ip().to_string();
        }
        Err(_) if !ip.is_empty() => {
            ippstr = ip.to_string();
            let (h, p) = split_host_port(ip).unwrap_or_default();
            host = h;
            port = p;
        }
        Err(_) if !port.is_empty() => ippstr = format!(":{port}"),
        Err(_) => return None,
    }
    let s = Struct::new(C_PROXYOPTS);
    s.set("Host", Field::Str(host));
    s.set("IP", Field::Str(ipstr));
    s.set("Port", Field::Str(port));
    s.set("IPPort", Field::Str(ippstr));
    s.set("Scheme", Field::Str("http".into()));
    Some(s)
}

/// Go `url.QueryEscape`.
fn query_escape(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => o.push(b as char),
            b' ' => o.push('+'),
            _ => o.push_str(&format!("%{b:02X}")),
        }
    }
    o
}

pub fn proxy_new(_env: &mut JNIEnv, ip: String, port: String) -> FsResult<i32> {
    Ok(rt::alloc_refnum(new_proxy_opts(&ip, &port).unwrap_or_else(|| Struct::new(C_PROXYOPTS))))
}
pub fn settings_new_proxy<'l>(env: &mut JNIEnv<'l>, ip: String, port: String) -> FsResult<JObject<'l>> {
    match new_proxy_opts(&ip, &port) {
        Some(s) => rt::new_struct_object(env, s),
        None => Ok(JObject::null()),
    }
}

macro_rules! field {
    ($get:ident, $set:ident, $name:literal) => {
        pub fn $get(env: &mut JNIEnv, this: &JObject) -> FsResult<String> {
            Ok(rt::struct_of(env, this)?.str($name))
        }
        pub fn $set(env: &mut JNIEnv, this: &JObject, v: String) -> FsResult<()> {
            rt::struct_of(env, this)?.set($name, Field::Str(v));
            Ok(())
        }
    };
}
field!(p_get_host, p_set_host, "Host");
field!(p_get_ip, p_set_ip, "IP");
field!(p_get_port, p_set_port, "Port");
field!(p_get_ipport, p_set_ipport, "IPPort");
field!(p_get_scheme, p_set_scheme, "Scheme");

fn auth(s: &Struct) -> (String, String) {
    (s.str("_user"), s.str("_pass"))
}
pub fn p_has_auth(env: &mut JNIEnv, this: &JObject) -> FsResult<bool> {
    let s = rt::struct_of(env, this)?;
    let (u, p) = auth(&s);
    Ok(!u.is_empty() && !p.is_empty())
}
pub fn p_url(env: &mut JNIEnv, this: &JObject) -> FsResult<String> {
    let s = rt::struct_of(env, this)?;
    Ok(format!("{}://{}", s.str("Scheme"), s.str("IPPort")))
}
pub fn p_full_url(env: &mut JNIEnv, this: &JObject) -> FsResult<String> {
    let s = rt::struct_of(env, this)?;
    let (u, p) = auth(&s);
    let (scheme, ipp) = (s.str("Scheme"), s.str("IPPort"));
    Ok(if !u.is_empty() && !p.is_empty() {
        format!("{scheme}://{}:{}@{ipp}", query_escape(&u), query_escape(&p))
    } else if !u.is_empty() {
        format!("{scheme}://{}@{ipp}", query_escape(&u))
    } else {
        format!("{scheme}://{ipp}")
    })
}
pub fn p_string(env: &mut JNIEnv, this: &JObject) -> FsResult<String> {
    let s = rt::struct_of(env, this)?;
    let (u, p) = auth(&s);
    Ok(format!("{u},{p},{}", s.str("IPPort")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_as_firestack() {
        let d = new_dns("[::ffff:1.2.3.4]:5353").unwrap();
        assert_eq!(d.str("_addr"), "1.2.3.4:5353");
        assert!(matches!(d.get("_port"), Field::I32(5353)));
        assert!(new_dns("1.2.3.4").is_err(), "needs a port");
        let h = new_dns_from_hostname("dns.example", "9.9.9.9:853,2620:fe::fe").unwrap();
        assert_eq!((h.str("_addr"), h.str("_ips")), ("dns.example:853".into(), "9.9.9.9,2620:fe::fe".into()));
        let h = new_dns_from_hostname("dns.example:5300", "9.9.9.9:853").unwrap();
        assert_eq!(h.str("_addr"), "dns.example:5300", "the host's port wins");
        let p = new_proxy_opts("10.0.0.1", "1080").unwrap();
        assert_eq!((p.str("IPPort"), p.str("IP"), p.str("Scheme")), ("10.0.0.1:1080".into(), "10.0.0.1".into(), "http".into()));
        let p = new_proxy_opts("proxy.example:3128", "").unwrap();
        assert_eq!((p.str("IPPort"), p.str("Host"), p.str("Port")), ("proxy.example:3128".into(), "proxy.example".into(), "3128".into()));
        assert!(new_proxy_opts("", "").is_none());
        assert_eq!(query_escape("a b@c"), "a+b%40c");
    }
}
