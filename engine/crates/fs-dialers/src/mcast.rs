// Copyright (c) 2026 RethinkReloaded contributors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Link-local multicast sends (mDNS). A socket with no multicast interface leaves the egress choice to the
//! routing tables, which on Android (Wi-Fi and mobile data both up, per-network policy routing) do not reliably
//! put 224.0.0.251 on the LAN. So the datagram goes out each LAN-like interface explicitly: up, multicast-capable,
//! not loopback, not point-to-point (mobile data, VPN tunnels).

use std::collections::BTreeMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};

/// An interface fit for link-local multicast: its IPv4 addresses and its index (for IPv6).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct McastIf {
    pub name: String,
    pub index: u32,
    pub v4: Vec<Ipv4Addr>,
    pub v6: bool,
}

type GetIfAddrs = unsafe extern "C" fn(*mut *mut libc::ifaddrs) -> libc::c_int;
type FreeIfAddrs = unsafe extern "C" fn(*mut libc::ifaddrs);

/// getifaddrs / freeifaddrs, looked up at run time: Bionic has them from API 24, and the app supports API 23.
fn ifaddrs_fns() -> Option<(GetIfAddrs, FreeIfAddrs)> {
    // SAFETY: dlsym on the default namespace with NUL-terminated names; the symbols have these C signatures.
    unsafe {
        let g = libc::dlsym(libc::RTLD_DEFAULT, c"getifaddrs".as_ptr());
        let f = libc::dlsym(libc::RTLD_DEFAULT, c"freeifaddrs".as_ptr());
        if g.is_null() || f.is_null() {
            return None;
        }
        Some((
            std::mem::transmute::<*mut libc::c_void, GetIfAddrs>(g),
            std::mem::transmute::<*mut libc::c_void, FreeIfAddrs>(f),
        ))
    }
}

/// The LAN-like interfaces (see the module docs), by name.
pub fn lan_interfaces() -> Vec<McastIf> {
    let mut out: BTreeMap<String, McastIf> = BTreeMap::new();
    let Some((getifaddrs, freeifaddrs)) = ifaddrs_fns() else {
        return Vec::new(); // Android 6 (API 23) lacks getifaddrs: callers fall back to routing
    };
    // SAFETY: getifaddrs allocates a list we only read and then free; every pointer is checked for null.
    unsafe {
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        if getifaddrs(&mut head) != 0 {
            return Vec::new();
        }
        let mut p = head;
        while !p.is_null() {
            let ifa = &*p;
            p = ifa.ifa_next;
            let flags = ifa.ifa_flags as libc::c_int;
            let want = libc::IFF_UP | libc::IFF_MULTICAST;
            if flags & want != want || flags & (libc::IFF_LOOPBACK | libc::IFF_POINTOPOINT) != 0 {
                continue;
            }
            if ifa.ifa_name.is_null() || ifa.ifa_addr.is_null() {
                continue;
            }
            let name = std::ffi::CStr::from_ptr(ifa.ifa_name)
                .to_string_lossy()
                .into_owned();
            if name.starts_with("tun") || name.starts_with("dummy") {
                continue;
            }
            let e = out.entry(name.clone()).or_insert_with(|| McastIf {
                index: libc::if_nametoindex(ifa.ifa_name),
                name,
                ..Default::default()
            });
            match (*ifa.ifa_addr).sa_family as libc::c_int {
                libc::AF_INET => {
                    let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                    e.v4.push(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)));
                }
                libc::AF_INET6 => e.v6 = true,
                _ => {}
            }
        }
        freeifaddrs(head);
    }
    out.into_values()
        .filter(|i| !i.v4.is_empty() || i.v6)
        .collect()
}

impl crate::UdpConn {
    /// Sends `b` to the multicast group `dst` out of every LAN-like interface of its family; with none (or for
    /// sockets of other stacks), a plain send. Ok when any send went out.
    pub async fn send_multicast(&self, b: &[u8], dst: SocketAddr) -> io::Result<usize> {
        let Some(s) = self.socket() else {
            return self.send_to(b, dst).await;
        };
        let r = socket2::SockRef::from(s);
        let mut sent = None;
        let mut last = None;
        for i in lan_interfaces() {
            let set = if dst.is_ipv6() {
                if !i.v6 {
                    continue;
                }
                r.set_multicast_if_v6(i.index)
            } else {
                let Some(a) = i.v4.first() else { continue };
                r.set_multicast_if_v4(a)
            };
            if let Err(e) = set {
                last = Some(e);
                continue;
            }
            match s.send_to(b, dst).await {
                Ok(n) => sent = Some(n),
                Err(e) => last = Some(e),
            }
        }
        match (sent, last) {
            (Some(n), _) => Ok(n),
            (None, Some(e)) => Err(e),
            (None, None) => self.send_to(b, dst).await, // no LAN-like interface: let routing decide
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_no_loopback_or_tunnels() {
        for i in lan_interfaces() {
            assert!(
                !i.name.starts_with("lo") && !i.name.starts_with("tun"),
                "{i:?}"
            );
        }
    }
}
