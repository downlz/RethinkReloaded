// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/ipn/wgproxy.go (wgIfConfigOf, loadIPNets, loadMH)

//! WireGuard configuration as Kotlin sends it: UAPI-style `key=value` lines. Interface keys (`private_key`,
//! `address`, `dns`, `mtu`) come first; each `public_key` starts a peer, followed by its `preshared_key`,
//! `endpoint`, `allowed_ip` and `persistent_keepalive_interval`. Amnezia keys (`jc`, `jmin`, `jmax`, `s1`, `s2`,
//! `h1`-`h4`, `client_id`) are parsed but not applied, as upstream. An empty line ends the configuration.

use std::net::IpAddr;

/// An address or network (`ip` alone is a host route).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Net {
    pub ip: IpAddr,
    pub bits: u8,
}

impl Net {
    pub fn parse(s: &str) -> Option<Net> {
        let s = s.trim();
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Some(Net {
                ip,
                bits: if ip.is_ipv4() { 32 } else { 128 },
            });
        }
        let (ip, bits) = s.split_once('/')?;
        let ip: IpAddr = ip.parse().ok()?;
        let bits: u8 = bits.parse().ok()?;
        (bits <= if ip.is_ipv4() { 32 } else { 128 }).then_some(Net { ip, bits })
    }
}

impl std::fmt::Display for Net {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.ip, self.bits)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerCfg {
    pub public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    /// `host:port` or `ip:port`, in order
    pub endpoints: Vec<String>,
    pub allowed: Vec<Net>,
    pub keepalive: Option<u16>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WgCfg {
    pub private_key: [u8; 32],
    pub ifaddrs: Vec<Net>,
    /// DNS servers: hostnames or IPs, in order
    pub dns: Vec<String>,
    /// configured MTU (65535 means auto)
    pub mtu: i64,
    pub peers: Vec<PeerCfg>,
    /// every peer's allowed IPs, plus the DNS servers' (firestack routes DNS through the tunnel)
    pub allowed: Vec<Net>,
    pub replace_peers: bool,
}

fn key32(v: &str) -> Result<[u8; 32], String> {
    let b = v.as_bytes();
    if b.len() != 64 {
        return Err("wg: key must be 64 hex chars".into());
    }
    // bytes, not str slices: a non-ASCII character must be an error, not a char-boundary panic
    let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        match (hex(b[2 * i]), hex(b[2 * i + 1])) {
            (Some(h), Some(l)) => *o = h << 4 | l,
            _ => return Err("wg: key: invalid hex".into()),
        }
    }
    Ok(out)
}

/// firestack `loadIPNets`: csv of addresses and networks (stops at the first invalid one, erring).
fn load_nets(out: &mut Vec<Net>, v: &str) -> Result<(), String> {
    for s in v.split(',') {
        match Net::parse(s) {
            Some(n) => out.push(n),
            None => return Err(format!("wg: bad address {s:?}")),
        }
    }
    Ok(())
}

/// firestack `wgIfConfigOf`.
pub fn parse(id: &str, txt: &str) -> Result<WgCfg, String> {
    let mut c = WgCfg {
        mtu: crate::MAXMTU,
        ..Default::default()
    };
    let mut have_key = false;
    let mut peer: Option<PeerCfg> = None;
    let invalid = |c: &WgCfg| c.ifaddrs.is_empty() || c.dns.is_empty() || c.mtu <= crate::NOMTU;
    for line in txt.lines() {
        if line.is_empty() {
            break; // firestack stops at the first empty line
        }
        let (k, v) = line
            .split_once('=')
            .ok_or_else(|| format!("proxy: wg: {id} failed to parse line {line:?}"))?;
        let k = k.trim().to_ascii_lowercase();
        let v = v.trim().to_ascii_lowercase();
        match k.as_str() {
            "private_key" => {
                c.private_key = key32(&v)?;
                have_key = true;
            }
            "replace_peers" => c.replace_peers = v == "true" || v == "1",
            "address" => load_nets(&mut c.ifaddrs, &v)?,
            "dns" => {
                c.dns.extend(
                    v.split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(String::from),
                );
                let _ = load_nets(&mut c.allowed, &v); // hostnames are not routes
            }
            "mtu" => {
                c.mtu = if v.is_empty() || v == "auto" || v == "(auto)" {
                    crate::MAXMTU
                } else {
                    v.parse::<i64>().map_err(|e| format!("wg: mtu: {e}"))?
                };
                if c.mtu < crate::NOMTU {
                    c.mtu = crate::MAXMTU;
                }
            }
            "public_key" => {
                if let Some(p) = peer.take() {
                    c.peers.push(p);
                }
                peer = Some(PeerCfg {
                    public_key: key32(&v)?,
                    ..Default::default()
                });
            }
            "preshared_key" => {
                if let Some(p) = peer.as_mut() {
                    let k = key32(&v)?;
                    p.preshared_key = (k != [0u8; 32]).then_some(k);
                }
            }
            "endpoint" => {
                if let Some(p) = peer.as_mut() {
                    p.endpoints.extend(
                        v.split(',')
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .map(String::from),
                    );
                }
            }
            "allowed_ip" => {
                load_nets(&mut c.allowed, &v)?;
                if let Some(p) = peer.as_mut() {
                    load_nets(&mut p.allowed, &v)?;
                }
            }
            "persistent_keepalive_interval" => {
                if let Some(p) = peer.as_mut() {
                    p.keepalive = v.parse::<u16>().ok().filter(|s| *s > 0);
                }
            }
            // amnezia (parse-only) and anything else wireguard-go would take over UAPI
            _ => {}
        }
    }
    if let Some(p) = peer.take() {
        c.peers.push(p);
    }
    if invalid(&c) || !have_key {
        return Err("proxy: invalid config".into());
    }
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    const K: &str = "e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a";
    const P: &str = "b85996fecc9c7f1fc6d2572a76eda11d59bcd20be8e543b15ce4bd85a8e75a33";

    #[test]
    fn keys_reject_non_hex_without_panicking() {
        // fuzzer find: a multi-byte character inside a 64-byte key split a str slice
        let k = format!("{}\u{a0}{}", "1".repeat(13), "1".repeat(49));
        assert_eq!(k.len(), 64);
        assert!(key32(&k).is_err());
        assert!(key32(&"g".repeat(64)).is_err());
        assert_eq!(key32(&"0f".repeat(32)).unwrap(), [0x0f; 32]);
    }

    #[test]
    fn firestack_config() {
        let txt = format!(
            "private_key={K}\naddress=10.2.0.2/32,fd00::2\ndns=10.2.0.1,dns.example\nmtu=auto\n\
             public_key={P}\npreshared_key={}\nendpoint=wg.example:51820,1.2.3.4:51820\n\
             allowed_ip=0.0.0.0/0,::/0\npersistent_keepalive_interval=25\njc=4\n",
            "0".repeat(64)
        );
        let c = parse("wg1", &txt).unwrap();
        assert_eq!(c.ifaddrs.len(), 2);
        assert_eq!(c.ifaddrs[1].bits, 128);
        assert_eq!(
            c.dns,
            vec!["10.2.0.1".to_string(), "dns.example".to_string()]
        );
        assert_eq!(c.mtu, crate::MAXMTU);
        let p = &c.peers[0];
        assert_eq!(
            (p.preshared_key, p.keepalive, p.endpoints.len()),
            (None, Some(25), 2)
        );
        assert_eq!(c.allowed.len(), 3, "dns ip + 0.0.0.0/0 + ::/0");
        assert!(
            parse("wg1", "address=10.0.0.1\n").is_err(),
            "no dns, no key"
        );
        assert!(
            parse(
                "wg1",
                &format!("private_key={K}\naddress=10.0.0.1\ndns=1.1.1.1\nmtu=-5\n")
            )
            .is_ok()
        );
    }
}
