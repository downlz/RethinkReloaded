// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/netstat/netstat.go (FindProcNetEntry)

//! uid of the app owning a flow, from `/proc/net/{tcp,tcp6,udp,udp6}` (firestack `BlockModeFilterProc`, used on
//! Android 9 and older where `ConnectivityManager.getConnectionOwnerUid` is unavailable). The app's socket shows
//! its tunnel-side address as local and the destination as remote; IPv4 sockets may appear IPv4-mapped in the
//! `*6` tables. Unconnected UDP sockets match on the local address alone.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Parses a `/proc/net` hex address (`0100007F:0035`, or 32 hex digits for IPv6), little-endian 32-bit words.
pub fn parse_hex_addr(s: &str) -> Option<SocketAddr> {
    let (ip, port) = s.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let ip = match ip.len() {
        8 => IpAddr::V4(Ipv4Addr::from(
            u32::from_str_radix(ip, 16).ok()?.swap_bytes(),
        )),
        32 => {
            let mut b = [0u8; 16];
            for i in 0..4 {
                let w = u32::from_str_radix(&ip[i * 8..i * 8 + 8], 16)
                    .ok()?
                    .swap_bytes();
                b[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
            }
            IpAddr::V6(Ipv6Addr::from(b)).to_canonical_v4()
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

trait Canon {
    fn to_canonical_v4(self) -> IpAddr;
}
impl Canon for IpAddr {
    fn to_canonical_v4(self) -> IpAddr {
        match self {
            IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(v6)),
            v4 => v4,
        }
    }
}

fn canon(sa: SocketAddr) -> SocketAddr {
    SocketAddr::new(sa.ip().to_canonical_v4(), sa.port())
}

/// Finds the uid in `/proc/net` table text for a socket with local `src` and remote `dst`.
pub fn find_in(table: &str, src: SocketAddr, dst: SocketAddr, udp: bool) -> Option<u32> {
    let (src, dst) = (canon(src), canon(dst));
    let mut unconnected = None;
    for line in table.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 8 {
            continue;
        }
        let (Some(local), Some(remote)) = (parse_hex_addr(f[1]), parse_hex_addr(f[2])) else {
            continue;
        };
        let Ok(uid) = f[7].parse::<u32>() else {
            continue;
        };
        if local != src {
            continue;
        }
        if remote == dst {
            return Some(uid);
        }
        if udp && remote.port() == 0 && remote.ip().is_unspecified() {
            unconnected = Some(uid);
        }
    }
    unconnected
}

/// uid owning a flow (`proto` "tcp" or "udp"), or None.
pub fn find_uid(proto: &str, src: SocketAddr, dst: SocketAddr) -> Option<u32> {
    let udp = proto == "udp";
    let tables: &[&str] = if udp {
        &["/proc/net/udp6", "/proc/net/udp"]
    } else {
        &["/proc/net/tcp6", "/proc/net/tcp"]
    };
    for t in tables {
        if let Ok(text) = std::fs::read_to_string(t)
            && let Some(uid) = find_in(&text, src, dst, udp)
        {
            return Some(uid);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCP: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 016F6F0A:D96A 6801A8C0:0050 01 00000000:00000000 00:00000000 00000000 10123        0 12345 1 0000000000000000 20 4 30 10 -1
   1: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 23456 1 0000000000000000 100 0 0 10 0";
    const TCP6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0000000000000000FFFF0000016F6F0A:D96B 0000000000000000FFFF00006801A8C0:01BB 01 00000000:00000000 00:00000000 00000000 10456        0 34567 1";

    #[test]
    fn parses_and_matches() {
        assert_eq!(
            parse_hex_addr("0100007F:0035"),
            Some("127.0.0.1:53".parse().unwrap())
        );
        assert_eq!(
            parse_hex_addr("016F6F0A:D96A"),
            Some("10.111.111.1:55658".parse().unwrap())
        );
        let src: SocketAddr = "10.111.111.1:55658".parse().unwrap();
        let dst: SocketAddr = "192.168.1.104:80".parse().unwrap();
        assert_eq!(find_in(TCP, src, dst, false), Some(10123));
        assert_eq!(
            find_in(TCP, src, "192.168.1.104:81".parse().unwrap(), false),
            None
        );
        // IPv4-mapped entry in tcp6
        let src6: SocketAddr = "10.111.111.1:55659".parse().unwrap();
        assert_eq!(
            find_in(TCP6, src6, "192.168.1.104:443".parse().unwrap(), false),
            Some(10456)
        );
    }
}
