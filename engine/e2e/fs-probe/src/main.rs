// Copyright (c) 2026 RethinkReloaded contributors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! fs-probe: a dependency-free CLI pushed to /data/local/tmp and run as the adb shell user, whose traffic is
//! routed through the VPN. Prints one JSON object per command.
//!
//!   fs-probe dns <server:port> <count> [uncached|cached]   UDP A-queries; latency p50/p95/max, failures
//!   fs-probe tcp <host:port> <count>                        TCP connect latency
//!   fs-probe get <host> <port> <path> [seconds]             plain HTTP/1.1 GET; bytes, seconds, Mbit/s

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant, SystemTime};

fn rand64(state: &mut u64) -> u64 {
    // xorshift64*
    *state ^= *state >> 12;
    *state ^= *state << 25;
    *state ^= *state >> 27;
    state.wrapping_mul(0x2545F4914F6CDD1D)
}

fn dns_query(id: u16, name: &str) -> Vec<u8> {
    let mut q = Vec::with_capacity(64);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]); // RD; 1 question
    for label in name.trim_end_matches('.').split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]); // root, A, IN
    q
}

fn stats(mut v: Vec<f64>) -> String {
    if v.is_empty() {
        return "\"p50_ms\":null,\"p95_ms\":null,\"max_ms\":null".into();
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p = |q: f64| v[((v.len() as f64 - 1.0) * q).round() as usize];
    format!(
        "\"p50_ms\":{:.2},\"p95_ms\":{:.2},\"max_ms\":{:.2}",
        p(0.5),
        p(0.95),
        v[v.len() - 1]
    )
}

fn dns(server: &str, count: usize, mode: &str) {
    let addr: SocketAddr = server.parse().expect("server ip:port");
    let sock = UdpSocket::bind(if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut seed = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
        | 1;
    let names = [
        "example.com",
        "wikipedia.org",
        "github.com",
        "cloudflare.com",
        "kernel.org",
    ];
    let (mut lat, mut fails) = (Vec::new(), 0usize);
    let mut buf = [0u8; 1500];
    for i in 0..count {
        let name = if mode == "cached" {
            names[i % names.len()].to_string()
        } else {
            format!("rr{:x}.example.com", rand64(&mut seed)) // unique: never cached anywhere (NXDOMAIN upstream)
        };
        let id = (rand64(&mut seed) & 0xffff) as u16;
        let t = Instant::now();
        if sock.send_to(&dns_query(id, &name), addr).is_err() {
            fails += 1;
            continue;
        }
        loop {
            match sock.recv_from(&mut buf) {
                Ok((n, _)) if n >= 2 && u16::from_be_bytes([buf[0], buf[1]]) == id => {
                    lat.push(t.elapsed().as_secs_f64() * 1e3);
                    break;
                }
                Ok(_) => continue, // stale answer
                Err(_) => {
                    fails += 1;
                    break;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    println!(
        "{{\"cmd\":\"dns\",\"server\":\"{server}\",\"mode\":\"{mode}\",\"count\":{count},\"ok\":{},\"fail\":{fails},{}}}",
        lat.len(),
        stats(lat)
    );
}

fn fail(cmd: &str, what: &str, err: impl std::fmt::Display) {
    println!(
        "{{\"cmd\":\"{cmd}\",\"target\":\"{what}\",\"error\":\"{}\"}}",
        err.to_string().replace('"', "'")
    );
}

fn resolve(target: impl ToSocketAddrs) -> std::io::Result<SocketAddr> {
    target
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| std::io::Error::other("no address"))
}

fn tcp(target: &str, count: usize) {
    let addr = match resolve(target) {
        Ok(a) => a,
        Err(e) => return fail("tcp", target, e),
    };
    let (mut lat, mut fails) = (Vec::new(), 0usize);
    for _ in 0..count {
        let t = Instant::now();
        match TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
            Ok(_) => lat.push(t.elapsed().as_secs_f64() * 1e3),
            Err(_) => fails += 1,
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    println!(
        "{{\"cmd\":\"tcp\",\"target\":\"{target}\",\"count\":{count},\"ok\":{},\"fail\":{fails},{}}}",
        lat.len(),
        stats(lat)
    );
}

fn get(host: &str, port: u16, path: &str, max_secs: u64) {
    let url = format!("http://{host}:{port}{path}");
    let addr = match resolve((host, port)) {
        Ok(a) => a,
        Err(e) => return fail("get", &url, e),
    };
    let t0 = Instant::now();
    let mut s = match TcpStream::connect_timeout(&addr, Duration::from_secs(10)) {
        Ok(s) => s,
        Err(e) => return fail("get", &url, e),
    };
    s.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    let connect_ms = t0.elapsed().as_secs_f64() * 1e3;
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: fs-probe\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut buf = vec![0u8; 256 * 1024];
    let (mut total, mut first_byte) = (0u64, None);
    let start = Instant::now();
    loop {
        match s.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if first_byte.is_none() {
                    first_byte = Some(start.elapsed().as_secs_f64() * 1e3);
                }
                total += n as u64;
                if start.elapsed().as_secs() >= max_secs {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let secs = start.elapsed().as_secs_f64();
    println!(
        "{{\"cmd\":\"get\",\"url\":\"http://{host}:{port}{path}\",\"connect_ms\":{connect_ms:.1},\"ttfb_ms\":{:.1},\"bytes\":{total},\"seconds\":{secs:.2},\"mbit_s\":{:.2}}}",
        first_byte.unwrap_or(-1.0),
        total as f64 * 8.0 / secs / 1e6
    );
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("dns") => dns(
            &a[2],
            a[3].parse().unwrap(),
            a.get(4).map(String::as_str).unwrap_or("uncached"),
        ),
        Some("tcp") => tcp(&a[2], a[3].parse().unwrap()),
        Some("get") => get(
            &a[2],
            a[3].parse().unwrap(),
            &a[4],
            a.get(5).map_or(20, |s| s.parse().unwrap()),
        ),
        _ => {
            eprintln!(
                "usage: fs-probe dns <ip:port> <n> [uncached|cached] | tcp <host:port> <n> | get <host> <port> <path> [secs]"
            );
            std::process::exit(2);
        }
    }
}
