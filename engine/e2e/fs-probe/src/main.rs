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
//!   fs-probe lookup <server:port> <name>                    one A query; rcode and answer addresses
//!   fs-probe udp <host:port> <message>                      one datagram; the echo and its round trip
//!   fs-probe echo <host:port> <message>                     TCP: send, read the echo back
//!   fs-probe ntp <host:port>                                one SNTP query (UDP); server time and round trip

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

/// Skips a (possibly compressed) name at `i`; returns the index after it.
fn skip_name(b: &[u8], mut i: usize) -> Option<usize> {
    loop {
        let l = *b.get(i)? as usize;
        if l == 0 {
            return Some(i + 1);
        }
        if l & 0xc0 == 0xc0 {
            return Some(i + 2);
        }
        i += 1 + l;
    }
}

fn lookup(server: &str, name: &str) {
    let addr: SocketAddr = server.parse().expect("server ip:port");
    let sock = UdpSocket::bind(if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let t = Instant::now();
    let mut b = [0u8; 1500];
    let n = match sock
        .send_to(&dns_query(0x5151, name), addr)
        .and_then(|_| sock.recv(&mut b))
    {
        Ok(n) => n,
        Err(e) => return fail("lookup", name, e),
    };
    let b = &b[..n];
    let ms = t.elapsed().as_secs_f64() * 1e3;
    let rcode = b.get(3).map(|x| x & 0x0f).unwrap_or(255);
    let an = u16::from_be_bytes([b[6], b[7]]) as usize;
    let mut ips = Vec::new();
    let mut i = skip_name(b, 12).map(|i| i + 4).unwrap_or(n);
    for _ in 0..an {
        let Some(j) = skip_name(b, i) else { break };
        if j + 10 > n {
            break;
        }
        let (typ, len) = (
            u16::from_be_bytes([b[j], b[j + 1]]),
            u16::from_be_bytes([b[j + 8], b[j + 9]]) as usize,
        );
        let rd = &b[j + 10..(j + 10 + len).min(n)];
        if typ == 1 && rd.len() == 4 {
            ips.push(format!("\"{}.{}.{}.{}\"", rd[0], rd[1], rd[2], rd[3]));
        } else {
            ips.push(format!("\"type{typ}\""));
        }
        i = j + 10 + len;
    }
    println!(
        "{{\"cmd\":\"lookup\",\"name\":\"{name}\",\"rcode\":{rcode},\"ms\":{ms:.2},\"answers\":[{}]}}",
        ips.join(",")
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

fn udp(target: &str, msg: &str) {
    let to: SocketAddr = target.to_socket_addrs().unwrap().next().unwrap();
    let s = UdpSocket::bind(if to.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let t = Instant::now();
    s.send_to(msg.as_bytes(), to).unwrap();
    let mut b = [0u8; 2048];
    match s.recv_from(&mut b) {
        Ok((n, from)) => println!(
            "{{\"cmd\":\"udp\",\"ok\":{},\"from\":\"{from}\",\"echo\":\"{}\",\"ms\":{:.2}}}",
            &b[..n] == msg.as_bytes(),
            String::from_utf8_lossy(&b[..n]),
            t.elapsed().as_secs_f64() * 1e3
        ),
        Err(e) => println!("{{\"cmd\":\"udp\",\"ok\":false,\"err\":\"{e}\"}}"),
    }
}

fn echo(target: &str, msg: &str) {
    let to: SocketAddr = target.to_socket_addrs().unwrap().next().unwrap();
    let t = Instant::now();
    let r = TcpStream::connect_timeout(&to, Duration::from_secs(10)).and_then(|mut c| {
        c.set_read_timeout(Some(Duration::from_secs(10)))?;
        c.write_all(msg.as_bytes())?;
        let mut b = vec![0u8; msg.len()];
        c.read_exact(&mut b)?;
        Ok(b)
    });
    match r {
        Ok(b) => println!(
            "{{\"cmd\":\"echo\",\"ok\":{},\"echo\":\"{}\",\"ms\":{:.2}}}",
            b == msg.as_bytes(),
            String::from_utf8_lossy(&b),
            t.elapsed().as_secs_f64() * 1e3
        ),
        Err(e) => println!("{{\"cmd\":\"echo\",\"ok\":false,\"err\":\"{e}\"}}"),
    }
}

fn ntp(target: &str) {
    let to: SocketAddr = target.to_socket_addrs().unwrap().next().unwrap();
    let s = UdpSocket::bind(if to.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut q = [0u8; 48];
    q[0] = 0x1b; // LI 0, version 3, client
    let t = Instant::now();
    s.send_to(&q, to).unwrap();
    let mut b = [0u8; 512];
    match s.recv_from(&mut b) {
        Ok((n, from)) if n >= 48 => {
            let secs = u32::from_be_bytes([b[40], b[41], b[42], b[43]]) as u64;
            println!(
                "{{\"cmd\":\"ntp\",\"ok\":true,\"from\":\"{from}\",\"unix\":{},\"ms\":{:.2}}}",
                secs.saturating_sub(2_208_988_800),
                t.elapsed().as_secs_f64() * 1e3
            )
        }
        Ok((n, _)) => println!("{{\"cmd\":\"ntp\",\"ok\":false,\"err\":\"short reply {n}\"}}"),
        Err(e) => println!("{{\"cmd\":\"ntp\",\"ok\":false,\"err\":\"{e}\"}}"),
    }
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
        Some("lookup") => lookup(&a[2], &a[3]),
        Some("udp") => udp(&a[2], &a[3]),
        Some("echo") => echo(&a[2], &a[3]),
        Some("ntp") => ntp(&a[2]),
        Some("get") => get(
            &a[2],
            a[3].parse().unwrap(),
            &a[4],
            a.get(5).map_or(20, |s| s.parse().unwrap()),
        ),
        _ => {
            eprintln!(
                "usage: fs-probe dns <ip:port> <n> [uncached|cached] | tcp <host:port> <n> | lookup <ip:port> <name> | udp <ip:port> <msg> | echo <ip:port> <msg> | ntp <ip:port> | get <host> <port> <path> [secs]"
            );
            std::process::exit(2);
        }
    }
}
