// Copyright (c) 2026 RethinkReloaded contributors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! wg-peer: the far end of the Phase 2 e2e run, on the host.
//!
//!   wg-peer <out-dir> [endpoint-host]    (endpoint-host: how the device reaches this host; emulator: 10.0.2.2)
//!
//! * outer WireGuard peer on udp/51820: tunnel 10.9.0.1 (client 10.9.0.2); tcp+udp echo on 7, http on 80
//! * inner WireGuard peer on 10.9.0.1:51821 *inside* the outer tunnel: tunnel 10.8.0.1 (client 10.8.0.2); echo on
//!   7, http on 80. It is only reachable by hopping through the outer tunnel.
//! * SOCKS5 server (fs-rnet, with UDP associate) on 127.0.0.1:10800, and a udp echo on 0.0.0.0:7007
//!
//! Client configs (wg-quick format, for the app's import) are written to <out-dir>/wg-outer.conf and wg-inner.conf.
//! Keys are fixed test keys: never use them for anything real.

use base64::Engine;
use fs_core::bridge::{AllowAllBridge, BoxFuture, ServerListener, ServerSummary, Tab};
use fs_dialers::{Protector, UdpConn};
use fs_proxy::wg::peer::{far_end, pubkey};
use fs_proxy::wg::stack::Stack;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

fn log(m: &str) {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    println!("[{t}] {m}");
}

/// A one-line HTTP responder inside a tunnel.
fn http(stack: Arc<Stack>, name: &'static str) {
    tokio::spawn(async move {
        loop {
            let Ok(mut c) = stack.accept(80).await else {
                return;
            };
            tokio::spawn(async move {
                let mut b = vec![0u8; 4096];
                let n = c.read(&mut b).await.unwrap_or(0);
                let line = String::from_utf8_lossy(&b[..n])
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_string();
                log(&format!("{name}: http {line:?}"));
                let body = format!("hello from the {name} peer\n");
                let _ = c
                    .write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes())
                    .await;
                let _ = c.shutdown().await;
            });
        }
    });
}

/// The inner peer's socket, logging each datagram (the multi-hop path is otherwise invisible).
struct Logged51821(fs_proxy::wg::stack::UdpSock);
impl fs_dialers::Datagram for Logged51821 {
    fn send<'a>(&'a self, b: &'a [u8]) -> fs_dialers::Fut<'a, std::io::Result<usize>> {
        self.0.send(b)
    }
    fn recv<'a>(&'a self, b: &'a mut [u8]) -> fs_dialers::Fut<'a, std::io::Result<usize>> {
        self.0.recv(b)
    }
    fn send_to<'a>(
        &'a self,
        b: &'a [u8],
        to: std::net::SocketAddr,
    ) -> fs_dialers::Fut<'a, std::io::Result<usize>> {
        Box::pin(async move {
            let r = self.0.send_to(b, to).await;
            log(&format!(
                "inner: sent {} bytes (type {}) to {to}: {:?}",
                b.len(),
                b.first().copied().unwrap_or(0),
                r.as_ref().map(|_| ())
            ));
            r
        })
    }
    fn recv_from<'a>(
        &'a self,
        b: &'a mut [u8],
    ) -> fs_dialers::Fut<'a, std::io::Result<(usize, std::net::SocketAddr)>> {
        Box::pin(async move {
            let r = self.0.recv_from(b).await;
            if let Ok((n, from)) = &r {
                log(&format!("inner: got {n} bytes (type {}) from {from}", b[0]));
            }
            r
        })
    }
    fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.0.local_addr()
    }
}

struct Logged;
impl ServerListener for Logged {
    fn svc_route(
        &self,
        sid: String,
        pid: String,
        network: String,
        src: String,
        dst: String,
    ) -> BoxFuture<Tab> {
        log(&format!(
            "socks5: route sid={sid} pid={pid:?} {network} {src} -> {dst}"
        ));
        Box::pin(async {
            Tab {
                cid: "e2e".into(),
                block: false,
            }
        })
    }
    fn on_svc_complete(&self, s: ServerSummary) {
        log(&format!(
            "socks5: done {} tx={} rx={} {}ms msg={:?}",
            s.typ, s.tx, s.rx, s.duration, s.msg
        ));
    }
}

fn client_conf(ck: [u8; 32], spub: [u8; 32], addr: &str, allowed: &str, endpoint: &str) -> String {
    format!(
        "[Interface]\nPrivateKey = {}\nAddress = {addr}\nDNS = 10.9.0.1\nMTU = 1420\n\n[Peer]\nPublicKey = {}\nAllowedIPs = {allowed}\nEndpoint = {endpoint}\nPersistentKeepalive = 25\n",
        B64.encode(ck),
        B64.encode(spub)
    )
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let a: Vec<String> = std::env::args().collect();
    let out = std::path::PathBuf::from(a.get(1).expect("usage: wg-peer <out-dir> [endpoint-host]"));
    let host = a.get(2).map_or("10.0.2.2", String::as_str);
    // fixed test keys (clamped by x25519)
    let (c1, s1, c0, s0) = ([0x11u8; 32], [0x22u8; 32], [0x33u8; 32], [0x44u8; 32]);

    let sock = tokio::net::UdpSocket::bind("0.0.0.0:51820")
        .await
        .expect("udp/51820");
    let (_outer, outer) = far_end(s1, pubkey(c1), "10.9.0.2/32", "10.9.0.1/32", sock.into()).await;
    http(outer.clone(), "outer");
    let inner_sock = UdpConn::Dyn(Arc::new(Logged51821(
        outer.udp_on(51821).expect("inner bind"),
    )));
    let (_inner, inner) = far_end(s0, pubkey(c0), "10.8.0.2/32", "10.8.0.1/32", inner_sock).await;
    http(inner.clone(), "inner");

    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(
        out.join("wg-outer.conf"),
        client_conf(
            c1,
            pubkey(s1),
            "10.9.0.2/32",
            "10.9.0.0/24",
            &format!("{host}:51820"),
        ),
    )
    .unwrap();
    std::fs::write(
        out.join("wg-inner.conf"),
        client_conf(
            c0,
            pubkey(s0),
            "10.8.0.2/32",
            "10.8.0.0/24",
            "10.9.0.1:51821",
        ),
    )
    .unwrap();

    let b = Arc::new(AllowAllBridge);
    let px = fs_proxy::Proxifier::new("46", 1500, Protector::new(b.clone()), b);
    let svc = fs_rnet::Services::new(px, Arc::new(Logged));
    svc.add_server(fs_rnet::SVCSOCKS5, "e2e-socks5", "socks5://127.0.0.1:10800")
        .unwrap()
        .start()
        .unwrap();

    let echo = tokio::net::UdpSocket::bind("0.0.0.0:7007")
        .await
        .expect("udp/7007");
    tokio::spawn(async move {
        let mut b = [0u8; 2048];
        while let Ok((n, from)) = echo.recv_from(&mut b).await {
            log(&format!("udp echo: {n} bytes from {from}"));
            let _ = echo.send_to(&b[..n], from).await;
        }
    });

    log(&format!(
        "ready: wg outer udp/51820 (endpoint {host}:51820), inner 10.9.0.1:51821, socks5 127.0.0.1:10800, udp echo :7007; configs in {}",
        out.display()
    ));
    tokio::signal::ctrl_c().await.ok();
}
