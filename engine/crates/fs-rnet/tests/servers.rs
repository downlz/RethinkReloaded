// Copyright (c) 2026 RethinkReloaded contributors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Local servers end to end, driven by the engine's own SOCKS5 and HTTP proxy clients: TCP and UDP through the
//! SOCKS5 server, CONNECT and plain requests through the HTTP server, credentials, Kotlin's routing (blocks and
//! connection ids) and summaries, bridging to a proxy, and the start/stop lifecycle.

use fs_core::bridge::{AllowAllBridge, BoxFuture, ServerListener, ServerSummary, Tab};
use fs_dialers::Protector;
use fs_proxy::{Proxifier, add_proxy};
use fs_rnet::{END, PXSOCKS5, SOK, SVCHTTP, SVCSOCKS5, Services};
use parking_lot::Mutex;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

/// Routes every connection with cid `c<n>`, blocks destinations on port 9, and records summaries.
#[derive(Default)]
struct Kotlin {
    n: Mutex<u32>,
    routes: Mutex<Vec<(String, String, String)>>,
    done: Mutex<Vec<ServerSummary>>,
}

impl ServerListener for Kotlin {
    fn svc_route(
        &self,
        sid: String,
        pid: String,
        network: String,
        _src: String,
        dst: String,
    ) -> BoxFuture<Tab> {
        let mut n = self.n.lock();
        *n += 1;
        let tab = Tab {
            cid: format!("c{n}"),
            block: dst.ends_with(":9"),
        };
        self.routes
            .lock()
            .push((sid, pid, format!("{network} {dst}")));
        Box::pin(async move { tab })
    }
    fn on_svc_complete(&self, s: ServerSummary) {
        self.done.lock().push(s);
    }
}

impl Kotlin {
    async fn summary(&self, cid: &str) -> ServerSummary {
        for _ in 0..100 {
            if let Some(s) = self.done.lock().iter().find(|s| s.cid == cid) {
                return s.clone();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("no summary for {cid}: {:?}", self.done.lock());
    }
}

fn setup() -> (Arc<Proxifier>, Arc<Services>, Arc<Kotlin>) {
    let b = Arc::new(AllowAllBridge);
    let px = Proxifier::new("46", 1500, Protector::new(b.clone()), b);
    let k = Arc::new(Kotlin::default());
    let svc = Services::new(px.clone(), k.clone());
    (px, svc, k)
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn tcp_echo() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut c, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut b = [0u8; 1024];
                while let Ok(n) = c.read(&mut b).await {
                    if n == 0 || c.write_all(&b[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    a
}

async fn udp_echo() -> SocketAddr {
    let u = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a = u.local_addr().unwrap();
    tokio::spawn(async move {
        let mut b = [0u8; 1500];
        while let Ok((n, from)) = u.recv_from(&mut b).await {
            let _ = u.send_to(&b[..n], from).await;
        }
    });
    a
}

async fn echo_over(mut c: fs_dialers::TcpConn, msg: &[u8]) {
    c.write_all(msg).await.unwrap();
    let mut b = vec![0u8; msg.len()];
    tokio::time::timeout(Duration::from_secs(5), c.read_exact(&mut b))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(b, msg);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socks5_server() {
    let (px, svc, k) = setup();
    let (echo, uecho) = (tcp_echo().await, udp_echo().await);
    let port = free_port();
    let s = svc
        .add_server(SVCSOCKS5, "s1", &format!("socks5://u:p@127.0.0.1:{port}"))
        .unwrap();
    assert_eq!((s.typ(), s.status()), (SVCSOCKS5, SOK));
    s.start().unwrap();
    assert!(s.start().unwrap_err().contains("running"));

    let client = add_proxy(&px, "cli", &format!("socks5://u:p@127.0.0.1:{port}")).unwrap();
    echo_over(
        client.dial_tcp(echo, Duration::from_secs(5)).await.unwrap(),
        b"via the local server",
    )
    .await;
    let smm = k.summary("c1").await;
    assert_eq!(
        (smm.typ.as_str(), smm.sid.as_str(), smm.pid.as_str()),
        (SVCSOCKS5, "s1", "")
    );
    assert_eq!((smm.tx, smm.rx, smm.msg.as_str()), (20, 20, "no error"));

    let u = client.dial_udp(uecho).await.unwrap();
    u.send(b"datagram").await.unwrap();
    let mut b = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), u.recv(&mut b))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&b[..n], b"datagram");
    assert!(
        k.routes
            .lock()
            .iter()
            .any(|r| r.2 == format!("udp {uecho}"))
    );

    // blocked by Kotlin
    let blocked: SocketAddr = "127.0.0.1:9".parse().unwrap();
    assert!(
        client
            .dial_tcp(blocked, Duration::from_secs(5))
            .await
            .is_err()
    );
    assert_eq!(k.summary("c3").await.msg, "svc: blocked", "never dialled");

    let bad = add_proxy(&px, "bad", &format!("socks5://u:nope@127.0.0.1:{port}")).unwrap();
    assert!(bad.dial_tcp(echo, Duration::from_secs(5)).await.is_err());

    // stop closes the listener; refresh brings it back
    s.stop();
    assert_eq!(s.status(), END);
    assert!(client.dial_tcp(echo, Duration::from_secs(2)).await.is_err());
    assert!(s.hop(None).is_err(), "stopped servers do not hop");
    assert_eq!(svc.refresh_servers(), "s1");
    echo_over(
        client.dial_tcp(echo, Duration::from_secs(5)).await.unwrap(),
        b"again",
    )
    .await;
    assert!(svc.remove_server("s1") && svc.get_server("s1").is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_server() {
    let (px, svc, k) = setup();
    let echo = tcp_echo().await;
    let port = free_port();
    let s = svc
        .add_server(SVCHTTP, "h1", &format!("http://u:p@127.0.0.1:{port}"))
        .unwrap();
    s.start().unwrap();

    // CONNECT, answering the 407 challenge
    let client = add_proxy(&px, "cli", &format!("http://u:p@127.0.0.1:{port}")).unwrap();
    echo_over(
        client.dial_tcp(echo, Duration::from_secs(5)).await.unwrap(),
        b"tunnelled",
    )
    .await;
    assert_eq!(k.summary("c1").await.typ, SVCHTTP);
    let anon = add_proxy(&px, "anon", &format!("http://127.0.0.1:{port}")).unwrap();
    assert!(anon.dial_tcp(echo, Duration::from_secs(5)).await.is_err());

    // a plain request is rewritten to origin form and forwarded
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let oa = origin.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut c, _) = origin.accept().await.unwrap();
        let mut b = vec![0u8; 1024];
        let n = c.read(&mut b).await.unwrap();
        let req = String::from_utf8_lossy(&b[..n]).into_owned();
        let ok = req.starts_with("GET /hello?x=1 HTTP/1.1\r\n")
            && req.contains("Connection: close")
            && !req.to_ascii_lowercase().contains("proxy-authorization");
        let body = if ok { "hi" } else { "bad" };
        let _ = c
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await;
    });
    let mut c = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    c.write_all(
        format!("GET http://{oa}/hello?x=1 HTTP/1.1\r\nHost: {oa}\r\nProxy-Authorization: Basic dTpw\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut resp = String::new();
    tokio::time::timeout(Duration::from_secs(5), c.read_to_string(&mut resp))
        .await
        .unwrap()
        .unwrap();
    assert!(
        resp.starts_with("HTTP/1.1 200 OK") && resp.ends_with("hi"),
        "{resp}"
    );

    // Kotlin blocks
    let mut c = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    c.write_all(b"GET http://127.0.0.1:9/ HTTP/1.1\r\nProxy-Authorization: Basic dTpw\r\n\r\n")
        .await
        .unwrap();
    let mut resp = String::new();
    tokio::time::timeout(Duration::from_secs(5), c.read_to_string(&mut resp))
        .await
        .unwrap()
        .unwrap();
    assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");

    // https servers are unimplemented (as firestack)
    let tls = svc
        .add_server(SVCHTTP, "h2", &format!("https://127.0.0.1:{}", free_port()))
        .unwrap();
    assert!(tls.start().is_err());
    assert_eq!(tls.status(), END);
}

/// A server bridged to a proxy dials out through it (here: another local SOCKS5 server, via the engine's client).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bridged_server() {
    let (px, svc, k) = setup();
    let echo = tcp_echo().await;
    let (inner, outer) = (free_port(), free_port());
    svc.add_server(SVCSOCKS5, "far", &format!("socks5://127.0.0.1:{inner}"))
        .unwrap()
        .start()
        .unwrap();
    let up = add_proxy(&px, "up", &format!("socks5://127.0.0.1:{inner}")).unwrap();
    // a namesake proxy bridges on add
    add_proxy(&px, "near", &format!("socks5://127.0.0.1:{inner}")).unwrap();
    let near = svc
        .add_server(SVCSOCKS5, "near", &format!("socks5://127.0.0.1:{outer}"))
        .unwrap();
    assert_eq!(near.typ(), PXSOCKS5);
    svc.bridge("near", "up").unwrap();
    assert_eq!((near.typ(), near.addr()), (PXSOCKS5, up.addr()));
    near.start().unwrap();

    let client = add_proxy(&px, "cli", &format!("socks5://127.0.0.1:{outer}")).unwrap();
    echo_over(
        client.dial_tcp(echo, Duration::from_secs(5)).await.unwrap(),
        b"two servers",
    )
    .await;
    let routes = k.routes.lock().clone();
    assert!(
        routes.iter().any(|r| r.0 == "near" && r.1 == "up"),
        "{routes:?}"
    );
    assert!(
        routes.iter().any(|r| r.0 == "far" && r.1.is_empty()),
        "{routes:?}"
    );

    svc.bridge("near", "").unwrap();
    assert_eq!(
        (near.typ(), near.addr()),
        (SVCSOCKS5, format!("127.0.0.1:{outer}"))
    );
    assert!(svc.bridge("near", "nope").is_err());
    assert!(svc.add_server("ftp", "x", "ftp://1.2.3.4:21").is_err());
    svc.remove_all();
    assert!(svc.get_server("far").is_err());
}
