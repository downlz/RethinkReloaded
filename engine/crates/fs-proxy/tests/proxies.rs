// Copyright (c) 2026 RethinkReloaded contributors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! SOCKS5 and HTTP proxies end to end, against minimal servers on loopback: TCP echo through CONNECT (with
//! credentials), UDP echo through SOCKS5 UDP ASSOCIATE (connected and unconnected), refused credentials.

use fs_core::bridge::AllowAllBridge;
use fs_dialers::Protector;
use fs_proxy::{Proxifier, add_proxy};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

async fn tcp_echo() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut b = [0u8; 1024];
                while let Ok(n) = s.read(&mut b).await {
                    if n == 0 || s.write_all(&b[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    a
}

async fn udp_echo() -> SocketAddr {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a = s.local_addr().unwrap();
    tokio::spawn(async move {
        let mut b = [0u8; 1500];
        while let Ok((n, p)) = s.recv_from(&mut b).await {
            let _ = s.send_to(&b[..n], p).await;
        }
    });
    a
}

fn addr_bytes(b: &[u8]) -> (SocketAddr, usize) {
    match b[0] {
        1 => (
            SocketAddr::new(
                [b[1], b[2], b[3], b[4]].into(),
                u16::from_be_bytes([b[5], b[6]]),
            ),
            7,
        ),
        _ => panic!("test server: ipv4 only"),
    }
}

/// A minimal SOCKS5 server (RFC 1928/1929): user `u`, password `p`; CONNECT and UDP ASSOCIATE.
async fn socks5_server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut c, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut h = [0u8; 2];
                c.read_exact(&mut h).await.unwrap();
                let mut m = vec![0u8; h[1] as usize];
                c.read_exact(&mut m).await.unwrap();
                assert!(m.contains(&2), "client offers username/password");
                c.write_all(&[5, 2]).await.unwrap();
                let mut v = [0u8; 2];
                c.read_exact(&mut v).await.unwrap();
                let mut u = vec![0u8; v[1] as usize];
                c.read_exact(&mut u).await.unwrap();
                let mut pl = [0u8; 1];
                c.read_exact(&mut pl).await.unwrap();
                let mut p = vec![0u8; pl[0] as usize];
                c.read_exact(&mut p).await.unwrap();
                let ok = u == b"u" && p == b"p";
                c.write_all(&[1, if ok { 0 } else { 1 }]).await.unwrap();
                if !ok {
                    return;
                }
                let mut r = [0u8; 4];
                c.read_exact(&mut r).await.unwrap();
                let mut rest = [0u8; 6];
                c.read_exact(&mut rest).await.unwrap();
                let mut ab = vec![1];
                ab.extend(rest);
                let (dst, _) = addr_bytes(&ab);
                match r[1] {
                    1 => {
                        let mut up = TcpStream::connect(dst).await.unwrap();
                        c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
                        let _ = tokio::io::copy_bidirectional(&mut c, &mut up).await;
                    }
                    3 => {
                        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                        let port = relay.local_addr().unwrap().port().to_be_bytes();
                        // 0.0.0.0 as relay address: "the server's own address"
                        c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, port[0], port[1]])
                            .await
                            .unwrap();
                        let mut client: Option<SocketAddr> = None;
                        let mut b = [0u8; 2048];
                        let mut one = [0u8; 1];
                        loop {
                            tokio::select! {
                                r = relay.recv_from(&mut b) => {
                                    let (n, from) = r.unwrap();
                                    if from.port() != 0 && b[0] == 0 && b[1] == 0 && (client.is_none() || client == Some(from)) {
                                        client = Some(from);
                                        let (dst, used) = addr_bytes(&b[3..n]);
                                        relay.send_to(&b[3 + used..n], dst).await.unwrap();
                                    } else if let Some(cl) = client {
                                        let mut m = vec![0, 0, 0];
                                        if let SocketAddr::V4(v4) = from {
                                            m.push(1);
                                            m.extend(v4.ip().octets());
                                            m.extend(v4.port().to_be_bytes());
                                        }
                                        m.extend(&b[..n]);
                                        relay.send_to(&m, cl).await.unwrap();
                                    }
                                }
                                r = c.read(&mut one) => if matches!(r, Ok(0) | Err(_)) { break },
                            }
                        }
                    }
                    _ => {}
                }
            });
        }
    });
    a
}

/// A minimal HTTP CONNECT proxy: 407 until `Proxy-Authorization: Basic dTpw` (u:p) is sent.
async fn http_proxy() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut c, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut first = true;
                loop {
                    let mut head = Vec::new();
                    let mut b = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        if c.read(&mut b).await.unwrap_or(0) == 0 {
                            return;
                        }
                        head.push(b[0]);
                    }
                    let h = String::from_utf8(head).unwrap();
                    let authed = h.contains("Proxy-Authorization: Basic dTpw");
                    if first || !authed {
                        first = false;
                        let body = "auth";
                        let r = format!(
                            "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"x\"\r\nContent-Length: {}\r\n\r\n{body}",
                            body.len()
                        );
                        c.write_all(r.as_bytes()).await.unwrap();
                        continue;
                    }
                    let target = h.split_whitespace().nth(1).unwrap().to_string();
                    let mut up = TcpStream::connect(target).await.unwrap();
                    c.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                        .await
                        .unwrap();
                    let _ = tokio::io::copy_bidirectional(&mut c, &mut up).await;
                    return;
                }
            });
        }
    });
    a
}

fn px() -> Arc<Proxifier> {
    let b = Arc::new(AllowAllBridge);
    Proxifier::new("46", 1500, Protector::new(b.clone()), b)
}

async fn echo_over(mut c: fs_dialers::TcpConn) {
    c.write_all(b"hello proxy").await.unwrap();
    let mut b = [0u8; 11];
    tokio::time::timeout(Duration::from_secs(5), c.read_exact(&mut b))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&b, b"hello proxy");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn socks5_tcp_and_udp() {
    let px = px();
    let (echo, uecho, srv) = (tcp_echo().await, udp_echo().await, socks5_server().await);
    let p = add_proxy(&px, "s5", &format!("socks5://u:p@{srv}")).unwrap();
    assert_eq!((p.typ(), p.addr()), ("socks5", srv.to_string()));
    assert!(
        p.is_self("127.0.0.1"),
        "flows to the proxy's own address would loop"
    );
    echo_over(p.dial_tcp(echo, Duration::from_secs(5)).await.unwrap()).await;
    assert_eq!(p.status(), fs_proxy::TOK);

    let u = p.dial_udp(uecho).await.unwrap();
    u.send(b"ping").await.unwrap();
    let mut b = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(5), u.recv(&mut b))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&b[..n], b"ping");

    let a = p.announce_udp(false).await.unwrap();
    a.send_to(b"pong", uecho).await.unwrap();
    let (n, from) = tokio::time::timeout(Duration::from_secs(5), a.recv_from(&mut b))
        .await
        .unwrap()
        .unwrap();
    assert_eq!((&b[..n], from), (&b"pong"[..], uecho));

    // wrong password
    let bad = add_proxy(&px, "s5bad", &format!("socks5://u:nope@{srv}")).unwrap();
    assert!(bad.dial_tcp(echo, Duration::from_secs(5)).await.is_err());
    assert_eq!(bad.status(), fs_proxy::TKO);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http_connect_with_challenge() {
    let px = px();
    let (echo, srv) = (tcp_echo().await, http_proxy().await);
    let p = add_proxy(&px, "h1", &format!("http://u:p@{srv}")).unwrap();
    assert_eq!(p.typ(), "http1");
    echo_over(p.dial_tcp(echo, Duration::from_secs(5)).await.unwrap()).await;
    assert!(p.dial_udp(echo).await.is_err(), "http proxies carry no udp");
    let anon = add_proxy(&px, "h1anon", &format!("http://{srv}")).unwrap();
    assert!(anon.dial_tcp(echo, Duration::from_secs(5)).await.is_err());
    assert!(add_proxy(&px, "x", "ftp://1.2.3.4:21").is_err());
}

/// firestack `hop` rules at the proxifier: no self, no triple hops, no unknown proxies, dry runs change nothing,
/// a replaced via keeps its origins, and WireGuard hops only through proxies that announce UDP and know their MTU.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hops() {
    let px = px();
    let (echo, srv) = (tcp_echo().await, socks5_server().await);
    let a = add_proxy(&px, "s5a", &format!("socks5://u:p@{srv}")).unwrap();
    let b = add_proxy(&px, "s5b", &format!("socks5://u:p@{srv}")).unwrap();
    add_proxy(&px, "dead", "socks5://127.0.0.1:1").unwrap();

    assert_eq!(px.test_hop("s5a", "s5b"), "");
    assert!(b.via().is_none(), "dry run");
    px.hop("dead", "s5b", false).unwrap();
    assert!(
        b.dial_tcp(echo, Duration::from_secs(5)).await.is_err(),
        "dials go through the hop"
    );
    px.hop("s5a", "s5b", false).unwrap();
    assert_eq!(px.hop_origins("s5a"), ["s5b"]);
    assert!(
        px.hop_origins("dead").is_empty(),
        "re-hopping unmaps the old via"
    );
    echo_over(b.dial_tcp(echo, Duration::from_secs(5)).await.unwrap()).await;
    assert_eq!(b.via().unwrap().handle(), a.handle());

    assert!(px.hop("s5b", "s5b", false).unwrap_err().contains("looping"));
    assert!(
        px.hop("s5b", "s5a", false).unwrap_err().contains("hopping"),
        "no triple hops"
    );
    assert!(px.hop("nope", "s5b", false).is_err());
    assert!(px.hop("s5a", "", false).is_err());

    // a replaced via carries its origins
    let a2 = add_proxy(&px, "s5a", &format!("socks5://u:p@{srv}")).unwrap();
    assert_ne!(a2.handle(), a.handle());
    assert_eq!(b.via().unwrap().handle(), a2.handle());
    echo_over(b.dial_tcp(echo, Duration::from_secs(5)).await.unwrap()).await;

    px.hop("", "s5b", false).unwrap();
    assert!(b.via().is_none() && px.hop_origins("s5a").is_empty());

    // WireGuard: the hop must announce UDP (http1 cannot) and have an MTU (socks5 does not: errNoMtu)
    let wg = format!(
        "private_key={}\naddress=10.9.0.2/32\ndns=1.1.1.1\nmtu=1420\npublic_key={}\nendpoint=127.0.0.1:9\nallowed_ip=0.0.0.0/0\n",
        "01".repeat(32),
        "02".repeat(32)
    );
    add_proxy(&px, "wgx", &wg).unwrap();
    add_proxy(&px, "h1", &format!("http://{srv}")).unwrap();
    assert!(px.test_hop("h1", "wgx").contains("announce"));
    assert!(px.test_hop("s5a", "wgx").contains("mtu"));

    px.remove_proxy("s5a");
    assert!(px.hop("s5a", "s5b", false).is_err());
}
