// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/rnet/http.go

//! HTTP proxy server: CONNECT tunnels, and plain `http://` requests forwarded one per connection (the request is
//! rewritten to origin form with `Connection: close`, and the response streamed back as is).

use crate::{Moved, Server, relay};
use base64::Engine;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const MAX_HEAD: usize = 16 * 1024;

struct Head {
    method: String,
    target: String,
    version: String,
    headers: Vec<(String, String)>,
}

impl Head {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Reads up to the end of the request head; returns it and whatever followed it.
async fn read_head(c: &mut TcpStream) -> Option<(Head, Vec<u8>)> {
    let mut buf = Vec::with_capacity(1024);
    let mut b = [0u8; 2048];
    let end = loop {
        let n = c.read(&mut b).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&b[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        if buf.len() > MAX_HEAD {
            return None;
        }
    };
    let text = String::from_utf8_lossy(&buf[..end]).into_owned();
    let mut lines = text.split("\r\n");
    let mut first = lines.next()?.split_whitespace();
    let (method, target, version) = (
        first.next()?,
        first.next()?,
        first.next().unwrap_or("HTTP/1.1"),
    );
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    Some((
        Head {
            method: method.to_string(),
            target: target.to_string(),
            version: version.to_string(),
            headers,
        },
        buf[end..].to_vec(),
    ))
}

async fn respond(c: &mut TcpStream, status: &str, body: &str) {
    let r = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = c.write_all(r.as_bytes()).await;
}

fn authorized(s: &Server, h: &Head) -> bool {
    if s.user.is_empty() && s.pass.is_empty() {
        return true;
    }
    let want = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", s.user, s.pass));
    ["Proxy-Authorization", "Authorization"].iter().any(|k| {
        h.header(k)
            .and_then(|v| v.split_once(' '))
            .is_some_and(|(scheme, cred)| {
                scheme.eq_ignore_ascii_case("basic") && cred.trim() == want
            })
    })
}

pub(crate) async fn serve(s: &Arc<Server>, mut c: TcpStream, from: SocketAddr) {
    let Some((h, rest)) = read_head(&mut c).await else {
        return;
    };
    if !authorized(s, &h) {
        if h.method.eq_ignore_ascii_case("CONNECT") {
            let _ = c
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\nContent-Length: 0\r\n\r\n",
                )
                .await;
        } else {
            respond(&mut c, "401 Unauthorized", "Unauthorized").await;
        }
        return;
    }
    if h.method.eq_ignore_ascii_case("CONNECT") {
        let dst = if fs_proxy::upstream::split_host_port(&h.target).1.is_some() {
            h.target.clone()
        } else {
            format!("{}:80", h.target)
        };
        tunnel(s, c, from, &dst, &rest).await;
    } else {
        forward(s, c, from, h, rest).await;
    }
}

async fn tunnel(s: &Arc<Server>, mut c: TcpStream, from: SocketAddr, dst: &str, rest: &[u8]) {
    let (tab, smm) = s.route("tcp", from, dst).await;
    if tab.block {
        respond(&mut c, "403 Forbidden", "Forbidden").await;
        s.summarize(smm.done(Moved::default(), Some(crate::ERR_BLOCKED.into())));
        return;
    }
    let e = match s.dial_tcp(dst).await {
        Ok(e) => e,
        Err(err) => {
            let _ = c.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
            s.summarize(smm.done(Moved::default(), Some(err.to_string())));
            return;
        }
    };
    if let Err(err) = c
        .write_all(b"HTTP/1.0 200 Connection established\r\n\r\n")
        .await
    {
        s.summarize(smm.done(Moved::default(), Some(err.to_string())));
        return;
    }
    let (moved, err) = relay(c, e, rest).await;
    s.summarize(smm.done(moved, err));
}

/// `http://host[:port]/path` → (`host:port`, `/path`)
fn split_absolute(target: &str) -> Option<(String, String)> {
    let rest = target.strip_prefix("http://").or_else(|| {
        target
            .get(..7)
            .filter(|p| p.eq_ignore_ascii_case("http://"))
            .map(|_| &target[7..])
    })?;
    let (auth, path) = match rest.find(['/', '?']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let auth = auth.rsplit_once('@').map_or(auth, |(_, h)| h);
    if auth.is_empty() {
        return None;
    }
    let hostport = if fs_proxy::upstream::split_host_port(auth).1.is_some() {
        auth.to_string()
    } else {
        format!("{auth}:80")
    };
    let path = if path.starts_with('?') {
        format!("/{path}")
    } else {
        path.to_string()
    };
    Some((hostport, path))
}

async fn forward(s: &Arc<Server>, mut c: TcpStream, from: SocketAddr, h: Head, rest: Vec<u8>) {
    let Some((dst, path)) = split_absolute(&h.target) else {
        respond(
            &mut c,
            "500 Internal Server Error",
            "This is a proxy server. Does not respond to non-proxy requests.",
        )
        .await;
        return;
    };
    let host = h
        .header("Host")
        .map(str::to_string)
        .unwrap_or_else(|| dst.clone());
    let (tab, smm) = s.route("tcp", from, &host).await;
    if tab.block {
        respond(&mut c, "403 Forbidden", "Forbidden").await;
        s.summarize(smm.done(Moved::default(), Some(crate::ERR_BLOCKED.into())));
        return;
    }
    let e = match s.dial_tcp(&dst).await {
        Ok(e) => e,
        Err(err) => {
            respond(&mut c, "502 Bad Gateway", &err.to_string()).await;
            s.summarize(smm.done(Moved::default(), Some(err.to_string())));
            return;
        }
    };
    let mut req = format!("{} {path} {}\r\n", h.method, h.version);
    let mut has_host = false;
    for (k, v) in &h.headers {
        let l = k.to_ascii_lowercase();
        if l.starts_with("proxy-") || l == "connection" || l == "keep-alive" {
            continue;
        }
        has_host |= l == "host";
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if !has_host {
        req.push_str(&format!("Host: {host}\r\n"));
    }
    req.push_str("Connection: close\r\n\r\n");
    let mut pre = req.into_bytes();
    pre.extend_from_slice(&rest);
    let (moved, err) = relay(c, e, &pre).await;
    s.summarize(smm.done(moved, err));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_targets() {
        assert_eq!(
            split_absolute("http://example.com/a?b").unwrap(),
            ("example.com:80".into(), "/a?b".into())
        );
        assert_eq!(
            split_absolute("HTTP://u@[::1]:8080?q").unwrap(),
            ("[::1]:8080".into(), "/?q".into())
        );
        assert_eq!(
            split_absolute("http://h").unwrap(),
            ("h:80".into(), "/".into())
        );
        assert!(split_absolute("/origin-form").is_none());
        assert!(
            split_absolute("https://h/").is_none(),
            "tls origins go through CONNECT"
        );
    }
}
