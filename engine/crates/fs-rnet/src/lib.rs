// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/rnet/servers.go
// Derived-From: celzero/firestack@d3d530ea3e:intra/rnet/listener.go

//! Local proxy servers (`backend.Services`): SOCKS5 and HTTP servers that apps or other devices can point at.
//! Each connection is routed by Kotlin (`svcRoute`: block, connection id) and dialled out protected as the
//! server, or through a proxy the server is bridged to; each relayed connection ends in a `ServerSummary`.
//!
//! Deviations from firestack (which ships these unused by the app, and with bugs that keep them from serving):
//! servers listen on `start()` (firestack's SOCKS5 refuses `start` while not stopped, its `candial` refuses every
//! connection while running, and its HTTP server refuses `start` after `stop`); `addServer` does not fail when
//! there is no namesake proxy to bridge to; proxied SOCKS5 connects work (firestack requires a raw TCP conn); HTTP
//! credentials are read from `Proxy-Authorization` (and `Authorization`, as firestack); `svcRoute` gets the client's
//! address as `src` for CONNECTs too. HTTPS (TLS) servers are unimplemented, as in firestack.

mod http;
mod socks;

use fs_core::bridge::{ServerListener, ServerSummary, Tab};
use fs_dialers::{Protector, TcpConn, UdpConn};
use fs_proxy::upstream::HostResolver;
use fs_proxy::{Proxifier, SharedProxy};
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};

pub const SVCSOCKS5: &str = "svcsocks5";
pub const SVCHTTP: &str = "svchttp";
pub const PXSOCKS5: &str = "pxsocks5";
pub const PXHTTP: &str = "pxhttp";

pub const SUP: i32 = 0;
pub const SOK: i32 = 1;
pub const SKO: i32 = -1;
/// stopped (`backend.SOP`)
pub const END: i32 = -2;

const ERR_NO_SERVER: &str = "svc: no such server";
const ERR_SVC_RUNNING: &str = "svc: service is running";
const ERR_SERVER_END: &str = "svc: server stopped";
const ERR_PROXY_END: &str = "svc: proxy stopped";
const ERR_PROXY_PAUSED: &str = "svc: proxy paused";
const ERR_BLOCKED: &str = "svc: blocked";
const NO_ERROR: &str = "no error";

const UDP_IDLE: Duration = Duration::from_secs(5 * 60);
const TCP_IDLE: Duration = Duration::from_secs(2 * 60 * 60 + 40 * 60);
const DIAL_TIMEOUT: Duration = Duration::from_secs(20);
/// summaries wait a bit, so Kotlin has persisted the connection (cid) the summary is about
const SUMMARY_DELAY: Duration = Duration::from_millis(50);
const SUMMARIES: usize = 256;

pub type Result<T> = std::result::Result<T, String>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Socks5,
    Http,
}

/// One local server (`backend.Server`).
pub struct Server {
    id: String,
    kind: Kind,
    /// listen address, `host:port` (an empty host listens on all interfaces)
    host: String,
    user: String,
    pass: String,
    tls: bool,
    protector: Protector,
    resolver: Option<HostResolver>,
    listener: Arc<dyn ServerListener>,
    queue: mpsc::Sender<ServerSummary>,
    rt: tokio::runtime::Handle,
    px: Mutex<Option<SharedProxy>>,
    status: AtomicI32,
    /// signals the accept loop and every relay of the current run to end
    run: Mutex<Option<watch::Sender<bool>>>,
}

/// Bytes moved for a summary.
#[derive(Default)]
struct Moved {
    rx: i64,
    tx: i64,
}

/// A summary under construction (firestack `serverSummary` / `done`).
struct Summary {
    s: ServerSummary,
    start: Instant,
}

impl Summary {
    fn done(mut self, moved: Moved, err: Option<String>) -> ServerSummary {
        self.s.rx = moved.rx;
        self.s.tx = moved.tx;
        self.s.duration = self.start.elapsed().as_millis() as i64;
        self.s.msg = err.unwrap_or_else(|| NO_ERROR.into());
        self.s
    }
}

impl Server {
    pub fn id(&self) -> &str {
        &self.id
    }

    /// `svcsocks5` / `svchttp`, or `pxsocks5` / `pxhttp` when bridged to a proxy
    pub fn typ(&self) -> &'static str {
        match (self.kind, self.px.lock().is_some()) {
            (Kind::Socks5, false) => SVCSOCKS5,
            (Kind::Socks5, true) => PXSOCKS5,
            (Kind::Http, false) => SVCHTTP,
            (Kind::Http, true) => PXHTTP,
        }
    }

    /// the bridged proxy's address, else the listen address
    pub fn addr(&self) -> String {
        match self.px.lock().as_ref() {
            Some(p) => p.addr(),
            None => self.host.clone(),
        }
    }

    pub fn status(&self) -> i32 {
        self.status.load(Ordering::Relaxed)
    }

    fn pid(&self) -> String {
        self.px
            .lock()
            .as_ref()
            .map(|p| p.id().to_string())
            .unwrap_or_default()
    }

    fn running(&self) -> bool {
        self.run
            .lock()
            .as_ref()
            .is_some_and(|t| !t.is_closed() && !*t.borrow())
    }

    /// Listens and serves until `stop`.
    pub fn start(self: &Arc<Self>) -> Result<()> {
        if self.running() {
            return Err(ERR_SVC_RUNNING.into());
        }
        if self.tls {
            self.status.store(END, Ordering::Relaxed);
            return Err(format!(
                "svchttp: {} cannot start; tls is unimplemented",
                self.id
            ));
        }
        let addr = listen_addr(&self.host)?;
        let l = std::net::TcpListener::bind(addr)
            .map_err(|e| format!("svc: {}: listen {addr}: {e}", self.id))?;
        l.set_nonblocking(true).map_err(|e| e.to_string())?;
        let (tx, rx) = watch::channel(false);
        *self.run.lock() = Some(tx);
        self.status.store(SOK, Ordering::Relaxed);
        let me = self.clone();
        self.rt.spawn(async move {
            let Ok(l) = tokio::net::TcpListener::from_std(l) else {
                me.status.store(END, Ordering::Relaxed);
                return;
            };
            let mut stop = rx.clone();
            loop {
                tokio::select! {
                    _ = stop.changed() => break,
                    r = l.accept() => match r {
                        Ok((c, from)) => {
                            let (me, stop) = (me.clone(), rx.clone());
                            tokio::spawn(async move {
                                tokio::select! {
                                    _ = until_stopped(stop) => {}
                                    _ = me.serve(c, from) => {}
                                }
                            });
                        }
                        Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
                    },
                }
            }
            me.status.store(END, Ordering::Relaxed);
        });
        Ok(())
    }

    /// Closes the listener and every connection it accepted.
    pub fn stop(&self) {
        if let Some(t) = self.run.lock().take() {
            let _ = t.send(true);
        }
        self.status.store(END, Ordering::Relaxed);
    }

    /// Stops and starts again.
    pub fn refresh(self: &Arc<Self>) -> Result<()> {
        self.stop();
        self.start()
    }

    /// Bridges the server to `p` (outbound connections go through it), or unbridges it.
    pub fn hop(&self, p: Option<SharedProxy>) -> Result<()> {
        if self.status() == END {
            return Err(ERR_SERVER_END.into());
        }
        *self.px.lock() = p;
        Ok(())
    }

    async fn serve(self: Arc<Self>, c: tokio::net::TcpStream, from: SocketAddr) {
        let _ = c.set_nodelay(true);
        match self.kind {
            Kind::Socks5 => socks::serve(&self, c, from).await,
            Kind::Http => http::serve(&self, c, from).await,
        }
    }

    fn candial(&self) -> io::Result<()> {
        let e = |m: &str| Err(io::Error::other(m.to_string()));
        if self.status() == END {
            return e(ERR_SERVER_END);
        }
        if let Some(p) = self.px.lock().as_ref() {
            match p.status() {
                fs_proxy::END => return e(ERR_PROXY_END),
                fs_proxy::TPU => return e(ERR_PROXY_PAUSED),
                _ => {}
            }
        }
        Ok(())
    }

    /// Asks Kotlin for the route of `network` `src` → `dst` (firestack `route`).
    async fn route(&self, network: &str, src: SocketAddr, dst: &str) -> (Tab, Summary) {
        let pid = self.pid();
        let tab = self
            .listener
            .svc_route(
                self.id.clone(),
                pid.clone(),
                network.into(),
                src.to_string(),
                dst.into(),
            )
            .await;
        let s = Summary {
            s: ServerSummary {
                typ: self.typ().into(),
                sid: self.id.clone(),
                pid,
                cid: tab.cid.clone(),
                ..Default::default()
            },
            start: Instant::now(),
        };
        (tab, s)
    }

    async fn resolve(&self, dst: &str) -> io::Result<SocketAddr> {
        let (host, port) = fs_proxy::upstream::split_host_port(dst);
        let port = port.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("svc: no port in {dst}"),
            )
        })?;
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(SocketAddr::new(ip, port));
        }
        let ips = match &self.resolver {
            Some(r) => r(host.clone()).await,
            None => tokio::net::lookup_host((host.as_str(), port))
                .await?
                .map(|a| a.ip())
                .collect(),
        };
        ips.first()
            .map(|ip| SocketAddr::new(*ip, port))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, format!("svc: no ips for {host}"))
            })
    }

    async fn dial_tcp(&self, dst: &str) -> io::Result<TcpConn> {
        self.candial()?;
        let to = self.resolve(dst).await?;
        let px = self.px.lock().clone();
        let r = match px {
            Some(p) => p.dial_tcp(to, DIAL_TIMEOUT).await,
            None => fs_dialers::Dial::dial_tcp(&self.protector, &self.id, to, DIAL_TIMEOUT).await,
        };
        self.note(&r);
        r
    }

    async fn dial_udp(&self, dst: &str) -> io::Result<UdpConn> {
        self.candial()?;
        let to = self.resolve(dst).await?;
        let px = self.px.lock().clone();
        let r = match px {
            Some(p) => p.dial_udp(to).await,
            None => fs_dialers::Dial::dial_udp(&self.protector, &self.id, to).await,
        };
        self.note(&r);
        r
    }

    fn note<T>(&self, r: &io::Result<T>) {
        if self.status() != END {
            self.status
                .store(if r.is_ok() { SOK } else { SKO }, Ordering::Relaxed);
        }
    }

    fn summarize(&self, s: ServerSummary) {
        let _ = self.queue.try_send(s); // dropped when full, as firestack
    }
}

async fn until_stopped(mut stop: watch::Receiver<bool>) {
    while !*stop.borrow() {
        if stop.changed().await.is_err() {
            return;
        }
    }
}

/// `host:port` to a bindable address (an empty host is every interface, as Go's `Listen(":port")`).
fn listen_addr(host: &str) -> Result<SocketAddr> {
    let (h, port) = fs_proxy::upstream::split_host_port(host);
    let port = port.ok_or_else(|| format!("svc: missing port in {host:?}"))?;
    let ip = if h.is_empty() {
        IpAddr::from([0u8, 0, 0, 0])
    } else {
        h.parse::<IpAddr>()
            .map_err(|_| format!("svc: listen address must be an ip: {host:?}"))?
    };
    Ok(SocketAddr::new(ip, port))
}

/// `scheme://[user[:pass]@]host:port[/…]`
fn parse_url(url: &str) -> Result<(String, String, String, String)> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| format!("svc: bad url {url:?}"))?;
    let rest = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let (user, pass, host) = match rest.rsplit_once('@') {
        Some((ui, h)) => {
            let (u, p) = ui.split_once(':').unwrap_or((ui, ""));
            (
                fs_proxy::upstream::pct_decode(u),
                fs_proxy::upstream::pct_decode(p),
                h,
            )
        }
        None => (String::new(), String::new(), rest),
    };
    Ok((scheme.to_ascii_lowercase(), user, pass, host.to_string()))
}

/// The local servers of a tunnel (`backend.Services`).
pub struct Services {
    servers: RwLock<HashMap<String, Arc<Server>>>,
    proxies: Arc<Proxifier>,
    listener: Arc<dyn ServerListener>,
    queue: mpsc::Sender<ServerSummary>,
}

impl Services {
    /// Must be called within a tokio runtime (summaries are delivered from a task on it).
    pub fn new(proxies: Arc<Proxifier>, listener: Arc<dyn ServerListener>) -> Arc<Self> {
        let (tx, mut rx) = mpsc::channel::<ServerSummary>(SUMMARIES);
        let l = listener.clone();
        proxies.runtime().spawn(async move {
            while let Some(s) = rx.recv().await {
                tokio::time::sleep(SUMMARY_DELAY).await;
                l.on_svc_complete(s);
            }
        });
        Arc::new(Services {
            servers: RwLock::new(HashMap::new()),
            proxies,
            listener,
            queue: tx,
        })
    }

    /// `addServer(type, id, url)`: replaces any server of the same id, and bridges it to a namesake proxy.
    pub fn add_server(&self, typ: &str, id: &str, url: &str) -> Result<Arc<Server>> {
        self.remove_server(id);
        let kind = match typ {
            SVCSOCKS5 | PXSOCKS5 => Kind::Socks5,
            SVCHTTP | PXHTTP => Kind::Http,
            _ => return Err("unsupported operation".into()),
        };
        let (scheme, user, pass, host) = parse_url(url)?;
        let s = Arc::new(Server {
            id: id.to_string(),
            kind,
            host,
            user,
            pass,
            tls: kind == Kind::Http && scheme == "https",
            protector: self.proxies.protector().clone(),
            resolver: self.proxies.host_resolver(),
            listener: self.listener.clone(),
            queue: self.queue.clone(),
            rt: self.proxies.runtime().clone(),
            px: Mutex::new(None),
            status: AtomicI32::new(SOK),
            run: Mutex::new(None),
        });
        self.servers.write().insert(id.to_string(), s.clone());
        if self.proxies.has_proxy(id) {
            self.bridge(id, id)?;
        }
        Ok(s)
    }

    /// `bridge(serverId, proxyId)`: routes the server's connections over the proxy; an empty proxy id unbridges.
    pub fn bridge(&self, sid: &str, pid: &str) -> Result<()> {
        let s = self.get_server(sid)?;
        if pid.is_empty() {
            return s.hop(None);
        }
        let p = self.proxies.proxy_for(pid)?;
        s.hop(Some(p))
    }

    pub fn get_server(&self, id: &str) -> Result<Arc<Server>> {
        self.servers
            .read()
            .get(id)
            .cloned()
            .ok_or_else(|| ERR_NO_SERVER.into())
    }

    pub fn remove_server(&self, id: &str) -> bool {
        let s = self.servers.write().remove(id);
        s.inspect(|s| s.stop()).is_some()
    }

    /// Restarts every server; csv of those that came back.
    pub fn refresh_servers(&self) -> String {
        let all: Vec<_> = self.servers.read().values().cloned().collect();
        all.iter()
            .filter(|s| s.refresh().is_ok())
            .map(|s| s.id.clone())
            .collect::<Vec<_>>()
            .join(",")
    }

    pub fn stop_servers(&self) {
        for s in self.servers.read().values() {
            s.stop();
        }
    }

    pub fn remove_all(&self) {
        self.stop_servers();
        self.servers.write().clear();
    }
}

/// Copies both ways until either side ends or idles for `TCP_IDLE`; `rx` is what `egress` sent back.
async fn relay<A, B>(ingress: A, egress: B, pre: &[u8]) -> (Moved, Option<String>)
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let (mut ir, mut iw) = tokio::io::split(ingress);
    let (mut er, mut ew) = tokio::io::split(egress);
    let mut moved = Moved::default();
    if !pre.is_empty() {
        if let Err(e) = ew.write_all(pre).await {
            return (moved, Some(e.to_string()));
        }
        moved.tx += pre.len() as i64;
    }
    let (up, down) = tokio::join!(pipe(&mut ir, &mut ew), pipe(&mut er, &mut iw));
    moved.tx += up.0;
    moved.rx = down.0;
    let errs: Vec<String> = [up.1, down.1].into_iter().flatten().collect();
    (moved, (!errs.is_empty()).then(|| errs.join("; ")))
}

/// One direction; half-closes the writer at the reader's end.
async fn pipe<R, W>(r: &mut R, w: &mut W) -> (i64, Option<String>)
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut b = vec![0u8; 16 * 1024];
    let mut n = 0i64;
    loop {
        let got = match tokio::time::timeout(TCP_IDLE, r.read(&mut b)).await {
            Err(_) => return (n, Some("idle timeout".into())),
            Ok(Err(e)) => return (n, Some(e.to_string())),
            Ok(Ok(0)) => break,
            Ok(Ok(k)) => k,
        };
        if let Err(e) = w.write_all(&b[..got]).await {
            return (n, Some(e.to_string()));
        }
        n += got as i64;
    }
    let _ = w.shutdown().await;
    (n, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_and_listen_addrs() {
        assert_eq!(
            parse_url("http://u:p%40ss@127.0.0.1:8080/x").unwrap(),
            (
                "http".into(),
                "u".into(),
                "p@ss".into(),
                "127.0.0.1:8080".into()
            )
        );
        assert_eq!(parse_url("socks5://:1080").unwrap().3, ":1080");
        assert_eq!(
            listen_addr(":1080").unwrap(),
            "0.0.0.0:1080".parse().unwrap()
        );
        assert_eq!(
            listen_addr("[::1]:1080").unwrap(),
            "[::1]:1080".parse().unwrap()
        );
        assert!(listen_addr("127.0.0.1").is_err(), "needs a port");
        assert!(listen_addr("localhost:80").is_err(), "needs an ip");
    }
}
