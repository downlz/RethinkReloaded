// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/tunnel.go
// Derived-From: celzero/firestack@d3d530ea3e:intra/tun2socks.go (Connect)
// Derived-From: celzero/firestack@d3d530ea3e:intra/dnsx/bootstrap.go (DefaultDNS)

//! `intra.Tunnel`: owns the netstack, resolver and handlers for one VPN session.

use crate::flow::Stall;
use crate::tcp;
use crate::udp::{Outbound, Sessions};
use fs_core::bridge::{BoxFuture, SharedBridge, dns_status};
use fs_core::settings;
use fs_dialers::Protector;
use fs_dns::dns53::{BlockAll, Dns53Transport};
use fs_dns::doh::{DohTransport, HostResolver};
use fs_dns::ids;
use fs_dns::transport::{Answer, QueryError, TYPE_DNS53, TYPE_DOH, Transport};
use fs_dnsx::Resolver;
use fs_netstack::tun::Tun;
use fs_netstack::{Netstack, Opts};
use fs_proxy::Proxifier;
use futures::{SinkExt, StreamExt};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Weak};
use tokio::sync::{Notify, mpsc};
use tokio::task::JoinHandle;

/// `Intra.newDefaultDNS(typ, url, ips)`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DefaultDnsSpec {
    pub typ: String,
    pub url: String,
    pub ips: String,
}

impl DefaultDnsSpec {
    /// firestack `reinit` validation: DoH needs seed IPs (no bootstrap loop); DNS53 needs `ip[:port]`s.
    pub fn validate(&self) -> Result<(), String> {
        match self.typ.as_str() {
            TYPE_DOH if self.ips.trim().is_empty() => {
                Err("not a default transport: doh needs ips".into())
            }
            TYPE_DOH => Ok(()),
            TYPE_DNS53 if Dns53Transport::parse_servers(&self.url).is_empty() => {
                Err(format!("default dns: bad ip:port {}", self.url))
            }
            TYPE_DNS53 => Ok(()),
            "" if self.url.is_empty() => Ok(()), // Goos
            t => Err(format!("default dns: unsupported type {t}")),
        }
    }
}

pub fn parse_ips(csv: &str) -> Vec<IpAddr> {
    csv.split(',')
        .filter_map(|s| s.trim().trim_matches(['[', ']']).parse().ok())
        .collect()
}

/// cid -> (uid, pid, closer)
type ConnMap = HashMap<String, (String, String, Arc<Notify>)>;

/// Connection registry for `Tunnel.closeConns`.
#[derive(Default)]
pub struct Conns {
    m: Mutex<ConnMap>,
}

pub struct ConnHandle(Arc<Notify>);

impl ConnHandle {
    pub async fn closed(&self) {
        self.0.notified().await
    }
}

impl Conns {
    pub fn track(&self, cid: &str, uid: &str, pid: &str) -> ConnHandle {
        let n = Arc::new(Notify::new());
        self.m.lock().insert(
            cid.to_string(),
            (uid.to_string(), pid.to_string(), n.clone()),
        );
        ConnHandle(n)
    }

    pub fn untrack(&self, cid: &str) {
        self.m.lock().remove(cid);
    }

    /// Closes connections whose cid, pid or uid is in `csv` (all when empty); returns the closed cids.
    pub fn close(&self, csv: &str) -> String {
        let keys: Vec<&str> = csv
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        let m = self.m.lock();
        let mut closed = Vec::new();
        for (cid, (uid, pid, n)) in m.iter() {
            if keys.is_empty() || keys.iter().any(|k| k == cid || k == uid || k == pid) {
                n.notify_one();
                closed.push(cid.clone());
            }
        }
        closed.join(",")
    }
}

/// State shared by the handlers.
pub struct Shared {
    pub bridge: SharedBridge,
    pub resolver: Arc<Resolver>,
    pub proxies: Arc<Proxifier>,
    pub stall: Stall,
    pub conns: Conns,
}

pub struct Tunnel {
    sh: Arc<Shared>,
    netstack: Arc<Netstack>,
    sessions: Arc<Sessions>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    closed: AtomicBool,
    link_mtu: AtomicI32,
    default: Mutex<DefaultDnsSpec>,
}

/// `Goos` (Go's system resolver in firestack): here, the `System` transport (DNS servers of the underlying
/// network, set by Kotlin via `Intra.setSystemDNS`).
struct Goos {
    resolver: Weak<Resolver>,
}

impl Transport for Goos {
    fn id(&self) -> &str {
        ids::GOOS
    }
    fn typ(&self) -> &str {
        TYPE_DNS53
    }
    fn addr(&self) -> String {
        self.resolver
            .upgrade()
            .and_then(|r| r.get(ids::SYSTEM))
            .map(|t| t.addr())
            .unwrap_or_default()
    }
    fn status(&self) -> i32 {
        self.resolver
            .upgrade()
            .and_then(|r| r.get(ids::SYSTEM))
            .map(|t| t.status())
            .unwrap_or(dns_status::START)
    }
    fn p50(&self) -> i64 {
        0
    }
    fn query(self: Arc<Self>, q: Vec<u8>, pid: String) -> BoxFuture<Result<Answer, QueryError>> {
        let sys = self.resolver.upgrade().and_then(|r| r.get(ids::SYSTEM));
        Box::pin(async move {
            match sys {
                Some(t) => t.query(q, pid).await,
                None => Err(QueryError::new(
                    dns_status::TRANSPORT_ERROR,
                    "goos: no system dns",
                )),
            }
        })
    }
}

/// Wraps a transport under another id (e.g. the bootstrap transport exposed as `Default`).
struct Renamed {
    id: &'static str,
    inner: Arc<dyn Transport>,
}

impl Transport for Renamed {
    fn id(&self) -> &str {
        self.id
    }
    fn typ(&self) -> &str {
        self.inner.typ()
    }
    fn addr(&self) -> String {
        self.inner.addr()
    }
    fn status(&self) -> i32 {
        self.inner.status()
    }
    fn p50(&self) -> i64 {
        self.inner.p50()
    }
    fn query(self: Arc<Self>, q: Vec<u8>, pid: String) -> BoxFuture<Result<Answer, QueryError>> {
        self.inner.clone().query(q, pid)
    }
}

impl Tunnel {
    /// `Intra.connect`. Must be called inside the engine runtime.
    #[allow(clippy::too_many_arguments)]
    pub fn connect(
        fd: i32,
        link_mtu: i32,
        tun_mtu: i32,
        _ifaddrs: &str,
        fakedns: &str,
        dtr: Option<DefaultDnsSpec>,
        bridge: SharedBridge,
    ) -> Result<Arc<Tunnel>, String> {
        let protector = Protector::new(bridge.clone());
        let proxies = Proxifier::new("46", link_mtu as i64, protector, bridge.clone());
        let resolver = Arc::new(Resolver::new(fakedns, bridge.clone()));
        let dup = !settings::OWN_TUN_FD.load(Ordering::SeqCst);
        let tun = Tun::from_fd(fd, tun_mtu, dup).map_err(|e| format!("tun: {e}"))?;
        let mtu = if tun_mtu > 0 { tun_mtu as usize } else { 1500 };
        let sh = Arc::new(Shared {
            bridge,
            resolver: resolver.clone(),
            proxies,
            stall: Stall::default(),
            conns: Conns::default(),
        });

        // ICMP echo requests are intercepted before the stack and handled by `icmp::handle`
        let ns_slot: Arc<std::sync::OnceLock<Weak<Netstack>>> =
            Arc::new(std::sync::OnceLock::new());
        let (shi, slot, flood) = (
            sh.clone(),
            ns_slot.clone(),
            Arc::new(crate::icmp::Flood::default()),
        );
        let intercept: fs_netstack::Interceptor = Arc::new(move |pkt: &[u8]| {
            let Some(e) = crate::icmp::parse_echo(pkt) else {
                return false;
            };
            if let Some(ns) = slot.get().and_then(Weak::upgrade) {
                tokio::spawn(crate::icmp::handle(shi.clone(), ns, flood.clone(), e));
            }
            true
        });
        let (netstack, eps) = Netstack::start(
            tun,
            Opts {
                mtu,
                ..Default::default()
            },
            Some(intercept),
        )
        .map_err(|e| format!("netstack: {e}"))?;
        let _ = ns_slot.set(Arc::downgrade(&netstack));
        let t = Arc::new(Tunnel {
            sh: sh.clone(),
            netstack,
            sessions: Arc::new(Sessions::default()),
            tasks: Mutex::new(Vec::new()),
            closed: AtomicBool::new(false),
            link_mtu: AtomicI32::new(if link_mtu > 0 { link_mtu } else { tun_mtu }),
            default: Mutex::new(DefaultDnsSpec::default()),
        });

        // fixed transports (firestack NewTunnel2): BlockAll, Goos; Default from dtr (or Goos)
        resolver.add(Arc::new(BlockAll::default()));
        resolver.add(Arc::new(Goos {
            resolver: Arc::downgrade(&resolver),
        }));
        t.set_default_dns(dtr.unwrap_or_default())?;

        // TCP accept loop
        let mut tcp = eps.tcp;
        let shc = sh.clone();
        let accept = tokio::spawn(async move {
            while let Some((stream, src, dst)) = tcp.next().await {
                tokio::spawn(tcp::handle(shc.clone(), stream, src, dst));
            }
        });
        // UDP: inbound dispatcher + outbound writer
        let (out_tx, mut out_rx) = mpsc::channel::<Outbound>(1024);
        let mut udp_tx = eps.udp_tx;
        let writer = tokio::spawn(async move {
            while let Some(m) = out_rx.recv().await {
                if udp_tx.send(m).await.is_err() {
                    break;
                }
            }
        });
        let mut udp_rx = eps.udp_rx;
        let (shu, sessions) = (sh.clone(), t.sessions.clone());
        let dispatch = tokio::spawn(async move {
            while let Some((payload, src, dst)) = udp_rx.next().await {
                sessions.dispatch(&shu, &out_tx, payload, src, dst);
            }
        });
        t.tasks.lock().extend([accept, writer, dispatch]);
        // proxy hostnames resolve through the engine (firestack multihost)
        let hr = t.host_resolver();
        t.sh.proxies.set_host_resolver(hr);
        Ok(t)
    }

    pub fn resolver(&self) -> &Arc<Resolver> {
        &self.sh.resolver
    }

    pub fn proxies(&self) -> &Arc<Proxifier> {
        &self.sh.proxies
    }

    /// DNS transports dial through the proxies, by the pid of each query.
    fn dialer(&self) -> fs_dialers::SharedDial {
        self.sh.proxies.clone()
    }

    /// Resolves DoH hostnames through the Default transport.
    pub fn host_resolver(&self) -> HostResolver {
        let r = Arc::downgrade(&self.sh.resolver);
        Arc::new(move |host: String| -> BoxFuture<Vec<IpAddr>> {
            let r = r.clone();
            Box::pin(async move {
                match r.upgrade() {
                    Some(r) => r.lookup_ip(&host).await,
                    None => Vec::new(),
                }
            })
        })
    }

    /// (Re)builds the Default transport (`Intra.addDefaultTransport` / `newDefaultDNS`); keeps the old one on error.
    pub fn set_default_dns(&self, spec: DefaultDnsSpec) -> Result<(), String> {
        spec.validate()?;
        let p = self.dialer();
        let inner: Arc<dyn Transport> = match spec.typ.as_str() {
            TYPE_DOH => Arc::new(DohTransport::new(
                ids::BOOTSTRAP,
                &spec.url,
                parse_ips(&spec.ips),
                p,
                None,
            )?),
            TYPE_DNS53 => Arc::new(Dns53Transport::new(
                ids::BOOTSTRAP,
                Dns53Transport::parse_servers(&spec.url),
                p,
            )),
            _ => Arc::new(Goos {
                resolver: Arc::downgrade(&self.sh.resolver),
            }),
        };
        self.sh.resolver.add(Arc::new(Renamed {
            id: ids::DEFAULT,
            inner,
        }));
        *self.default.lock() = spec;
        Ok(())
    }

    /// `Intra.addDoHTransport(t, id, url, ipcsv)`.
    pub fn add_doh(&self, id: &str, url: &str, ipcsv: &str) -> Result<(), String> {
        let t = DohTransport::new(
            id,
            url,
            parse_ips(ipcsv),
            self.dialer(),
            Some(self.host_resolver()),
        )?;
        self.sh.resolver.add(Arc::new(t));
        Ok(())
    }

    /// `Intra.addDNSProxy(t, id, ipportcsv)` / `Intra.setSystemDNS(t, ipcsv)`.
    /// `Intra.addDoTTransport(t, id, url, ipcsv)`.
    pub fn add_dot(&self, id: &str, url: &str, ipcsv: &str) -> Result<(), String> {
        let t = fs_dns::dot::DotTransport::new(
            id,
            url,
            parse_ips(ipcsv),
            self.dialer(),
            Some(self.host_resolver()),
        )?;
        self.sh.resolver.add(Arc::new(t));
        Ok(())
    }

    pub fn add_dns53(&self, id: &str, csv: &str) -> Result<(), String> {
        let servers = Dns53Transport::parse_servers(csv);
        if servers.is_empty() {
            return Err(format!("dns53: no valid ip:port in {csv:?}"));
        }
        self.sh
            .resolver
            .add(Arc::new(Dns53Transport::new(id, servers, self.dialer())));
        Ok(())
    }

    pub fn is_connected(&self) -> bool {
        !self.closed.load(Ordering::SeqCst)
    }

    pub fn enabled(&self) -> bool {
        self.is_connected() && self.netstack.is_linked()
    }

    pub fn mtu(&self) -> i32 {
        if self.is_connected() {
            self.netstack.mtu()
        } else {
            -1
        }
    }

    pub fn link_mtu(&self) -> i32 {
        self.link_mtu.load(Ordering::SeqCst)
    }

    /// `Tunnel.setLinkMtu`: true if changed.
    pub fn set_link_mtu(&self, m: i32) -> bool {
        self.link_mtu.swap(m, Ordering::SeqCst) != m
    }

    /// `Tunnel.setLinkAndRoutes2(fd, tunmtu, linkmtu, engine)`: swaps the TUN fd, keeping connections.
    pub fn set_link_and_routes(
        &self,
        fd: i32,
        tun_mtu: i32,
        link_mtu: i32,
        engine: i64,
    ) -> Result<(), String> {
        if !self.is_connected() {
            return Err("tunnel closed".into());
        }
        // firestack RefreshProto: proxies follow the link's families and MTU
        self.sh
            .proxies
            .refresh_proto(settings::l3(engine), link_mtu as i64);
        let dup = !settings::OWN_TUN_FD.load(Ordering::SeqCst);
        let tun = Tun::from_fd(fd, tun_mtu, dup).map_err(|e| format!("tun: {e}"))?;
        self.netstack.swap(tun);
        self.set_link_mtu(link_mtu);
        Ok(())
    }

    /// `Tunnel.restart(fd, linkmtu, tunmtu, engine)`: new fd and a clean slate (all connections closed).
    pub fn restart(&self, fd: i32, link_mtu: i32, tun_mtu: i32, engine: i64) -> Result<(), String> {
        self.sh.conns.close("");
        self.sessions.clear();
        self.set_link_and_routes(
            fd,
            tun_mtu,
            if link_mtu > 0 { link_mtu } else { tun_mtu },
            engine,
        )
    }

    /// `Tunnel.unlink`: closes the TUN fd; the stack and connections survive.
    pub fn unlink(&self) {
        self.netstack.unlink();
    }

    pub fn close_conns(&self, csv: &str) -> String {
        self.sh.conns.close(csv)
    }

    /// `Tunnel.disconnect`: tears everything down (once).
    pub fn disconnect(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        self.sh.conns.close("");
        self.sessions.clear();
        for t in self.tasks.lock().drain(..) {
            t.abort();
        }
        self.netstack.stop();
        self.sh.resolver.stop_all();
        self.sh.proxies.stop_proxies(); // tells Kotlin onProxiesStopped
    }

    pub fn fakedns(&self) -> Vec<SocketAddr> {
        self.sh.resolver.fakedns().to_vec()
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        self.disconnect();
    }
}
