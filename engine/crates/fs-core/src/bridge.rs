// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/listener.go
// Derived-From: celzero/firestack@d3d530ea3e:intra/backend/dnsx_listener.go
// Derived-From: celzero/firestack@d3d530ea3e:intra/backend/protect.go

//! Engine-side view of the callbacks Kotlin implements (`intra.Bridge` = Controller + FlowListener +
//! DNSListener + ProxyListener + ServerListener). JNI-free: `fs-jni` implements these traits over the real Kotlin object, tests
//! implement them in Rust. Callbacks that return a value are async (they run on JVM-attached executor threads);
//! notifications are fire-and-forget.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

/// IP protocol numbers passed as `protocol` to flow callbacks (firestack `ntoa`).
pub const PROTO_ICMP: i32 = 1;
pub const PROTO_TCP: i32 = 6;
pub const PROTO_UDP: i32 = 17;
pub const PROTO_ICMP6: i32 = 58;

/// `intra.PreMark`: result of `preflow`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PreMark {
    pub uid: String,
    pub is_uid_self: bool,
}

/// `intra.Mark`: verdict of `flow` / `inflow`, also passed to `flowing`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Mark {
    /// csv of proxy ids to route over (`Base`, `Exit`, `Block`, WireGuard ids, …)
    pub pidcsv: String,
    /// connection id (chosen by Kotlin)
    pub cid: String,
    pub uid: String,
    /// preferred egress IP override (optional)
    pub ip: String,
}

/// Arguments of `flow`.
#[derive(Clone, Debug, Default)]
pub struct FlowArgs {
    pub protocol: i32,
    pub uid: i32,
    pub src: String,
    pub dst: String,
    pub origdsts: String,
    pub domains: String,
    pub probable_domains: String,
    pub blocklists: String,
    pub dst_is_alg: bool,
}

/// `intra.FlowSummary`, delivered by `postflow` when a connection ends.
#[derive(Clone, Debug, Default)]
pub struct FlowSummary {
    pub proto: String,
    pub id: String,
    pub pid: String,
    pub rpid: String,
    pub uid: String,
    pub source: String,
    pub target: String,
    pub rx: i64,
    pub tx: i64,
    /// milliseconds
    pub duration: i64,
    /// milliseconds
    pub rtt: i64,
    pub msg: String,
}

/// `backend.DNSOpts`: per-query policy from `onQuery` / `onUpstreamAnswer`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DnsOpts {
    pub uid: String,
    pub ipcsv: String,
    /// `[Cache]<tid>[:pid1[:pid2]]`, comma-separated
    pub tidcsv: String,
    pub tidseccsv: String,
    pub noblock: bool,
}

/// DNS query status codes (backend constants).
pub mod dns_status {
    pub const START: i32 = 0;
    pub const COMPLETE: i32 = 1;
    pub const SEND_FAILED: i32 = 2;
    pub const NO_RESPONSE: i32 = 3;
    pub const BAD_QUERY: i32 = 4;
    pub const BAD_RESPONSE: i32 = 5;
    pub const INTERNAL_ERROR: i32 = 6;
    pub const TRANSPORT_ERROR: i32 = 7;
    pub const CLIENT_ERROR: i32 = 8;
    pub const PAUSED: i32 = 9;
    pub const UNPAUSED: i32 = 10;
    pub const DEND: i32 = 11;
    pub const UNKNOWN: i32 = 100;
}

/// `backend.DNSSummary`.
#[derive(Clone, Debug, Default)]
pub struct DnsSummary {
    pub typ: String,
    pub fid: String,
    pub id: String,
    pub uid: String,
    pub origin: String,
    /// unix millis
    pub start: i64,
    /// seconds
    pub latency: f64,
    pub qname: String,
    pub qtype: i64,
    pub targets: String,
    pub cached: bool,
    pub rdata: String,
    pub rcode: i64,
    pub rttl: i64,
    pub server: String,
    pub pid: String,
    pub rpid: String,
    pub status: i32,
    pub blocklists: String,
    pub blocked_target: String,
    pub upstream_blocks: bool,
    pub do_bit: bool,
    pub ad: bool,
    pub ech: bool,
    pub msg: String,
    pub extra: String,
    pub region: String,
}

/// `backend.Controller`: socket protection. `fd` is a raw socket descriptor; `addrport` is the destination
/// (`ip:port`) for dials or the local wildcard (`0.0.0.0:0` / `[::]:0`) for listens.
pub trait Controller: Send + Sync {
    fn bind4(&self, who: String, addrport: String, fd: i64) -> BoxFuture<()>;
    fn bind6(&self, who: String, addrport: String, fd: i64) -> BoxFuture<()>;
    fn protect(&self, who: String, fd: i64) -> BoxFuture<()>;
}

/// Flow decisions and notifications (`intra.FlowListener`).
pub trait FlowListener: Send + Sync {
    fn preflow(
        &self,
        protocol: i32,
        uid: i32,
        src: String,
        dst: String,
    ) -> BoxFuture<Option<PreMark>>;
    fn flow(&self, args: FlowArgs) -> BoxFuture<Option<Mark>>;
    fn inflow(&self, protocol: i32, uid: i32, src: String, dst: String) -> BoxFuture<Option<Mark>>;
    fn flowing(&self, m: Mark);
    fn postflow(&self, s: FlowSummary);
}

/// DNS policy and notifications (`backend.DNSListener`).
pub trait DnsListener: Send + Sync {
    fn on_query(
        &self,
        who: String,
        uid: String,
        domain: String,
        qtype: i64,
    ) -> BoxFuture<Option<DnsOpts>>;
    fn on_upstream_answer(
        &self,
        who: String,
        smm: DnsSummary,
        pref: DnsOpts,
        ipcsv: String,
    ) -> BoxFuture<Option<DnsOpts>>;
    fn on_response(&self, smm: DnsSummary);
    fn on_dns_added(&self, id: String);
    fn on_dns_removed(&self, id: String);
    fn on_dns_stopped(&self);
}

/// Proxy lifecycle notifications (`backend.ProxyListener`).
pub trait ProxyListener: Send + Sync {
    fn on_proxy_added(&self, id: String, handle: String);
    fn on_proxy_removed(&self, id: String, handle: String);
    fn on_proxy_updated(&self, id: String, handle: String);
    fn on_proxy_stopped(&self, id: String, handle: String);
    fn on_proxies_stopped(&self);
}

/// `backend.Tab`: verdict of `svcRoute` for a connection a local server accepted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Tab {
    /// connection id (chosen by Kotlin)
    pub cid: String,
    pub block: bool,
}

/// `backend.ServerSummary`: one connection a local server relayed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServerSummary {
    /// `svcsocks5`, `pxsocks5`, `svchttp`, `pxhttp`
    pub typ: String,
    pub sid: String,
    pub pid: String,
    pub cid: String,
    pub rx: i64,
    pub tx: i64,
    /// milliseconds
    pub duration: i64,
    pub msg: String,
}

/// Local server callbacks (`backend.ServerListener`).
pub trait ServerListener: Send + Sync {
    /// `svcRoute(sid, pid, network, src, dst)`
    fn svc_route(
        &self,
        sid: String,
        pid: String,
        network: String,
        src: String,
        dst: String,
    ) -> BoxFuture<Tab>;
    fn on_svc_complete(&self, s: ServerSummary);
}

/// `intra.Bridge`.
pub trait Bridge: Controller + FlowListener + DnsListener + ProxyListener + ServerListener {}
impl<T: Controller + FlowListener + DnsListener + ProxyListener + ServerListener> Bridge for T {}

pub type SharedBridge = Arc<dyn Bridge>;

/// A Bridge that allows everything over `Exit` and protects nothing (host tests, tools).
#[derive(Default)]
pub struct AllowAllBridge;

fn ready<T: Send + 'static>(v: T) -> BoxFuture<T> {
    Box::pin(async move { v })
}

impl Controller for AllowAllBridge {
    fn bind4(&self, _: String, _: String, _: i64) -> BoxFuture<()> {
        ready(())
    }
    fn bind6(&self, _: String, _: String, _: i64) -> BoxFuture<()> {
        ready(())
    }
    fn protect(&self, _: String, _: i64) -> BoxFuture<()> {
        ready(())
    }
}
impl FlowListener for AllowAllBridge {
    fn preflow(&self, _: i32, uid: i32, _: String, _: String) -> BoxFuture<Option<PreMark>> {
        ready(Some(PreMark {
            uid: uid.to_string(),
            is_uid_self: false,
        }))
    }
    fn flow(&self, a: FlowArgs) -> BoxFuture<Option<Mark>> {
        ready(Some(Mark {
            pidcsv: "Exit".into(),
            cid: format!("c{}", a.src),
            uid: a.uid.to_string(),
            ip: String::new(),
        }))
    }
    fn inflow(&self, _: i32, _: i32, src: String, dst: String) -> BoxFuture<Option<Mark>> {
        ready(Some(Mark {
            pidcsv: "Ingress".into(),
            cid: format!("i{dst}>{src}"),
            uid: "-1".into(),
            ip: String::new(),
        }))
    }
    fn flowing(&self, _: Mark) {}
    fn postflow(&self, _: FlowSummary) {}
}
impl DnsListener for AllowAllBridge {
    fn on_query(&self, _: String, uid: String, _: String, _: i64) -> BoxFuture<Option<DnsOpts>> {
        ready(Some(DnsOpts {
            uid,
            tidcsv: "CachePreferred:Base".into(),
            ..Default::default()
        }))
    }
    fn on_upstream_answer(
        &self,
        _: String,
        _: DnsSummary,
        pref: DnsOpts,
        _: String,
    ) -> BoxFuture<Option<DnsOpts>> {
        ready(Some(pref))
    }
    fn on_response(&self, _: DnsSummary) {}
    fn on_dns_added(&self, _: String) {}
    fn on_dns_removed(&self, _: String) {}
    fn on_dns_stopped(&self) {}
}
impl ProxyListener for AllowAllBridge {
    fn on_proxy_added(&self, _: String, _: String) {}
    fn on_proxy_removed(&self, _: String, _: String) {}
    fn on_proxy_updated(&self, _: String, _: String) {}
    fn on_proxy_stopped(&self, _: String, _: String) {}
    fn on_proxies_stopped(&self) {}
}

impl ServerListener for AllowAllBridge {
    fn svc_route(&self, _: String, _: String, _: String, _: String, _: String) -> BoxFuture<Tab> {
        ready(Tab::default())
    }
    fn on_svc_complete(&self, _: ServerSummary) {}
}
