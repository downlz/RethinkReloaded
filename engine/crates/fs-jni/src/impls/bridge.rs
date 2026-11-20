// Copyright (c) 2026 RethinkReloaded contributors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! `JniBridge`: the engine's Bridge traits implemented over the Kotlin `intra.Bridge` object. Calls run on the
//! callback executor lanes (never on async workers); struct values cross through the gobind struct store, so
//! Kotlin's own `Mark()` / `DNSOpts()` / `PreMark()` objects are read back directly.

use crate::cbexec::{Lane, executor};
use crate::rt::{self, Field, Struct};
use fs_core::bridge::*;
use jni::JNIEnv;
use jni::objects::{GlobalRef, JObject, JValue};
use std::sync::Arc;

const C_MARK: &str = "com/celzero/firestack/intra/Mark";
const C_FLOW_SUMMARY: &str = "com/celzero/firestack/intra/FlowSummary";
const C_DNS_SUMMARY: &str = "com/celzero/firestack/backend/DNSSummary";
const C_DNS_OPTS: &str = "com/celzero/firestack/backend/DNSOpts";
const SIG_STR: &str = "Ljava/lang/String;";

pub struct JniBridge {
    obj: Arc<GlobalRef>,
}

impl JniBridge {
    pub fn new(env: &mut JNIEnv, bridge: &JObject) -> jni::errors::Result<Self> {
        Ok(JniBridge {
            obj: Arc::new(env.new_global_ref(bridge)?),
        })
    }
}

fn jstr<'l>(env: &mut JNIEnv<'l>, s: &str) -> JObject<'l> {
    env.new_string(s).map(JObject::from).unwrap_or_default()
}

/// Calls a Kotlin method; a thrown exception is cleared and reported as `None`.
fn call<'l>(
    env: &mut JNIEnv<'l>,
    obj: &GlobalRef,
    name: &str,
    sig: &str,
    args: &[JValue],
) -> Option<jni::objects::JValueOwned<'l>> {
    match env.call_method(obj.as_obj(), name, sig, args) {
        Ok(v) => Some(v),
        Err(_) => {
            if env.exception_check().unwrap_or(false) {
                let _ = env.exception_describe();
                let _ = env.exception_clear();
            }
            None
        }
    }
}

fn returned_struct(env: &mut JNIEnv, v: Option<jni::objects::JValueOwned>) -> Option<Arc<Struct>> {
    let o = v?.l().ok()?;
    if o.is_null() {
        return None;
    }
    rt::struct_of(env, &o).ok()
}

fn mark_struct(m: &Mark) -> Arc<Struct> {
    let s = Struct::new(C_MARK);
    s.set("PIDCSV", Field::Str(m.pidcsv.clone()));
    s.set("CID", Field::Str(m.cid.clone()));
    s.set("UID", Field::Str(m.uid.clone()));
    s.set("IP", Field::Str(m.ip.clone()));
    s
}

fn mark_from(s: &Struct) -> Mark {
    Mark {
        pidcsv: s.str("PIDCSV"),
        cid: s.str("CID"),
        uid: s.str("UID"),
        ip: s.str("IP"),
    }
}

fn opts_struct(o: &DnsOpts) -> Arc<Struct> {
    let s = Struct::new(C_DNS_OPTS);
    s.set("UID", Field::Str(o.uid.clone()));
    s.set("IPCSV", Field::Str(o.ipcsv.clone()));
    s.set("TIDCSV", Field::Str(o.tidcsv.clone()));
    s.set("TIDSECCSV", Field::Str(o.tidseccsv.clone()));
    s.set("NOBLOCK", Field::Bool(o.noblock));
    s
}

fn opts_from(s: &Struct) -> DnsOpts {
    DnsOpts {
        uid: s.str("UID"),
        ipcsv: s.str("IPCSV"),
        tidcsv: s.str("TIDCSV"),
        tidseccsv: s.str("TIDSECCSV"),
        noblock: s.bool("NOBLOCK"),
    }
}

fn summary_struct(d: &DnsSummary) -> Arc<Struct> {
    let s = Struct::new(C_DNS_SUMMARY);
    for (k, v) in [
        ("Type", &d.typ),
        ("FID", &d.fid),
        ("ID", &d.id),
        ("UID", &d.uid),
        ("Origin", &d.origin),
        ("QName", &d.qname),
        ("Targets", &d.targets),
        ("RData", &d.rdata),
        ("Server", &d.server),
        ("PID", &d.pid),
        ("RPID", &d.rpid),
        ("Blocklists", &d.blocklists),
        ("BlockedTarget", &d.blocked_target),
        ("Msg", &d.msg),
        ("Extra", &d.extra),
        ("Region", &d.region),
    ] {
        s.set(k, Field::Str(v.clone()));
    }
    s.set("Start", Field::I64(d.start));
    s.set("Latency", Field::F64(d.latency));
    s.set("QType", Field::I64(d.qtype));
    s.set("RCode", Field::I64(d.rcode));
    s.set("RTtl", Field::I64(d.rttl));
    s.set("Status", Field::I32(d.status));
    s.set("Cached", Field::Bool(d.cached));
    s.set("UpstreamBlocks", Field::Bool(d.upstream_blocks));
    s.set("DO", Field::Bool(d.do_bit));
    s.set("AD", Field::Bool(d.ad));
    s.set("ECH", Field::Bool(d.ech));
    s
}

fn flow_summary_struct(f: &FlowSummary) -> Arc<Struct> {
    let s = Struct::new(C_FLOW_SUMMARY);
    for (k, v) in [
        ("Proto", &f.proto),
        ("ID", &f.id),
        ("PID", &f.pid),
        ("RPID", &f.rpid),
        ("UID", &f.uid),
        ("Source", &f.source),
        ("Target", &f.target),
        ("Msg", &f.msg),
    ] {
        s.set(k, Field::Str(v.clone()));
    }
    s.set("Rx", Field::I64(f.rx));
    s.set("Tx", Field::I64(f.tx));
    s.set("Duration", Field::I64(f.duration));
    s.set("Rtt", Field::I64(f.rtt));
    s
}

impl JniBridge {
    fn bind(
        &self,
        name: &'static str,
        who: String,
        addrport: Option<String>,
        fd: i64,
    ) -> BoxFuture<()> {
        let obj = self.obj.clone();
        Box::pin(async move {
            executor()
                .call(Lane::Protect, move |env| {
                    let w = jstr(env, &who);
                    match addrport {
                        Some(a) => {
                            let a = jstr(env, &a);
                            call(
                                env,
                                &obj,
                                name,
                                "(Ljava/lang/String;Ljava/lang/String;J)V",
                                &[JValue::Object(&w), JValue::Object(&a), JValue::Long(fd)],
                            );
                        }
                        None => {
                            call(
                                env,
                                &obj,
                                name,
                                "(Ljava/lang/String;J)V",
                                &[JValue::Object(&w), JValue::Long(fd)],
                            );
                        }
                    }
                })
                .await;
        })
    }

    fn notify(&self, f: impl FnOnce(&mut JNIEnv, &GlobalRef) + Send + 'static) {
        let obj = self.obj.clone();
        executor().post(Lane::Notify, move |env| f(env, &obj));
    }
}

impl Controller for JniBridge {
    fn bind4(&self, who: String, addrport: String, fd: i64) -> BoxFuture<()> {
        self.bind("bind4", who, Some(addrport), fd)
    }
    fn bind6(&self, who: String, addrport: String, fd: i64) -> BoxFuture<()> {
        self.bind("bind6", who, Some(addrport), fd)
    }
    fn protect(&self, who: String, fd: i64) -> BoxFuture<()> {
        self.bind("protect", who, None, fd)
    }
}

impl FlowListener for JniBridge {
    fn preflow(
        &self,
        protocol: i32,
        uid: i32,
        src: String,
        dst: String,
    ) -> BoxFuture<Option<PreMark>> {
        let obj = self.obj.clone();
        Box::pin(async move {
            executor()
                .call(Lane::Flow, move |env| {
                    let (s, d) = (jstr(env, &src), jstr(env, &dst));
                    let sig =
                        format!("(II{SIG_STR}{SIG_STR})Lcom/celzero/firestack/intra/PreMark;");
                    let v = call(
                        env,
                        &obj,
                        "preflow",
                        &sig,
                        &[
                            JValue::Int(protocol),
                            JValue::Int(uid),
                            JValue::Object(&s),
                            JValue::Object(&d),
                        ],
                    );
                    returned_struct(env, v).map(|st| PreMark {
                        uid: st.str("UID"),
                        is_uid_self: st.bool("IsUidSelf"),
                    })
                })
                .await
                .flatten()
        })
    }

    fn flow(&self, a: FlowArgs) -> BoxFuture<Option<Mark>> {
        let obj = self.obj.clone();
        Box::pin(async move {
            executor()
                .call(Lane::Flow, move |env| {
                    let strs: Vec<JObject> = [
                        &a.src,
                        &a.dst,
                        &a.origdsts,
                        &a.domains,
                        &a.probable_domains,
                        &a.blocklists,
                    ]
                    .iter()
                    .map(|s| jstr(env, s))
                    .collect();
                    let sig = format!(
                        "(II{SIG_STR}{SIG_STR}{SIG_STR}{SIG_STR}{SIG_STR}{SIG_STR}Z)L{C_MARK};"
                    );
                    let v = call(
                        env,
                        &obj,
                        "flow",
                        &sig,
                        &[
                            JValue::Int(a.protocol),
                            JValue::Int(a.uid),
                            JValue::Object(&strs[0]),
                            JValue::Object(&strs[1]),
                            JValue::Object(&strs[2]),
                            JValue::Object(&strs[3]),
                            JValue::Object(&strs[4]),
                            JValue::Object(&strs[5]),
                            JValue::Bool(a.dst_is_alg.into()),
                        ],
                    );
                    returned_struct(env, v).map(|s| mark_from(&s))
                })
                .await
                .flatten()
        })
    }

    fn inflow(
        &self,
        _protocol: i32,
        _uid: i32,
        _src: String,
        _dst: String,
    ) -> BoxFuture<Option<Mark>> {
        Box::pin(async { None }) // ingress (WireGuard) arrives in Phase 2
    }

    fn flowing(&self, m: Mark) {
        self.notify(move |env, obj| {
            if let Ok(o) = rt::new_struct_object(env, mark_struct(&m)) {
                call(
                    env,
                    obj,
                    "flowing",
                    &format!("(L{C_MARK};)V"),
                    &[JValue::Object(&o)],
                );
            }
        });
    }

    fn postflow(&self, s: FlowSummary) {
        self.notify(move |env, obj| {
            if let Ok(o) = rt::new_struct_object(env, flow_summary_struct(&s)) {
                call(
                    env,
                    obj,
                    "postflow",
                    &format!("(L{C_FLOW_SUMMARY};)V"),
                    &[JValue::Object(&o)],
                );
            }
        });
    }
}

impl DnsListener for JniBridge {
    fn on_query(
        &self,
        who: String,
        uid: String,
        domain: String,
        qtype: i64,
    ) -> BoxFuture<Option<DnsOpts>> {
        let obj = self.obj.clone();
        Box::pin(async move {
            executor()
                .call(Lane::Dns, move |env| {
                    let (w, u, d) = (jstr(env, &who), jstr(env, &uid), jstr(env, &domain));
                    let sig = format!("({SIG_STR}{SIG_STR}{SIG_STR}J)L{C_DNS_OPTS};");
                    let v = call(
                        env,
                        &obj,
                        "onQuery",
                        &sig,
                        &[
                            JValue::Object(&w),
                            JValue::Object(&u),
                            JValue::Object(&d),
                            JValue::Long(qtype),
                        ],
                    );
                    returned_struct(env, v).map(|s| opts_from(&s))
                })
                .await
                .flatten()
        })
    }

    fn on_upstream_answer(
        &self,
        who: String,
        smm: DnsSummary,
        pref: DnsOpts,
        ipcsv: String,
    ) -> BoxFuture<Option<DnsOpts>> {
        let obj = self.obj.clone();
        Box::pin(async move {
            executor()
                .call(Lane::Dns, move |env| {
                    let w = jstr(env, &who);
                    let ips = jstr(env, &ipcsv);
                    let (Ok(s), Ok(p)) = (
                        rt::new_struct_object(env, summary_struct(&smm)),
                        rt::new_struct_object(env, opts_struct(&pref)),
                    ) else {
                        return None;
                    };
                    let sig = format!(
                        "({SIG_STR}L{C_DNS_SUMMARY};L{C_DNS_OPTS};{SIG_STR})L{C_DNS_OPTS};"
                    );
                    let v = call(
                        env,
                        &obj,
                        "onUpstreamAnswer",
                        &sig,
                        &[
                            JValue::Object(&w),
                            JValue::Object(&s),
                            JValue::Object(&p),
                            JValue::Object(&ips),
                        ],
                    );
                    returned_struct(env, v).map(|s| opts_from(&s))
                })
                .await
                .flatten()
        })
    }

    fn on_response(&self, smm: DnsSummary) {
        self.notify(move |env, obj| {
            if let Ok(o) = rt::new_struct_object(env, summary_struct(&smm)) {
                call(
                    env,
                    obj,
                    "onResponse",
                    &format!("(L{C_DNS_SUMMARY};)V"),
                    &[JValue::Object(&o)],
                );
            }
        });
    }

    fn on_dns_added(&self, id: String) {
        self.notify(move |env, obj| {
            let s = jstr(env, &id);
            call(
                env,
                obj,
                "onDNSAdded",
                "(Ljava/lang/String;)V",
                &[JValue::Object(&s)],
            );
        });
    }

    fn on_dns_removed(&self, id: String) {
        self.notify(move |env, obj| {
            let s = jstr(env, &id);
            call(
                env,
                obj,
                "onDNSRemoved",
                "(Ljava/lang/String;)V",
                &[JValue::Object(&s)],
            );
        });
    }

    fn on_dns_stopped(&self) {
        self.notify(|env, obj| {
            call(env, obj, "onDNSStopped", "()V", &[]);
        });
    }
}

impl ProxyListener for JniBridge {
    fn on_proxy_added(&self, id: String, handle: String) {
        self.proxy_event("onProxyAdded", id, handle)
    }
    fn on_proxy_removed(&self, id: String, handle: String) {
        self.proxy_event("onProxyRemoved", id, handle)
    }
    fn on_proxy_updated(&self, id: String, handle: String) {
        self.proxy_event("onProxyUpdated", id, handle)
    }
    fn on_proxy_stopped(&self, id: String, handle: String) {
        self.proxy_event("onProxyStopped", id, handle)
    }
    fn on_proxies_stopped(&self) {
        self.notify(|env, obj| {
            call(env, obj, "onProxiesStopped", "()V", &[]);
        });
    }
}

impl JniBridge {
    fn proxy_event(&self, name: &'static str, id: String, handle: String) {
        self.notify(move |env, obj| {
            let (i, h) = (jstr(env, &id), jstr(env, &handle));
            call(
                env,
                obj,
                name,
                "(Ljava/lang/String;Ljava/lang/String;)V",
                &[JValue::Object(&i), JValue::Object(&h)],
            );
        });
    }
}
