// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/tunnel.go (Stat)
// Derived-From: celzero/firestack@d3d530ea3e:intra/netstat/ (NetStat structs)

//! `Tunnel.stat()` and the `NetStat` accessors. firestack fills these from gVisor's stack counters; here they carry
//! what this engine tracks (TUN traffic, open connections, link and resolver state); the remaining counters read 0.

use crate::impls::tunnel::TunnelRef;
use crate::rt::{self, Field, FsError, FsResult, Struct};
use fs_core::settings;
use jni::JNIEnv;
use jni::objects::JObject;
use std::sync::atomic::Ordering;

const C_NETSTAT: &str = "com/celzero/firestack/backend/NetStat";
const C_NICINFO: &str = "com/celzero/firestack/backend/NICInfo";
const C_TUN: &str = "com/celzero/firestack/backend/TUNStat";
const C_RDNS: &str = "com/celzero/firestack/backend/RDNSInfo";
const C_NIC: &str = "com/celzero/firestack/backend/NICStat";
const C_TCP: &str = "com/celzero/firestack/backend/TCPStat";
const C_UDP: &str = "com/celzero/firestack/backend/UDPStat";
const C_IP: &str = "com/celzero/firestack/backend/IPStat";
const C_ICMP: &str = "com/celzero/firestack/backend/ICMPStat";
const C_FWD: &str = "com/celzero/firestack/backend/IPFwdStat";

fn s(v: impl Into<String>) -> Field {
    Field::Str(v.into())
}

/// `Tunnel.stat()`
pub fn t_stat<'l>(env: &mut JNIEnv<'l>, this: &JObject) -> FsResult<JObject<'l>> {
    let t = rt::obj_of::<TunnelRef>(env, this)?.0.clone();
    if !t.is_connected() {
        return Err(FsError::new("tunnel closed"));
    }
    let n = t.net_stat();
    let ld = |a: &std::sync::atomic::AtomicBool| a.load(Ordering::Relaxed);

    let nicinfo = Struct::new(C_NICINFO);
    nicinfo.set("Name", s("tun"));
    nicinfo.set("Mtu", Field::I32(n.mtu));
    nicinfo.set("Up", Field::Bool(n.up));
    nicinfo.set("Running", Field::Bool(n.up));
    nicinfo.set("Addrs", s(n.l3.clone()));

    let tun = Struct::new(C_TUN);
    tun.set("Open", Field::Bool(n.open));
    tun.set("Up", Field::Bool(n.up));
    tun.set("Mtu", Field::I32(n.mtu));
    tun.set("PcapMode", s(n.pcap.clone()));
    tun.set(
        "EpStats",
        s(format!(
            "rx: {}B/{}p, tx: {}B/{}p, errs: {}",
            n.rx_bytes, n.rx_pkts, n.tx_bytes, n.tx_pkts, n.errs
        )),
    );

    let nic = Struct::new(C_NIC);
    nic.set("Rx", s(format!("{}", n.rx_bytes)));
    nic.set("RxPkts", Field::I64(n.rx_pkts));
    nic.set("Tx", s(format!("{}", n.tx_bytes)));
    nic.set("TxPkts", Field::I64(n.tx_pkts));
    nic.set("Invalid", Field::I64(n.errs));

    let tcp = Struct::new(C_TCP);
    tcp.set("Est", Field::I64(n.tcp_open));
    tcp.set("Active", Field::I64(n.tcp_open));

    let rdns = Struct::new(C_RDNS);
    rdns.set("Open", Field::Bool(n.open));
    rdns.set("DNS", s(n.dns.clone()));
    rdns.set("DNS64Pfx", s(n.dns64.clone()));
    rdns.set("ALG", s(if n.alg { "on" } else { "off" }));
    rdns.set("LinkMTU", s(n.link_mtu.to_string()));
    rdns.set("OpenConnsTCP", s(n.tcp_open.to_string()));
    rdns.set("OpenConnsUDP", s(n.udp_open.to_string()));
    rdns.set("OpenConnsICMP", s("0"));
    rdns.set("Proxies", s(n.proxies.clone()));
    rdns.set("ProxiesHas4", Field::Bool(n.proxies4));
    rdns.set("ProxiesHas6", Field::Bool(n.proxies6));
    rdns.set("Debug", Field::Bool(ld(&settings::DEBUG)));
    rdns.set("Looping", Field::Bool(ld(&settings::LOOPINGBACK)));
    rdns.set(
        "HappyEyeballs",
        Field::Bool(ld(&settings::SUPPORT_HAPPY_EYEBALLS)),
    );
    rdns.set(
        "SystemDNSForUndelegated",
        Field::Bool(ld(&settings::SYSTEM_DNS_FOR_UNDELEGATED_DOMAINS)),
    );
    rdns.set(
        "DefaultDNSAsFallback",
        Field::Bool(ld(&settings::DEFAULT_DNS_AS_FALLBACK)),
    );
    rdns.set("OwnTunFd", Field::Bool(ld(&settings::OWN_TUN_FD)));
    rdns.set(
        "AutoDialsParallel",
        Field::Bool(ld(&settings::AUTO_DIALS_PARALLEL)),
    );
    rdns.set(
        "Transparency",
        Field::Bool(ld(&settings::ENDPOINT_INDEPENDENT_MAPPING)),
    );
    rdns.set(
        "EIMEIF",
        s(format!(
            "{}/{}",
            ld(&settings::ENDPOINT_INDEPENDENT_MAPPING),
            ld(&settings::ENDPOINT_INDEPENDENT_FILTERING)
        )),
    );
    rdns.set(
        "AutoMode",
        s(settings::AUTO_MODE.load(Ordering::Relaxed).to_string()),
    );
    rdns.set(
        "TunMode",
        s(format!(
            "{}; {}; {}",
            settings::mode2string("dns", settings::DNS_MODE.load(Ordering::Relaxed)),
            settings::mode2string("block", settings::BLOCK_MODE.load(Ordering::Relaxed)),
            settings::mode2string("pt", settings::PT_MODE.load(Ordering::Relaxed))
        )),
    );
    rdns.set("Dialer4", Field::Bool(n.l3.contains('4')));
    rdns.set("Dialer6", Field::Bool(n.l3.contains('6')));

    let ns = Struct::new(C_NETSTAT);
    for (k, c, v) in [
        ("NICInfo", C_NICINFO, nicinfo),
        ("TUNSt", C_TUN, tun),
        ("RDNSIn", C_RDNS, rdns),
        ("NICSt", C_NIC, nic),
        ("TCPSt", C_TCP, tcp),
        ("UDPSt", C_UDP, Struct::new(C_UDP)),
        ("IPSt", C_IP, Struct::new(C_IP)),
        ("ICMPSt", C_ICMP, Struct::new(C_ICMP)),
        ("FWDSt", C_FWD, Struct::new(C_FWD)),
    ] {
        ns.set(k, Field::Obj(c, v));
    }
    rt::new_struct_object(env, ns)
}

fn sub<'l>(env: &mut JNIEnv<'l>, this: &JObject, key: &str) -> FsResult<JObject<'l>> {
    let ns = rt::struct_of(env, this)?;
    match ns.get(key) {
        Field::Obj(_, o) => match o.downcast::<Struct>() {
            Ok(st) => rt::new_struct_object(env, st),
            Err(_) => Ok(JObject::null()),
        },
        _ => Ok(JObject::null()),
    }
}

pub fn ns_nicinfo<'l>(env: &mut JNIEnv<'l>, this: &JObject) -> FsResult<JObject<'l>> {
    sub(env, this, "NICInfo")
}
pub fn ns_tun<'l>(env: &mut JNIEnv<'l>, this: &JObject) -> FsResult<JObject<'l>> {
    sub(env, this, "TUNSt")
}
pub fn ns_rdnsinfo<'l>(env: &mut JNIEnv<'l>, this: &JObject) -> FsResult<JObject<'l>> {
    sub(env, this, "RDNSIn")
}
pub fn ns_nic<'l>(env: &mut JNIEnv<'l>, this: &JObject) -> FsResult<JObject<'l>> {
    sub(env, this, "NICSt")
}
pub fn ns_tcp<'l>(env: &mut JNIEnv<'l>, this: &JObject) -> FsResult<JObject<'l>> {
    sub(env, this, "TCPSt")
}
pub fn ns_udp<'l>(env: &mut JNIEnv<'l>, this: &JObject) -> FsResult<JObject<'l>> {
    sub(env, this, "UDPSt")
}
pub fn ns_ip<'l>(env: &mut JNIEnv<'l>, this: &JObject) -> FsResult<JObject<'l>> {
    sub(env, this, "IPSt")
}
pub fn ns_icmp<'l>(env: &mut JNIEnv<'l>, this: &JObject) -> FsResult<JObject<'l>> {
    sub(env, this, "ICMPSt")
}
pub fn ns_fwd<'l>(env: &mut JNIEnv<'l>, this: &JObject) -> FsResult<JObject<'l>> {
    sub(env, this, "FWDSt")
}
