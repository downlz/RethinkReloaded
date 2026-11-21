// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/tun2socks.go (GoMet, PrintStack, Crash, CPUProfile, MemProfile,
// SetFlightRecordOutput)

//! Diagnostics for bug reports. firestack exposes Go's runtime (memstats, goroutine dumps, pprof profiles, the
//! flight recorder); there is no Go runtime here, so these report the process instead: memory and threads from
//! /proc, the engine's threads with a backtrace of the caller, and text "profiles" that capture the same.

use crate::rt::{self, Field, FsError, FsResult, Struct};
use jni::JNIEnv;
use jni::objects::JObject;
use parking_lot::Mutex;
use std::io::Write;
use std::time::{Duration, Instant};

const C_GOMETRICS: &str = "com/celzero/firestack/backend/GoMetrics";
const C_GOSTAT: &str = "com/celzero/firestack/backend/GoStat";

static FLIGHT: Mutex<String> = Mutex::new(String::new());

fn read(p: &str) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}

/// `key:  value` lines of /proc/self/status.
fn status(key: &str) -> String {
    read("/proc/self/status")
        .lines()
        .find_map(|l| {
            l.strip_prefix(key)
                .and_then(|r| r.strip_prefix(':'))
                .map(|v| v.trim().to_string())
        })
        .unwrap_or_default()
}

/// The engine's threads: name and state, from /proc/self/task.
fn threads() -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Ok(d) = std::fs::read_dir("/proc/self/task") {
        for e in d.flatten() {
            let p = e.path();
            let name = read(&format!("{}/comm", p.display())).trim().to_string();
            let state = read(&format!("{}/status", p.display()))
                .lines()
                .find_map(|l| l.strip_prefix("State:").map(|v| v.trim().to_string()))
                .unwrap_or_default();
            out.push((name, state));
        }
    }
    out
}

fn report() -> String {
    let mut s = String::new();
    for k in [
        "VmRSS",
        "VmHWM",
        "VmSize",
        "RssAnon",
        "RssFile",
        "VmSwap",
        "Threads",
        "voluntary_ctxt_switches",
        "nonvoluntary_ctxt_switches",
    ] {
        s.push_str(&format!("{k}: {}\n", status(k)));
    }
    s.push_str(&read("/proc/self/smaps_rollup"));
    s
}

/// `Intra.goMet()`
pub fn go_met<'l>(env: &mut JNIEnv<'l>) -> FsResult<JObject<'l>> {
    let g = Struct::new(C_GOSTAT);
    g.set("Alloc", Field::Str(status("RssAnon")));
    g.set("Sys", Field::Str(status("VmRSS")));
    g.set("HeapSys", Field::Str(status("VmSize")));
    g.set("StackSys", Field::Str(status("VmStk")));
    let ts = threads();
    g.set("NumGoroutine", Field::I64(ts.len() as i64));
    g.set(
        "NumCPU",
        Field::I64(
            std::thread::available_parallelism()
                .map(|n| n.get() as i64)
                .unwrap_or(1),
        ),
    );
    g.set("EnableGC", Field::Bool(false));
    // SAFETY: getpid/getuid/sysconf are always safe.
    let (pid, uid, pg) = unsafe {
        (
            libc::getpid(),
            libc::getuid(),
            libc::sysconf(libc::_SC_PAGESIZE),
        )
    };
    g.set("Args", Field::Str(format!("uid={uid};pid={pid};pgsz={pg}")));
    g.set("Trac", Field::Str("rust (no go runtime)".into()));
    g.set(
        "Pers",
        Field::Str(
            std::env::current_exe()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
        ),
    );
    let m = Struct::new(C_GOMETRICS);
    m.set("G", Field::Obj(C_GOSTAT, g));
    m.set(
        "M",
        Field::Str(format!(
            "threads: {}",
            ts.iter()
                .map(|(n, s)| format!("{n}({})", s.split_whitespace().next().unwrap_or("?")))
                .collect::<Vec<_>>()
                .join(" ")
        )),
    );
    m.set(
        "C",
        Field::Str(format!(
            "rss: {}, ctxsw: {}/{}",
            status("VmRSS"),
            status("voluntary_ctxt_switches"),
            status("nonvoluntary_ctxt_switches")
        )),
    );
    m.set(
        "L",
        Field::Str(format!(
            "log level: {}, console level: {}",
            crate::impls::log::LEVEL.load(std::sync::atomic::Ordering::Relaxed),
            crate::impls::log::CONSOLE_LEVEL.load(std::sync::atomic::Ordering::Relaxed)
        )),
    );
    rt::new_struct_object(env, m)
}

/// `GoMetrics.go()`
pub fn gm_go<'l>(env: &mut JNIEnv<'l>, this: &JObject) -> FsResult<JObject<'l>> {
    let m = rt::struct_of(env, this)?;
    match m.get("G") {
        Field::Obj(_, o) => match o.downcast::<Struct>() {
            Ok(g) => rt::new_struct_object(env, g),
            Err(_) => Ok(JObject::null()),
        },
        _ => Ok(JObject::null()),
    }
}

fn stack_text() -> String {
    let mut s = String::from("rust engine threads (not a crash):\n");
    for (n, st) in threads() {
        s.push_str(&format!("  {n}: {st}\n"));
    }
    s.push_str("\ncaller:\n");
    s.push_str(&std::backtrace::Backtrace::force_capture().to_string());
    s
}

/// `Intra.printStack(where)`: 0 to logcat, 1 to the console, otherwise returned.
pub fn print_stack(_env: &mut JNIEnv, where_: i32) -> FsResult<Vec<u8>> {
    let s = stack_text();
    match where_ {
        0 => {
            crate::impls::log::info(&s);
            Ok(Vec::new())
        }
        1 => {
            crate::impls::console::write(6, &s);
            Ok(Vec::new())
        }
        _ => Ok(s.into_bytes()),
    }
}

/// `Intra.crash(typ, afterMs)` (testing): after `afterMs`, 0 aborts with the report on stderr, 1 reports to the
/// console and carries on, 2 reports to the console and aborts.
pub fn crash(_env: &mut JNIEnv, typ: i64, after_ms: i64) -> FsResult<()> {
    std::thread::spawn(move || {
        crate::impls::log::info(&format!("tun: debug: crashing in {after_ms}ms"));
        std::thread::sleep(Duration::from_millis(after_ms.max(0) as u64));
        let msg = format!("tun: debugging... not a crash\n{}", stack_text());
        match typ {
            1 => crate::impls::console::write(6, &msg),
            2 => {
                crate::impls::console::write(6, &msg);
                crate::impls::log::crash("debug", &msg);
                std::thread::sleep(Duration::from_millis(500)); // let the console drain
                std::process::abort();
            }
            _ => {
                eprintln!("{msg}");
                crate::impls::log::crash("debug", &msg);
                std::process::abort();
            }
        }
    });
    Ok(())
}

/// `Intra.setFlightRecordOutput(path)`: remembered (there is no flight recorder); returns the previous path.
pub fn set_flight_record_output(_env: &mut JNIEnv, path: String) -> FsResult<String> {
    if !path.is_empty() {
        std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&path)
            .map_err(|e| FsError::new(format!("flight recorder: {path}: {e}")))?;
    }
    Ok(std::mem::replace(&mut *FLIGHT.lock(), path))
}

/// `Intra.memProfile(rate, path)`: a text snapshot of the process' memory (no heap profiler).
pub fn mem_profile(_env: &mut JNIEnv, rate: i32, path: String) -> FsResult<()> {
    if rate == 0 {
        return Ok(());
    }
    std::fs::write(
        &path,
        format!(
            "rethinkreloaded rust engine: memory snapshot\n\n{}",
            report()
        ),
    )
    .map_err(|e| FsError::new(format!("memprofile: {path}: {e}")))
}

/// CPU seconds (user + system) of the process, from /proc/self/stat.
fn cpu_ticks() -> u64 {
    let s = read("/proc/self/stat");
    // fields after the parenthesized comm: state is 3rd; utime 14th, stime 15th (1-based)
    let rest = s.rsplit_once(')').map(|(_, r)| r).unwrap_or_default();
    let f: Vec<&str> = rest.split_whitespace().collect();
    let p = |i: usize| f.get(i).and_then(|x| x.parse::<u64>().ok()).unwrap_or(0);
    p(11) + p(12)
}

/// `Intra.cpuProfile(path, flightrecorder, secs)`: samples the process' CPU time over `secs` (10..120, as
/// firestack) into a text report; returns the seconds sampled.
pub fn cpu_profile(_env: &mut JNIEnv, path: String, _flight: String, secs: i32) -> FsResult<i32> {
    let secs = secs.clamp(10, 120);
    let (t0, c0) = (Instant::now(), cpu_ticks());
    let mut lines = Vec::new();
    for _ in 0..secs {
        std::thread::sleep(Duration::from_secs(1));
        lines.push(format!(
            "{:>4}s cpu ticks {}",
            t0.elapsed().as_secs(),
            cpu_ticks() - c0
        ));
    }
    let ran = t0.elapsed().as_secs() as i32;
    let mut f = std::fs::File::create(&path)
        .map_err(|e| FsError::new(format!("cpuprofile: {path}: {e}")))?;
    let _ = writeln!(
        f,
        "rethinkreloaded rust engine: cpu sampling ({ran}s; ticks are 1/100 s)\n"
    );
    let _ = writeln!(f, "{}\n\n{}", lines.join("\n"), stack_text());
    Ok(ran)
}
