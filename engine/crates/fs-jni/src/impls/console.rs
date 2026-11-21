// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2025 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/log/memconsole.go
// Derived-From: celzero/firestack@d3d530ea3e:intra/tun2socks.go (SetupConsole)

//! Engine logs to Kotlin's console (`Intra.setupConsole`). Preferred: firestack's memfd double buffer, handed over
//! once via `Console.logMemFD(fd1, fd2, size, slotsize)`; each region is an 8-byte little-endian slot count followed
//! by 801-byte slots (a two-character level prefix, the message, `\n`, zeros). A full region, or one holding lines for
//! 2.5 s, is drained (`LogConsumer.drain(fd, 8, 8 + n*801)`) while the other takes new lines; when both are busy the
//! active one is overwritten. Without memfd (older kernels) or a consumer, each line goes through `Console.log`.

use crate::cbexec::{Lane, executor};
use jni::objects::{GlobalRef, JValue};
use parking_lot::{Condvar, Mutex};
use std::sync::OnceLock;
use std::time::Duration;

const HDR: usize = 8;
const SLOT: usize = 801;
const PAGES: usize = 16;
const FLUSH_AFTER: Duration = Duration::from_millis(2500);

struct Region {
    fd: i32,
    ptr: *mut u8,
    len: usize,
}
// SAFETY: the mapping is only written under `Mem::st`, and only read by Kotlin (pread) while drained.
unsafe impl Send for Region {}
unsafe impl Sync for Region {}

impl Region {
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn new(_: usize) -> Option<Region> {
        None // memfd is Linux-only
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn new(len: usize) -> Option<Region> {
        // SAFETY: plain syscalls; results checked.
        unsafe {
            let fd = libc::syscall(
                libc::SYS_memfd_create,
                c"rr-console".as_ptr(),
                libc::MFD_CLOEXEC,
            ) as i32;
            if fd < 0 {
                return None;
            }
            if libc::ftruncate(fd, len as libc::off_t) != 0 {
                libc::close(fd);
                return None;
            }
            let p = libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            );
            if p == libc::MAP_FAILED {
                libc::close(fd);
                return None;
            }
            Some(Region {
                fd,
                ptr: p as *mut u8,
                len,
            })
        }
    }
    #[allow(clippy::mut_from_ref)] // a shared mapping: writes are serialized by the console lock
    fn bytes(&self) -> &mut [u8] {
        // SAFETY: a live mapping of `len` bytes, written under the console lock.
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
    fn set_count(&self, n: usize) {
        self.bytes()[..HDR].copy_from_slice(&(n as u64).to_le_bytes());
    }
}

struct State {
    active: usize,
    slot: usize,
    /// a region to drain: (index, slots)
    pending: Option<(usize, usize)>,
    draining: [bool; 2],
}

struct Mem {
    regions: [Region; 2],
    slots: usize,
    st: Mutex<State>,
    cv: Condvar,
    consumer: GlobalRef,
}

enum Sink {
    Mem(&'static Mem),
    Calls(GlobalRef),
}

static SINK: OnceLock<Sink> = OnceLock::new();
thread_local! {
    /// guards against re-entry from a log within the console path (per thread: other threads keep logging)
    static BUSY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn prefix(level: i32) -> &'static [u8] {
    match level {
        ..=1 => b"V ",
        2 => b"D ",
        3 => b"I ",
        4 => b"W ",
        _ => b"E ",
    }
}

impl Mem {
    fn write(&self, level: i32, msg: &str) {
        let mut st = self.st.lock();
        if st.slot >= self.slots {
            let other = st.active ^ 1;
            if st.pending.is_none() && !st.draining[other] {
                let (a, n) = (st.active, st.slot);
                self.regions[a].set_count(n);
                st.pending = Some((a, n));
                st.active = other;
                st.slot = 0;
                self.cv.notify_one();
            } else {
                st.slot = 0; // both regions busy: overwrite the active one (firestack overwriteOnFull)
            }
        }
        let r = &self.regions[st.active];
        fill_slot(
            &mut r.bytes()[HDR + st.slot * SLOT..HDR + (st.slot + 1) * SLOT],
            level,
            msg,
        );
        let was_empty = st.slot == 0;
        st.slot += 1;
        r.set_count(st.slot);
        if was_empty {
            self.cv.notify_one(); // starts the lazy flush timer
        }
    }

    /// Drains full regions at once and partial ones after [`FLUSH_AFTER`]; blocks (no wakeups) while idle.
    fn flusher(&'static self) {
        loop {
            let (idx, n) = {
                let mut st = self.st.lock();
                while st.pending.is_none() && st.slot == 0 {
                    self.cv.wait(&mut st);
                }
                if st.pending.is_none() {
                    let timed_out = self.cv.wait_for(&mut st, FLUSH_AFTER).timed_out();
                    if st.pending.is_none() && st.slot > 0 && (timed_out || st.slot >= self.slots) {
                        let other = st.active ^ 1;
                        if !st.draining[other] {
                            let (a, n) = (st.active, st.slot);
                            self.regions[a].set_count(n);
                            st.pending = Some((a, n));
                            st.active = other;
                            st.slot = 0;
                        }
                    }
                }
                let Some(p) = st.pending.take() else { continue };
                st.draining[p.0] = true;
                p
            };
            let (fd, end) = (self.regions[idx].fd as i64, (HDR + n * SLOT) as i64);
            let consumer = self.consumer.clone();
            executor().call_blocking(Lane::Notify, move |env| {
                let r = env.call_method(
                    consumer.as_obj(),
                    "drain",
                    "(JJJ)J",
                    &[
                        JValue::Long(fd),
                        JValue::Long(HDR as i64),
                        JValue::Long(end),
                    ],
                );
                if r.is_err() {
                    let _ = env.exception_clear();
                }
            });
            self.st.lock().draining[idx] = false;
        }
    }
}

/// `Intra.setupConsole(console)`: sets up the memfd console once (firestack refuses a second setup).
pub fn setup(console: GlobalRef) {
    if SINK.get().is_some() {
        return;
    }
    let slots = PAGES * page_size() / SLOT;
    let len = HDR + slots * SLOT;
    let mem = match (Region::new(len), Region::new(len)) {
        (Some(a), Some(b)) => Some([a, b]),
        _ => None,
    };
    let sink = match mem {
        None => Sink::Calls(console),
        Some(regions) => {
            let (fa, fb) = (regions[0].fd as i64, regions[1].fd as i64);
            let c = console.clone();
            let consumer = executor()
                .call_blocking(Lane::Notify, move |env| {
                    let o = env
                        .call_method(
                            c.as_obj(),
                            "logMemFD",
                            "(JJJJ)Lcom/celzero/firestack/backend/LogConsumer;",
                            &[
                                JValue::Long(fa),
                                JValue::Long(fb),
                                JValue::Long(len as i64),
                                JValue::Long(SLOT as i64),
                            ],
                        )
                        .and_then(|v| v.l());
                    match o {
                        Ok(o) if !o.is_null() => env.new_global_ref(o).ok(),
                        _ => {
                            let _ = env.exception_clear();
                            None
                        }
                    }
                })
                .flatten();
            match consumer {
                Some(consumer) => {
                    let m: &'static Mem = Box::leak(Box::new(Mem {
                        regions,
                        slots,
                        st: Mutex::new(State {
                            active: 0,
                            slot: 0,
                            pending: None,
                            draining: [false; 2],
                        }),
                        cv: Condvar::new(),
                        consumer,
                    }));
                    let _ = std::thread::Builder::new()
                        .name("rr-console".into())
                        .spawn(move || m.flusher());
                    Sink::Mem(m)
                }
                None => Sink::Calls(console),
            }
        }
    };
    let _ = SINK.set(sink);
}

/// One slot: the level prefix, the message (truncated to fit), `\n`, zeros.
fn fill_slot(slot: &mut [u8], level: i32, msg: &str) {
    slot[..2].copy_from_slice(prefix(level));
    let body = msg.as_bytes();
    let n = body.len().min(SLOT - 3);
    slot[2..2 + n].copy_from_slice(&body[..n]);
    slot[2 + n] = b'\n';
    slot[3 + n..].fill(0);
}

fn page_size() -> usize {
    // SAFETY: sysconf is always safe to call.
    let p = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if p > 0 { p as usize } else { 4096 }
}

/// A line for Kotlin's console (already filtered by the console level).
pub fn write(level: i32, msg: &str) {
    if BUSY.with(|b| b.replace(true)) {
        return;
    }
    match SINK.get() {
        Some(Sink::Mem(m)) => m.write(level, msg),
        Some(Sink::Calls(c)) => {
            let (c, msg) = (c.clone(), msg.to_string());
            executor().post(Lane::Notify, move |env| {
                if let Ok(s) = env.new_string(&msg) {
                    let _ = env.call_method(
                        c.as_obj(),
                        "log",
                        "(ILjava/lang/String;)V",
                        &[JValue::Int(level), JValue::Object(&s)],
                    );
                    let _ = env.exception_clear();
                }
            });
        }
        None => {}
    }
    BUSY.with(|b| b.set(false));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_layout() {
        let mut slot = vec![0xffu8; SLOT];
        fill_slot(&mut slot, 4, "hello");
        assert_eq!(&slot[..8], b"W hello\n");
        assert!(slot[8..].iter().all(|x| *x == 0), "zero tail");
        let long = "x".repeat(2000);
        fill_slot(&mut slot, 3, &long);
        assert_eq!(&slot[..2], b"I ");
        assert_eq!(slot[SLOT - 1], b'\n', "truncated to one slot");
        assert_eq!(
            16 * 4096 / SLOT,
            81,
            "slots per region on 4 KiB pages, as firestack"
        );
    }
}
