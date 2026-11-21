// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/log/logger.go (levels, crash output)

//! Minimal logging for the skeleton engine: Android logcat (tag "GoLog", as gomobile uses) and the
//! `Intra.setCrashOutput` file, written in the Go panic format that rethink-app's `ExceptionParser` understands.

use parking_lot::Mutex;
use std::io::Write;
use std::sync::atomic::{AtomicI32, Ordering};

/// firestack log levels: VVERBOSE=0 VERBOSE=1 DEBUG=2 INFO=3 WARN=4 ERROR=5 STACKTRACE=6 USR=7 NONE=8.
pub static LEVEL: AtomicI32 = AtomicI32::new(3);
pub static CONSOLE_LEVEL: AtomicI32 = AtomicI32::new(4);
static CRASH_FILES: Mutex<Vec<String>> = Mutex::new(Vec::new());

#[cfg(target_os = "android")]
mod sys {
    use std::ffi::{CString, c_char, c_int};
    #[link(name = "log")]
    unsafe extern "C" {
        fn __android_log_write(prio: c_int, tag: *const c_char, text: *const c_char) -> c_int;
    }
    pub fn write(prio: i32, msg: &str) {
        let tag = c"GoLog";
        if let Ok(text) = CString::new(msg.replace('\0', " ")) {
            // SAFETY: valid NUL-terminated strings.
            unsafe { __android_log_write(prio, tag.as_ptr(), text.as_ptr()) };
        }
    }
}
#[cfg(not(target_os = "android"))]
mod sys {
    pub fn write(prio: i32, msg: &str) {
        eprintln!("[GoLog/{prio}] {msg}");
    }
}

fn emit(level: i32, prio: i32, msg: &str) {
    if level >= LEVEL.load(Ordering::Relaxed) {
        sys::write(prio, msg);
    }
    if level >= CONSOLE_LEVEL.load(Ordering::Relaxed) {
        crate::impls::console::write(level, msg);
    }
}

// android/log.h priorities: DEBUG=3 INFO=4 WARN=5 ERROR=6
pub fn debug(msg: &str) {
    emit(2, 3, msg)
}
pub fn info(msg: &str) {
    emit(3, 4, msg)
}
pub fn warn(msg: &str) {
    emit(4, 5, msg)
}
pub fn error(msg: &str) {
    emit(5, 6, msg)
}

pub fn set_crash_outputs(files: Vec<String>) {
    *CRASH_FILES.lock() = files;
}

/// Records a contained panic. Uses Go's panic text format (`panic: …` + `goroutine N [running]:`) so that the
/// app's bug-report parser (`util/ExceptionParser.kt`) recognises it.
pub fn crash(where_: &str, msg: &str) {
    let bt = std::backtrace::Backtrace::force_capture();
    let report =
        format!("{where_} <===> panic: {msg}\n\ngoroutine 1 [running]:\n{where_}(...)\n{bt}\n");
    sys::write(6, &report);
    for f in CRASH_FILES.lock().iter().filter(|f| !f.is_empty()) {
        if let Ok(mut fh) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(f)
        {
            let _ = fh.write_all(report.as_bytes());
        }
    }
}
