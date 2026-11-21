// Copyright (c) 2026 RethinkReloaded contributors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! A logging hook for engine crates: `fs-jni` installs its logcat writer at load; elsewhere (host tests, tools)
//! messages go to stderr when `RR_LOG` is set and are dropped otherwise.

use std::sync::OnceLock;

/// levels as `fs-jni`'s logger: 2 debug, 3 info, 4 warn, 5 error
pub type Sink = fn(level: i32, msg: &str);

static SINK: OnceLock<Sink> = OnceLock::new();

pub fn set_sink(s: Sink) {
    let _ = SINK.set(s);
}

pub fn log(level: i32, msg: &str) {
    match SINK.get() {
        Some(s) => s(level, msg),
        None if std::env::var_os("RR_LOG").is_some() => eprintln!("[{level}] {msg}"),
        None => {}
    }
}

pub fn debug(msg: &str) {
    log(2, msg)
}
pub fn info(msg: &str) {
    log(3, msg)
}
pub fn warn(msg: &str) {
    log(4, msg)
}
