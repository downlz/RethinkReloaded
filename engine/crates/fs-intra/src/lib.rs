// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! The tunnel: TUN + netstack + resolver + flow handlers, wired to Kotlin through the Bridge.

pub mod flow;
pub mod tcp;
pub mod tunnel;
pub mod udp;

pub use tunnel::{DefaultDnsSpec, Tunnel};

use std::sync::OnceLock;
use tokio::runtime::Runtime;

/// The engine's async runtime: two workers keep wakeups and memory low on phones (DNS, dials, relays are
/// I/O-bound). Created on first use.
pub fn runtime() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(8)
            .thread_name("fs-io")
            .thread_stack_size(512 * 1024)
            .enable_all()
            .build()
            .expect("tokio runtime")
    })
}
