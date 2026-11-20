// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/dnsx/transport.go (Transport interface, types, statuses)

//! The DNS transport abstraction (`backend.DNSTransport` on the Kotlin side).

use fs_core::bridge::{BoxFuture, dns_status};
use parking_lot::Mutex;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Duration;

/// Transport type strings (backend constants).
pub const TYPE_DOH: &str = "DNS-over-HTTPS";
pub const TYPE_DNS53: &str = "DNS";
pub const TYPE_DOT: &str = "DNS-over-TLS";
pub const TYPE_DNSCRYPT: &str = "DNSCrypt";
pub const TYPE_ODOH: &str = "Oblivious DNS-over-HTTPS";

/// A successful upstream exchange.
#[derive(Debug, Clone)]
pub struct Answer {
    /// wire-format response (with the caller's query id restored)
    pub msg: Vec<u8>,
    /// server address or hostname, for `DNSSummary.Server`
    pub server: String,
    /// proxy used
    pub pid: String,
    pub latency: Duration,
}

/// A failed exchange, with the `DNSSummary.Status` it maps to.
#[derive(Debug, Clone)]
pub struct QueryError {
    pub status: i32,
    pub msg: String,
    pub server: String,
}

impl QueryError {
    pub fn new(status: i32, msg: impl Into<String>) -> Self {
        QueryError {
            status,
            msg: msg.into(),
            server: String::new(),
        }
    }
}

pub trait Transport: Send + Sync {
    fn id(&self) -> &str;
    fn typ(&self) -> &str;
    /// address shown to the user (`DNSTransport.getAddr`)
    fn addr(&self) -> String;
    /// last query status (`DNSTransport.status`)
    fn status(&self) -> i32;
    /// p50 latency estimate in millis (`DNSTransport.p50`)
    fn p50(&self) -> i64;
    /// Sends `q` (wire format) via proxy `pid`.
    fn query(self: Arc<Self>, q: Vec<u8>, pid: String) -> BoxFuture<Result<Answer, QueryError>>;
}

/// Shared bookkeeping for status and latency (a cheap moving p50 estimate).
pub struct Stats {
    status: AtomicI32,
    p50: Mutex<f64>,
}

impl Default for Stats {
    fn default() -> Self {
        Stats {
            status: AtomicI32::new(dns_status::START),
            p50: Mutex::new(0.0),
        }
    }
}

impl Stats {
    pub fn status(&self) -> i32 {
        self.status.load(Ordering::Relaxed)
    }
    pub fn p50(&self) -> i64 {
        *self.p50.lock() as i64
    }
    pub fn ok(&self, latency: Duration) {
        self.status.store(dns_status::COMPLETE, Ordering::Relaxed);
        let ms = latency.as_secs_f64() * 1e3;
        let mut p = self.p50.lock();
        // stochastic median estimate: step towards the sample
        *p = if *p == 0.0 {
            ms
        } else if ms > *p {
            *p + (*p * 0.05).max(1.0).min(ms - *p)
        } else {
            *p - (*p * 0.05).max(1.0).min(*p - ms)
        };
    }
    pub fn err(&self, status: i32) {
        self.status.store(status, Ordering::Relaxed);
    }
}
