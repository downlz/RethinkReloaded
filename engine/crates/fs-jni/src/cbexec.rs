// Copyright (c) 2026 RethinkReloaded contributors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Callback executor: runs upcalls into Kotlin (Bridge / Controller / Console) on dedicated, permanently
//! JVM-attached daemon threads, never on the async runtime's workers (Kotlin blocks inside callbacks with
//! `runBlocking`, so an upcall on a tokio worker could stall the whole engine).
//!
//! Lanes keep latency-critical work (socket protection) from queueing behind slower work (flow decisions, DNS
//! policy, notifications). Each lane starts with `min` threads and adds one (up to `max`) whenever a job arrives
//! while no thread is idle; extra threads exit after [`IDLE_EXIT`] without work. Every job runs inside a JNI local frame so
//! local references never accumulate on these long-lived native threads.

use crate::impls::seq;
use crossbeam_channel::{Receiver, Sender, unbounded};
use jni::JNIEnv;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

pub const IDLE_EXIT: Duration = Duration::from_secs(30);
const LOCAL_FRAME: i32 = 64;
const STACK: usize = 512 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lane {
    /// Controller.protect / bind4 / bind6: on the dial path of every connection.
    Protect,
    /// Bridge.preflow / flow / inflow: on the setup path of every connection.
    Flow,
    /// DNS policy: onPrequery / onQuery / onUpstreamAnswer.
    Dns,
    /// Fire-and-forget notifications: postflow, flowing, onResponse, onProxy*, onDNS*, console logs.
    Notify,
}

type Job = Box<dyn FnOnce(&mut JNIEnv) + Send>;

struct Pool {
    name: &'static str,
    tx: Sender<(Instant, Job)>,
    rx: Receiver<(Instant, Job)>,
    threads: AtomicUsize,
    idle: AtomicUsize,
    min: usize,
    max: usize,
}

impl Pool {
    fn new(name: &'static str, min: usize, max: usize) -> Arc<Self> {
        let (tx, rx) = unbounded();
        let p = Arc::new(Pool {
            name,
            tx,
            rx,
            threads: AtomicUsize::new(0),
            idle: AtomicUsize::new(0),
            min,
            max,
        });
        for _ in 0..min {
            p.spawn();
        }
        p
    }

    fn spawn(self: &Arc<Self>) {
        let n = self.threads.fetch_add(1, Ordering::SeqCst);
        if n >= self.max {
            self.threads.fetch_sub(1, Ordering::SeqCst);
            return;
        }
        let me = self.clone();
        let spawned = std::thread::Builder::new()
            .name(format!("fs-cb-{}-{n}", me.name))
            .stack_size(STACK)
            .spawn(move || me.run());
        if spawned.is_err() {
            self.threads.fetch_sub(1, Ordering::SeqCst);
        }
    }

    fn run(self: Arc<Self>) {
        let Some(vm) = seq::vm() else {
            self.threads.fetch_sub(1, Ordering::SeqCst);
            return;
        };
        // attached once, for the thread's lifetime; daemon threads do not block JVM shutdown
        let Ok(mut env) = vm.attach_current_thread_as_daemon() else {
            self.threads.fetch_sub(1, Ordering::SeqCst);
            return;
        };
        loop {
            self.idle.fetch_add(1, Ordering::SeqCst);
            let got = self.rx.recv_timeout(IDLE_EXIT);
            self.idle.fetch_sub(1, Ordering::SeqCst);
            match got {
                Ok((_enqueued, job)) => {
                    if env.push_local_frame(LOCAL_FRAME).is_ok() {
                        job(&mut env);
                        // SAFETY: balances push_local_frame above; no local refs escape the job.
                        let _ = unsafe { env.pop_local_frame(&jni::objects::JObject::null()) };
                    } else {
                        job(&mut env);
                    }
                    if env.exception_check().unwrap_or(false) {
                        let _ = env.exception_describe();
                        let _ = env.exception_clear();
                    }
                }
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                    if self.threads.load(Ordering::SeqCst) > self.min {
                        self.threads.fetch_sub(1, Ordering::SeqCst);
                        return;
                    }
                }
                Err(crossbeam_channel::RecvTimeoutError::Disconnected) => {
                    self.threads.fetch_sub(1, Ordering::SeqCst);
                    return;
                }
            }
        }
    }

    fn submit(self: &Arc<Self>, job: Job) {
        // no idle worker: add one (bounded by `max`); surplus workers exit after IDLE_EXIT. This mirrors Go's
        // effectively unbounded callback concurrency, which Kotlin's blocking callbacks may rely on.
        if self.idle.load(Ordering::SeqCst) == 0 {
            self.spawn();
        }
        let _ = self.tx.send((Instant::now(), job));
    }
}

pub struct CallbackExecutor {
    protect: Arc<Pool>,
    flow: Arc<Pool>,
    dns: Arc<Pool>,
    notify: Arc<Pool>,
}

impl CallbackExecutor {
    fn pool(&self, lane: Lane) -> &Arc<Pool> {
        match lane {
            Lane::Protect => &self.protect,
            Lane::Flow => &self.flow,
            Lane::Dns => &self.dns,
            Lane::Notify => &self.notify,
        }
    }

    /// Runs `f` on `lane` and waits (blocking the calling thread) for its result.
    /// Must not be called from an async runtime worker; use [`CallbackExecutor::call`] there.
    pub fn call_blocking<R: Send + 'static>(
        &self,
        lane: Lane,
        f: impl FnOnce(&mut JNIEnv) -> R + Send + 'static,
    ) -> Option<R> {
        let (tx, rx) = crossbeam_channel::bounded(1);
        self.pool(lane).submit(Box::new(move |env| {
            let _ = tx.send(f(env));
        }));
        rx.recv().ok()
    }

    /// Runs `f` on `lane`; the returned future resolves with its result without blocking an async worker.
    pub fn call<R: Send + 'static>(
        &self,
        lane: Lane,
        f: impl FnOnce(&mut JNIEnv) -> R + Send + 'static,
    ) -> impl std::future::Future<Output = Option<R>> + Send + 'static {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.pool(lane).submit(Box::new(move |env| {
            let _ = tx.send(f(env));
        }));
        async move { rx.await.ok() }
    }

    /// Fire-and-forget.
    pub fn post(&self, lane: Lane, f: impl FnOnce(&mut JNIEnv) + Send + 'static) {
        self.pool(lane).submit(Box::new(f));
    }
}

/// Process-wide executor (created lazily after `Seq.init` has recorded the JavaVM).
pub fn executor() -> &'static CallbackExecutor {
    static E: OnceLock<CallbackExecutor> = OnceLock::new();
    E.get_or_init(|| CallbackExecutor {
        protect: Pool::new("protect", 2, 32),
        flow: Pool::new("flow", 4, 64),
        dns: Pool::new("dns", 4, 64),
        notify: Pool::new("notify", 2, 8),
    })
}
