// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/dialers/retrier.go (dialStratLocked, calcTimeout, Read, Write)
// Derived-From: celzero/firestack@d3d530ea3e:intra/dialers/direct_split.go (splitter)
// Derived-From: celzero/firestack@d3d530ea3e:intra/dialers/op.go (splitHello, writeTCPOrTLSSplit)
// Derived-From: celzero/firestack@d3d530ea3e:intra/dialers/rdial.go (doSplit)
//
// This file incorporates work covered by the following copyright and permission notice:
//
//     Copyright 2020 Jigsaw Operations LLC
//
//     Licensed under the Apache License, Version 2.0 (the "License");
//     you may not use this file except in compliance with the License.
//     You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0

//! Censorship circumvention for TCP to public HTTPS / DoT servers (`settings.DialerOpts`): the first segment the
//! app sends ("hello") is split in two TCP segments, or its TLS record fragmented in two records, or sent after a
//! decoy that only middleboxes see ([`crate::desync`]). [`Retrier`] remembers what was written before the first
//! reply and, when the connection fails, closes without a reply, stalls past a timeout derived from the handshake
//! RTT, or (split TLS) answers too little, re-dials with the next strategy and replays it; at most three tries.

use crate::TcpConn;
use crate::conn::Fut;
use fs_core::settings::{
    self, RETRY_AFTER_SPLIT, RETRY_NEVER, RETRY_WITH_SPLIT, SPLIT_AUTO, SPLIT_DESYNC, SPLIT_NEVER,
    SPLIT_TCP, SPLIT_TCP_OR_TLS,
};
use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

const MAX_RETRY_COUNT: u8 = 3;
const MIN_EXPECTED_TLS_READ: usize = 16;
const TLS_PORT: u16 = 443;
const CIEL_RETRY_READ_TIMEOUT_SEC: u64 = 9;
const FLOOR_RETRY_READ_TIMEOUT_MILLIS: u64 = 1000;

/// firestack `doSplit`: HTTPS or DoT to a non-private address (Go's `IsPrivate`: 10/8, 172.16/12, 192.168/16,
/// fc00::/7; loopback is not private).
pub fn do_split(dst: SocketAddr) -> bool {
    let private = match dst.ip() {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xfe00) == 0xfc00,
    };
    !private && matches!(dst.port(), 443 | 853)
}

/// A cheap PRNG (Go's `math/rand` in firestack): split sizes and probe ports, nothing secret.
pub(crate) fn rand_below(n: u64) -> u64 {
    static S: AtomicU64 = AtomicU64::new(0);
    let seed = S.fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed)
        ^ std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
    // splitmix64
    let mut z = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    (z ^ (z >> 31)) % n.max(1)
}

/// firestack `splitHello`: the first segment's length, 32..=64 bytes but at most half the hello.
fn split_hello_at(len: usize) -> usize {
    let s = 32 + rand_below(64 + 1 - 32) as usize;
    s.min(len / 2)
}

/// firestack `getTLSClientHelloRecordLen`.
fn client_hello_record_len(h: &[u8]) -> Option<u16> {
    if h.len() < 5 || h[0] != 22 {
        return None;
    }
    let ver = u16::from_be_bytes([h[1], h[2]]);
    if !(0x0301..=0x0304).contains(&ver) {
        return None;
    }
    Some(u16::from_be_bytes([h[3], h[4]]))
}

/// The segments of a split first write: firestack `writeTCPSplit` and `writeTCPOrTLSSplit` (TLS record
/// fragmentation, 6..=64 bytes into the record including its header, else a TCP split). `split_len` is the
/// random choice (tests pass it).
fn segments(strat: i32, hello: &[u8], split_len: Option<usize>) -> Vec<Vec<u8>> {
    if strat == SPLIT_TCP_OR_TLS && hello.len() > 1 {
        let s = split_len
            .unwrap_or_else(|| 6 + rand_below(64 + 1 - 6) as usize)
            .min(hello.len() / 2);
        let rec1 = s as i64 - 5;
        if let Some(rl) = client_hello_record_len(hello)
            && rec1 > 0
            && rec1 < rl as i64
        {
            let rec2 = rl - rec1 as u16;
            let mut a = hello[..s].to_vec();
            a[3..5].copy_from_slice(&(rec1 as u16).to_be_bytes());
            let mut b = hello[..5].to_vec();
            b[3..5].copy_from_slice(&rec2.to_be_bytes());
            b.extend_from_slice(&hello[s..]);
            return vec![a, b];
        }
    } else if strat == SPLIT_TCP_OR_TLS {
        return vec![hello.to_vec()];
    }
    if hello.is_empty() {
        return vec![Vec::new()];
    }
    let s = split_len
        .unwrap_or_else(|| split_hello_at(hello.len()))
        .min(hello.len() / 2);
    vec![hello[..s].to_vec(), hello[s..].to_vec()]
}

/// firestack `splitter`: writes the first write as two segments (`strat` SplitTCP or SplitTCPOrTLS).
pub struct Splitter {
    conn: TcpConn,
    strat: i32,
    used: bool,
    out: VecDeque<Vec<u8>>,
    /// bytes reported for the first write once its segments are out
    out_ret: usize,
}

impl Splitter {
    pub fn new(conn: TcpConn, strat: i32) -> Self {
        Splitter {
            conn,
            strat,
            used: false,
            out: VecDeque::new(),
            out_ret: 0,
        }
    }
}

impl AsyncRead for Splitter {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.conn).poll_read(cx, buf)
    }
}

impl AsyncWrite for Splitter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = &mut *self;
        if !me.used {
            me.used = true;
            me.out = segments(me.strat, b, None).into();
            me.out_ret = b.len();
        }
        // each segment goes out in its own write (TCP_NODELAY), so in its own TCP segment
        while let Some(seg) = me.out.front_mut() {
            if seg.is_empty() {
                me.out.pop_front();
                continue;
            }
            match Pin::new(&mut me.conn).poll_write(cx, seg) {
                Poll::Ready(Ok(n)) => {
                    seg.drain(..n);
                }
                Poll::Ready(Err(e)) => {
                    me.out.clear();
                    me.out_ret = 0;
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        if me.out_ret > 0 {
            // after a TLS fragmentation the bytes on the wire exceed the hello; report the hello (firestack)
            return Poll::Ready(Ok(std::mem::take(&mut me.out_ret)));
        }
        Pin::new(&mut me.conn).poll_write(cx, b)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.conn).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.conn).poll_shutdown(cx)
    }
}

/// Dials one attempt with a strategy (SplitNever, SplitTCP, SplitTCPOrTLS or SplitDesync).
pub type StratDial = Arc<dyn Fn(i32) -> Fut<'static, io::Result<TcpConn>> + Send + Sync>;

/// firestack `dialStratLocked`: the strategy of attempt `retry_count` (None: no attempt allowed).
pub fn dial_strat(strat: i32, retry: i32, retry_count: u8, max_retries: u8) -> Option<i32> {
    let auto = strat == SPLIT_AUTO;
    let mut split = strat != SPLIT_NEVER;
    match retry {
        RETRY_NEVER => {
            if retry_count >= 1 {
                return None;
            }
            split = split && retry_count == 0;
        }
        RETRY_WITH_SPLIT => split = split && retry_count >= 1,
        RETRY_AFTER_SPLIT => {
            split = split && retry_count == 0;
            if auto {
                split = split && retry_count < max_retries;
            }
        }
        _ => {}
    }
    Some(if !split {
        SPLIT_NEVER
    } else if auto {
        let cycle = retry_count % max_retries.max(1);
        match retry {
            RETRY_NEVER => SPLIT_TCP,
            RETRY_WITH_SPLIT => match cycle {
                1 => SPLIT_TCP,
                2 => SPLIT_TCP_OR_TLS,
                _ => SPLIT_DESYNC,
            },
            RETRY_AFTER_SPLIT => match cycle {
                0 => SPLIT_TCP,
                1 => SPLIT_TCP_OR_TLS,
                _ => SPLIT_TCP,
            },
            _ => SPLIT_NEVER,
        }
    } else {
        strat
    })
}

/// firestack `calcTimeout`: how long to wait for a reply to the first segment, given the connect RTT.
pub fn calc_timeout(rtt: Duration, spread: u16) -> Duration {
    let spread = spread.max(1) as u64;
    let ciel = Duration::from_secs((CIEL_RETRY_READ_TIMEOUT_SEC / spread).max(1));
    let floor = Duration::from_millis((FLOOR_RETRY_READ_TIMEOUT_MILLIS / spread).min(300));
    (rtt * 2).max(ciel) + (rtt * 2).min(floor)
}

fn is_split(strat: i32) -> bool {
    strat == SPLIT_TCP || strat == SPLIT_TCP_OR_TLS
}

/// Counters a retry carries along.
#[derive(Clone, Copy)]
struct Tries {
    strat: i32,
    retry: i32,
    count: u8,
    max: u8,
    cur: i32,
    timeout: Duration,
}

impl Tries {
    fn can_retry(&self) -> bool {
        self.retry != RETRY_NEVER
    }
    fn redo_for_tls(&self, rport: u16, n: usize) -> bool {
        is_split(self.cur) && rport == TLS_PORT && n < MIN_EXPECTED_TLS_READ
    }
    /// firestack `dialLocked`: dials with this attempt's strategy and derives the reply timeout from its RTT.
    async fn dial(&mut self, d: &StratDial) -> io::Result<TcpConn> {
        let strat = dial_strat(self.strat, self.retry, self.count, self.max)
            .ok_or_else(|| io::Error::other("retrier: no retries"))?;
        self.cur = strat;
        let spread = if strat == SPLIT_NEVER {
            0
        } else {
            self.max as i32 - self.count as i32
        };
        let t0 = Instant::now();
        let r = d(strat).await;
        // if retries are disabled, do not time out aggressively: there is nothing else to do
        self.timeout = if self.can_retry() {
            calc_timeout(t0.elapsed(), spread.max(0) as u16)
        } else {
            Duration::ZERO
        };
        r
    }
}

struct RetryDone {
    conn: Option<TcpConn>,
    tries: Tries,
    read: io::Result<Vec<u8>>,
}

enum State {
    /// before the first reply
    Probe,
    Retrying(Fut<'static, RetryDone>),
    Done,
}

/// firestack `retrier`.
pub struct Retrier {
    dial: StratDial,
    rport: u16,
    conn: Option<TcpConn>,
    tries: Tries,
    state: State,
    /// written before the first reply
    tee: Vec<u8>,
    /// reply deadline, armed by writes before the first reply
    deadline: Option<Pin<Box<tokio::time::Sleep>>>,
    /// a reply from a retry, not yet read
    pending: Vec<u8>,
    write_done: bool,
    writer: Option<Waker>,
    /// a reader parked before any write (no timer yet)
    reader: Option<Waker>,
}

impl Retrier {
    /// firestack `DialWithSplitRetry`: dials the first attempt (its error is the caller's) with the global
    /// `DialerOpts`.
    pub async fn dial(d: StratDial, rport: u16) -> io::Result<Retrier> {
        let o = settings::dialer_opts();
        Self::dial_with(d, rport, o.strat, o.retry).await
    }

    pub async fn dial_with(
        d: StratDial,
        rport: u16,
        strat: i32,
        retry: i32,
    ) -> io::Result<Retrier> {
        let mut tries = Tries {
            strat,
            retry,
            count: 0,
            max: MAX_RETRY_COUNT,
            cur: SPLIT_NEVER,
            timeout: Duration::ZERO,
        };
        let c = tries.dial(&d).await?;
        Ok(Retrier {
            dial: d,
            rport,
            conn: Some(c),
            tries,
            state: State::Probe,
            tee: Vec::new(),
            deadline: None,
            pending: Vec::new(),
            write_done: false,
            writer: None,
            reader: None,
        })
    }

    /// The strategy of the current connection.
    pub fn current_strat(&self) -> i32 {
        self.tries.cur
    }

    /// Retry attempts made.
    pub fn retries(&self) -> u8 {
        self.tries.count
    }

    fn finish(&mut self) {
        self.state = State::Done;
        self.tee = Vec::new();
        self.deadline = None;
        if let Some(w) = self.writer.take() {
            w.wake();
        }
    }

    /// firestack `retryWriteReadLocked` in a loop (Read's retry block): re-dial, replay, await a reply.
    fn start_retry(&mut self, first: io::Error) {
        let (d, rport, tee, mut tries, wd) = (
            self.dial.clone(),
            self.rport,
            self.tee.clone(),
            self.tries,
            self.write_done,
        );
        drop(self.conn.take()); // closes the failed connection
        self.deadline = None;
        self.state = State::Retrying(Box::pin(async move {
            let mut err = first;
            let mut conn = None;
            while tries.can_retry() && tries.count < tries.max {
                tries.count += 1;
                drop(conn.take());
                let mut c = match tries.dial(&d).await {
                    Ok(c) => c,
                    Err(e) => {
                        err = e;
                        continue;
                    }
                };
                if let Err(e) = c.write_all(&tee).await {
                    err = e;
                    continue;
                }
                if wd {
                    let _ = c.shutdown().await;
                }
                let mut b = vec![0u8; 16 * 1024];
                let rd = if tries.timeout.is_zero() {
                    Ok(c.read(&mut b).await)
                } else {
                    tokio::time::timeout(tries.timeout, c.read(&mut b)).await
                };
                match rd {
                    Ok(Ok(n)) if n > 0 && !tries.redo_for_tls(rport, n) => {
                        b.truncate(n);
                        return RetryDone {
                            conn: Some(c),
                            tries,
                            read: Ok(b),
                        };
                    }
                    Ok(Ok(0)) => err = io::Error::new(io::ErrorKind::UnexpectedEof, "retrier: eof"),
                    Ok(Ok(_)) => err = io::Error::other("retrier: tls handshake incomplete"),
                    Ok(Err(e)) => err = e,
                    Err(_) => {
                        err = io::Error::new(io::ErrorKind::TimedOut, "retrier: read timeout")
                    }
                }
                conn = Some(c);
            }
            RetryDone {
                conn,
                tries,
                read: Err(err),
            }
        }));
    }
}

impl AsyncRead for Retrier {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = &mut *self;
        loop {
            match &mut me.state {
                State::Done => {
                    if !me.pending.is_empty() {
                        let n = me.pending.len().min(buf.remaining());
                        buf.put_slice(&me.pending[..n]);
                        me.pending.drain(..n);
                        return Poll::Ready(Ok(()));
                    }
                    return match me.conn.as_mut() {
                        Some(c) => Pin::new(c).poll_read(cx, buf),
                        None => Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::NotConnected,
                            "retrier: no conn",
                        ))),
                    };
                }
                State::Retrying(f) => {
                    let RetryDone { conn, tries, read } = match f.as_mut().poll(cx) {
                        Poll::Ready(r) => r,
                        Poll::Pending => return Poll::Pending,
                    };
                    me.conn = conn;
                    me.tries = tries;
                    me.finish();
                    match read {
                        Ok(b) => me.pending = b,
                        Err(e) => return Poll::Ready(Err(e)),
                    }
                }
                State::Probe => {
                    let Some(c) = me.conn.as_mut() else {
                        me.start_retry(io::Error::new(
                            io::ErrorKind::NotConnected,
                            "retrier: no conn",
                        ));
                        continue;
                    };
                    let before = buf.filled().len();
                    let err = match Pin::new(c).poll_read(cx, buf) {
                        Poll::Ready(Ok(())) => {
                            let n = buf.filled().len() - before;
                            if n > 0 && !me.tries.redo_for_tls(me.rport, n) {
                                me.finish();
                                return Poll::Ready(Ok(()));
                            }
                            buf.set_filled(before); // a too-short TLS reply is not passed on
                            if n == 0 {
                                io::Error::new(io::ErrorKind::UnexpectedEof, "retrier: eof")
                            } else {
                                io::Error::other("retrier: tls handshake incomplete")
                            }
                        }
                        Poll::Ready(Err(e)) => e,
                        Poll::Pending => match me.deadline.as_mut().map(|d| d.as_mut().poll(cx)) {
                            Some(Poll::Ready(())) => {
                                io::Error::new(io::ErrorKind::TimedOut, "retrier: read timeout")
                            }
                            Some(Poll::Pending) => return Poll::Pending,
                            None => {
                                me.reader = Some(cx.waker().clone());
                                return Poll::Pending;
                            }
                        },
                    };
                    if me.tries.can_retry() && me.tries.count < me.tries.max {
                        me.start_retry(err);
                        continue;
                    }
                    me.finish();
                    if err.kind() == io::ErrorKind::UnexpectedEof {
                        return Poll::Ready(Ok(())); // a plain EOF
                    }
                    return Poll::Ready(Err(err));
                }
            }
        }
    }
}

impl AsyncWrite for Retrier {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = &mut *self;
        match me.state {
            State::Done => match me.conn.as_mut() {
                Some(c) => Pin::new(c).poll_write(cx, b),
                None => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "retrier: no conn",
                ))),
            },
            State::Retrying(_) => {
                me.writer = Some(cx.waker().clone());
                Poll::Pending
            }
            State::Probe => {
                // firestack teedFirstWrite: everything written before the first reply is kept for a replay, and
                // a reply is then expected within the timeout
                let n = match me.conn.as_mut() {
                    Some(c) => match Pin::new(c).poll_write(cx, b) {
                        Poll::Ready(Ok(n)) => n,
                        // the retry (on the read side) replays it on a new connection
                        Poll::Ready(Err(_)) => b.len(),
                        Poll::Pending => return Poll::Pending,
                    },
                    None => b.len(),
                };
                me.tee.extend_from_slice(&b[..n]);
                if !me.tries.timeout.is_zero() {
                    me.deadline = Some(Box::pin(tokio::time::sleep(me.tries.timeout)));
                    // the reader may be parked without a timer: wake it to poll this one
                    if let Some(w) = me.reader.take() {
                        w.wake();
                    }
                }
                Poll::Ready(Ok(n))
            }
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = &mut *self;
        if let State::Retrying(_) = me.state {
            me.writer = Some(cx.waker().clone());
            return Poll::Pending;
        }
        match me.conn.as_mut() {
            Some(c) => match Pin::new(c).poll_flush(cx) {
                Poll::Ready(Err(_)) if matches!(me.state, State::Probe) => Poll::Ready(Ok(())),
                r => r,
            },
            None => Poll::Ready(Ok(())),
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = &mut *self;
        me.write_done = true;
        if let State::Retrying(_) = me.state {
            me.writer = Some(cx.waker().clone());
            return Poll::Pending;
        }
        match me.conn.as_mut() {
            Some(c) => Pin::new(c).poll_shutdown(cx),
            None => Poll::Ready(Ok(())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strategies_as_firestack() {
        // (strat, retry) -> strategies of attempts 0..3 (None: not allowed)
        let s = |st, r| (0..4).map(|i| dial_strat(st, r, i, 3)).collect::<Vec<_>>();
        let (n, t, tt, d) = (
            Some(SPLIT_NEVER),
            Some(SPLIT_TCP),
            Some(SPLIT_TCP_OR_TLS),
            Some(SPLIT_DESYNC),
        );
        assert_eq!(s(SPLIT_AUTO, RETRY_AFTER_SPLIT), [t, n, n, n]);
        assert_eq!(s(SPLIT_AUTO, RETRY_WITH_SPLIT), [n, t, tt, d]);
        assert_eq!(s(SPLIT_AUTO, RETRY_NEVER), [t, None, None, None]);
        assert_eq!(s(SPLIT_TCP_OR_TLS, RETRY_AFTER_SPLIT), [tt, n, n, n]);
        assert_eq!(s(SPLIT_DESYNC, RETRY_WITH_SPLIT), [n, d, d, d]);
        assert_eq!(s(SPLIT_NEVER, RETRY_WITH_SPLIT), [n, n, n, n]);
        assert_eq!(s(SPLIT_TCP, RETRY_NEVER), [t, None, None, None]);
    }

    #[test]
    fn timeouts_as_firestack() {
        let ms = Duration::from_millis;
        assert_eq!(
            calc_timeout(ms(50), 3),
            ms(3000 + 100),
            "ciel 9/3 s, floor min(300, 333) ms"
        );
        assert_eq!(calc_timeout(ms(50), 0), ms(9000 + 100));
        assert_eq!(calc_timeout(ms(400), 1), ms(9000 + 300));
        assert_eq!(calc_timeout(ms(6000), 3), ms(12000 + 300));
        assert!(!do_split("192.168.1.1:443".parse().unwrap()));
        assert!(!do_split("[fd00::1]:853".parse().unwrap()));
        assert!(!do_split("1.1.1.1:80".parse().unwrap()));
        assert!(do_split("1.1.1.1:853".parse().unwrap()));
        assert!(
            do_split("127.0.0.1:443".parse().unwrap()),
            "Go: loopback is not private"
        );
    }

    /// Server behaviours of successive attempts.
    #[derive(Clone, Copy)]
    enum Srv {
        /// reads the hello, closes without a reply
        Reset,
        /// reads the hello, never replies
        Stall,
        /// reads the hello, replies with this many bytes
        Reply(usize),
    }

    type Seen = Arc<std::sync::Mutex<Vec<(i32, Vec<u8>)>>>;

    /// A dialer of in-memory connections: attempt i behaves as `plan[i]`; records strategies and hellos seen.
    fn mock(plan: Vec<Srv>) -> (StratDial, Seen) {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let n = Arc::new(AtomicU64::new(0));
        let s2 = seen.clone();
        let d: StratDial = Arc::new(move |strat| {
            let i = n.fetch_add(1, Ordering::Relaxed) as usize;
            let (srv, seen) = (plan[i.min(plan.len() - 1)], s2.clone());
            Box::pin(async move {
                let (c, mut s) = tokio::io::duplex(64 * 1024);
                tokio::spawn(async move {
                    let mut b = vec![0u8; 4096];
                    let n = s.read(&mut b).await.unwrap_or(0);
                    seen.lock().unwrap().push((strat, b[..n].to_vec()));
                    match srv {
                        Srv::Reset => drop(s),
                        Srv::Stall => {
                            tokio::time::sleep(Duration::from_secs(3600)).await;
                        }
                        Srv::Reply(k) => {
                            let _ = s.write_all(&vec![0x16; k]).await;
                            tokio::time::sleep(Duration::from_secs(3600)).await;
                        }
                    }
                });
                let c = TcpConn::Dyn(Box::new(c));
                Ok(if is_split(strat) {
                    TcpConn::Dyn(Box::new(Splitter::new(c, strat)))
                } else {
                    c
                })
            })
        });
        (d, seen)
    }

    async fn exchange(r: &mut Retrier) -> io::Result<Vec<u8>> {
        let hello: Vec<u8> = (0..200u8).collect();
        r.write_all(&hello).await?;
        let mut b = vec![0u8; 1024];
        let n = r.read(&mut b).await?;
        Ok(b[..n].to_vec())
    }

    #[tokio::test]
    async fn retries_after_reset_with_the_hello() {
        let (d, seen) = mock(vec![Srv::Reset, Srv::Reply(100)]);
        let mut r = Retrier::dial_with(d, 443, SPLIT_AUTO, RETRY_AFTER_SPLIT)
            .await
            .unwrap();
        assert_eq!(
            r.current_strat(),
            SPLIT_TCP,
            "auto splits the first attempt"
        );
        assert_eq!(exchange(&mut r).await.unwrap().len(), 100);
        let seen = seen.lock().unwrap().clone();
        let hello: Vec<u8> = (0..200u8).collect();
        assert_eq!(
            seen.iter().map(|x| x.0).collect::<Vec<_>>(),
            [SPLIT_TCP, SPLIT_NEVER]
        );
        assert_eq!(seen[1].1, hello, "replayed on the new connection");
        assert_eq!((r.retries(), r.current_strat()), (1, SPLIT_NEVER));
        r.write_all(b"after").await.unwrap(); // steady state
    }

    #[tokio::test(start_paused = true)]
    async fn retries_a_stall_after_the_timeout() {
        let (d, seen) = mock(vec![Srv::Stall, Srv::Stall, Srv::Reply(64)]);
        let t0 = tokio::time::Instant::now();
        let mut r = Retrier::dial_with(d, 853, SPLIT_AUTO, RETRY_WITH_SPLIT)
            .await
            .unwrap();
        assert_eq!(exchange(&mut r).await.unwrap().len(), 64);
        let strats: Vec<i32> = seen.lock().unwrap().iter().map(|x| x.0).collect();
        assert_eq!(strats, [SPLIT_NEVER, SPLIT_TCP, SPLIT_TCP_OR_TLS]);
        // no split: 9 s; then spread over 2 remaining tries: 4 s
        assert_eq!(t0.elapsed().as_secs(), 9 + 4);
    }

    #[tokio::test]
    async fn short_tls_reply_to_a_split_is_retried() {
        let (d, seen) = mock(vec![Srv::Reply(5), Srv::Reply(5)]);
        let mut r = Retrier::dial_with(d, 443, SPLIT_TCP_OR_TLS, RETRY_AFTER_SPLIT)
            .await
            .unwrap();
        assert_eq!(
            exchange(&mut r).await.unwrap().len(),
            5,
            "unsplit: a short reply is fine"
        );
        assert_eq!(seen.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn retry_never_gives_up() {
        let (d, seen) = mock(vec![Srv::Reset, Srv::Reply(100)]);
        let mut r = Retrier::dial_with(d, 443, SPLIT_TCP, RETRY_NEVER)
            .await
            .unwrap();
        assert_eq!(exchange(&mut r).await.unwrap().len(), 0, "eof");
        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    #[test]
    fn splits_hellos() {
        let hello: Vec<u8> = (0..200u8).collect();
        let s = segments(SPLIT_TCP, &hello, None);
        assert_eq!(s.len(), 2);
        assert!((32..=64).contains(&s[0].len()));
        assert_eq!(s.concat(), hello);
        assert_eq!(
            segments(SPLIT_TCP, &hello[..40], None)[0].len(),
            20,
            "at most half"
        );

        // a TLS ClientHello record (type 22, TLS 1.0 record version, 195-byte body)
        let mut ch = vec![22, 3, 1, 0, 195];
        ch.extend((0..195).map(|i| i as u8));
        let s = segments(SPLIT_TCP_OR_TLS, &ch, Some(20));
        assert_eq!(s[0][..5], [22, 3, 1, 0, 15], "first record: 15 body bytes");
        assert_eq!(s[0][5..], ch[5..20]);
        assert_eq!(
            s[1][..5],
            [22, 3, 1, 0, 180],
            "second record: the other 180"
        );
        assert_eq!(s[1][5..], ch[20..]);
        // not TLS: a TCP split
        let s = segments(SPLIT_TCP_OR_TLS, &hello, Some(20));
        assert_eq!((s[0].len(), s.concat()), (20, hello.clone()));
    }
}
