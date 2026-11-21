// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:tunnel/tunnel.go (fd dup, link swap)
// Derived-From: celzero/firestack@d3d530ea3e:intra/netstack/fdbased.go (raw-IP fd endpoint)

//! TUN device and userspace TCP/IP stack.
//!
//! Phase 1 uses `netstack-smoltcp` (smoltcp underneath) behind this crate's interface: the TUN fd is read and
//! written as raw IP packets (Android's `VpnService` TUN has no packet-info header) and pumped into / out of the
//! stack, which hands out accepted TCP streams (handshake completed first, as firestack does with happy eyeballs
//! off) and UDP datagrams. If the Phase 1 performance gate requires it, this crate is where a direct smoltcp
//! integration replaces `netstack-smoltcp` without touching the handlers.

pub mod pcap;
pub mod tun;

use futures::{SinkExt, StreamExt};
use netstack_smoltcp::{StackBuilder, TcpListener, udp};
use parking_lot::Mutex;
use std::sync::Arc;
use tokio::task::JoinHandle;
use tun::Tun;

pub use netstack_smoltcp::TcpStream;
pub use netstack_smoltcp::udp::UdpMsg;

/// Sees every packet read from the TUN before the stack; returns true to consume it (e.g. ICMP echo).
pub type Interceptor = Arc<dyn Fn(&[u8]) -> bool + Send + Sync>;

/// A running stack bound to a (swappable) TUN device.
pub struct Netstack {
    tun: Arc<tun::Link>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

/// The stack's outputs for the handlers.
pub struct Endpoints {
    /// accepted TCP connections: (stream, src = app, dst = remote)
    pub tcp: TcpListener,
    /// datagrams from apps: (payload, src = app, dst = remote)
    pub udp_rx: udp::ReadHalf,
    /// datagrams to apps: (payload, src = remote, dst = app)
    pub udp_tx: udp::WriteHalf,
}

/// Stack tuning (TCP buffers per connection, MTU).
#[derive(Clone, Copy, Debug)]
pub struct Opts {
    pub mtu: usize,
    pub tcp_buffer: u32,
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            mtu: 1500,
            tcp_buffer: 64 * 1024,
        }
    }
}

impl Netstack {
    /// Starts pumping packets between `tun` and a new stack. Must be called within a tokio runtime.
    pub fn start(
        tun: Tun,
        opts: Opts,
        intercept: Option<Interceptor>,
    ) -> std::io::Result<(Arc<Netstack>, Endpoints)> {
        let (stack, runner, udp, tcp) = StackBuilder::default()
            .enable_tcp(true)
            .enable_udp(true)
            .enable_icmp(true) // echo requests are intercepted before the stack (see `Interceptor`)
            .mtu(opts.mtu)
            .stack_buffer_size(1024)
            .udp_buffer_size(1024)
            .tcp_buffer_size(1024)
            .tcp_recv_buffer_size(opts.tcp_buffer)
            .tcp_send_buffer_size(opts.tcp_buffer)
            .build()?;
        let (udp, tcp) = match (udp, tcp) {
            (Some(u), Some(t)) => (u, t),
            _ => return Err(std::io::Error::other("netstack: tcp/udp disabled")),
        };
        let (udp_rx, udp_tx) = udp.split();
        let link = Arc::new(tun::Link::new(tun));
        let mut tasks = Vec::new();
        if let Some(runner) = runner {
            tasks.push(tokio::spawn(async move {
                let _ = runner.await;
            }));
        }
        let (mut stack_sink, mut stack_stream) = stack.split();

        // TUN -> stack
        let rd = link.clone();
        let mtu = opts.mtu;
        tasks.push(tokio::spawn(async move {
            let mut buf = vec![0u8; mtu.max(1500) + 64];
            loop {
                match rd.read(&mut buf).await {
                    Ok(0) => continue,
                    Ok(n) => {
                        if let Some(f) = &intercept
                            && f(&buf[..n])
                        {
                            continue;
                        }
                        if stack_sink.send(buf[..n].to_vec()).await.is_err() {
                            break;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => {
                        // link closed or swapped: wait for a new fd (or exit when the link is shut)
                        if !rd.wait_swapped().await {
                            break;
                        }
                    }
                }
            }
        }));

        // stack -> TUN
        let wr = link.clone();
        tasks.push(tokio::spawn(async move {
            while let Some(pkt) = stack_stream.next().await {
                let Ok(pkt) = pkt else { continue };
                // drop on write failure (unlinked / swapping): IP is lossy, TCP retransmits
                let _ = wr.write(&pkt).await;
            }
        }));

        let ns = Arc::new(Netstack {
            tun: link,
            tasks: Mutex::new(tasks),
        });
        Ok((
            ns,
            Endpoints {
                tcp,
                udp_rx,
                udp_tx,
            },
        ))
    }

    /// Writes a raw IP packet to the TUN (e.g. a synthesized ICMP reply).
    pub async fn write_to_tun(&self, pkt: &[u8]) -> std::io::Result<usize> {
        self.tun.write(pkt).await
    }

    /// Replaces the TUN fd (network change / new VpnService.Builder fd) without dropping connections.
    pub fn swap(&self, tun: Tun) {
        self.tun.swap(tun);
    }

    /// Closes the TUN fd; the stack and connections survive until [`Netstack::stop`] (firestack `Unlink`).
    pub fn unlink(&self) {
        self.tun.unlink();
    }

    pub fn mtu(&self) -> i32 {
        self.tun.mtu()
    }

    pub fn set_mtu(&self, mtu: i32) {
        self.tun.set_mtu(mtu);
    }

    pub fn is_linked(&self) -> bool {
        self.tun.is_linked()
    }

    /// TUN traffic counters.
    pub fn stats(&self) -> &tun::LinkStats {
        &self.tun.stats
    }

    /// Packet capture (`Tunnel.setPcap`).
    pub fn pcap(&self) -> &pcap::Pcap {
        &self.tun.pcap
    }

    pub fn stop(&self) {
        self.tun.shutdown();
        for t in self.tasks.lock().drain(..) {
            t.abort();
        }
    }
}

impl Drop for Netstack {
    fn drop(&mut self) {
        self.stop();
    }
}
