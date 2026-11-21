// Copyright (c) 2026 RethinkReloaded contributors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! A WireGuard far end for tests and the `wg-peer` e2e tool: gotatun with a userspace stack, over any datagram
//! endpoint (a loopback socket, or a socket inside another far end's tunnel for multi-hop).

use super::stack::Stack;
use super::{FromStack, ToStack, canon, config};
use fs_dialers::UdpConn;
use gotatun::device::{DeviceBuilder, Peer};
use gotatun::packet::{Packet, PacketBufPool};
use gotatun::udp::{UdpRecv, UdpSend, UdpTransportFactory, UdpTransportFactoryParams};
use gotatun::x25519::{PublicKey, StaticSecret};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

pub fn pubkey(k: [u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(k)).to_bytes()
}

/// The far end's bind: a loopback socket, or a socket inside another far end's stack.
pub struct Plain(pub UdpConn);
#[derive(Clone)]
pub struct PlainIo(UdpConn);
impl UdpTransportFactory for Plain {
    type Send = PlainIo;
    type Recv = PlainIo;
    async fn bind(&mut self, _: &UdpTransportFactoryParams) -> io::Result<(PlainIo, PlainIo)> {
        Ok((PlainIo(self.0.clone()), PlainIo(self.0.clone())))
    }
}
impl UdpSend for PlainIo {
    type SendManyBuf = ();
    async fn send_to(&self, p: Packet, dst: SocketAddr) -> io::Result<()> {
        self.0.send_to(&p, dst).await.map(|_| ())
    }
}
impl UdpRecv for PlainIo {
    type RecvManyBuf = ();
    async fn recv_from(&mut self, pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        let mut b = pool.get();
        let (n, a) = self.0.recv_from(&mut b).await?;
        b.truncate(n);
        Ok((b, canon(a)))
    }
}

/// A WireGuard peer (key `sk`, tunnel address `addr`) accepting `client` (`client_ip`) over `bind`, with
/// TCP and UDP echo on port 7 inside its tunnel. Keep the first value alive: dropping it stops the device.
pub async fn far_end(
    sk: [u8; 32],
    client: [u8; 32],
    client_ip: &str,
    addr: &str,
    bind: UdpConn,
) -> (impl Sized, Arc<Stack>) {
    let (tx, rx) = mpsc::channel(1024);
    let server = Stack::new(&[config::Net::parse(addr).unwrap()], 1420, tx);
    let dev = DeviceBuilder::new()
        .with_udp(Plain(bind))
        .with_ip_pair(ToStack(server.clone()), FromStack { rx, mtu: 1420 })
        .with_private_key(StaticSecret::from(sk))
        .with_peer(Peer::new(PublicKey::from(client)).with_allowed_ip(client_ip.parse().unwrap()))
        .build()
        .await
        .unwrap();
    let s2 = server.clone();
    tokio::spawn(async move {
        loop {
            let Ok(mut c) = s2.accept(7).await else {
                return;
            };
            tokio::spawn(async move {
                let mut b = [0u8; 64];
                while let Ok(n) = c.read(&mut b).await {
                    if n == 0 || c.write_all(&b[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    let us = server.udp_on(7).unwrap();
    tokio::spawn(async move {
        let mut b = [0u8; 1500];
        while let Ok((n, from)) = fs_dialers::Datagram::recv_from(&us, &mut b).await {
            let _ = fs_dialers::Datagram::send_to(&us, &b[..n], from).await;
        }
    });
    (dev, server)
}
