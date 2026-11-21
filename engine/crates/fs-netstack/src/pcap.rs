// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:tunnel/tunnel.go (SetPcap), tunnel/sink.go

//! Packet capture of the TUN traffic (`Tunnel.setPcap`): an empty path turns it off, a one-character one logs a line
//! per packet, anything else is a file appended to in pcap format (raw IP link type).

use parking_lot::Mutex;
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{SystemTime, UNIX_EPOCH};

const LINKTYPE_RAW: u32 = 101;
const SNAPLEN: u32 = 65535;

enum Mode {
    Off,
    Log,
    File(std::fs::File),
}

pub struct Pcap {
    mode: Mutex<Mode>,
}

impl Default for Pcap {
    fn default() -> Self {
        Pcap {
            mode: Mutex::new(Mode::Off),
        }
    }
}

impl Pcap {
    /// firestack `SetPcap`.
    pub fn set(&self, path: &str) -> std::io::Result<()> {
        let m = match path.len() {
            0 => Mode::Off,
            1 => Mode::Log,
            _ => {
                let mut f = std::fs::OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open(path)?;
                if f.metadata()?.len() == 0 {
                    let mut h = Vec::with_capacity(24);
                    h.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
                    h.extend_from_slice(&2u16.to_le_bytes());
                    h.extend_from_slice(&4u16.to_le_bytes());
                    h.extend_from_slice(&0i32.to_le_bytes());
                    h.extend_from_slice(&0u32.to_le_bytes());
                    h.extend_from_slice(&SNAPLEN.to_le_bytes());
                    h.extend_from_slice(&LINKTYPE_RAW.to_le_bytes());
                    f.write_all(&h)?;
                }
                Mode::File(f)
            }
        };
        *self.mode.lock() = m;
        Ok(())
    }

    /// "none", "log" or "file" (`TUNStat.PcapMode`).
    pub fn mode(&self) -> &'static str {
        match &*self.mode.lock() {
            Mode::Off => "none",
            Mode::Log => "log",
            Mode::File(_) => "file",
        }
    }

    /// Records `pkt` (`rx`: read from the TUN).
    pub fn record(&self, rx: bool, pkt: &[u8]) {
        let mut g = self.mode.lock();
        match &mut *g {
            Mode::Off => {}
            Mode::Log => fs_core::log::info(&format!(
                "pcap: {} {}",
                if rx { "rx" } else { "tx" },
                summary(pkt)
            )),
            Mode::File(f) => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default();
                let n = pkt.len().min(SNAPLEN as usize);
                let mut rec = Vec::with_capacity(16 + n);
                rec.extend_from_slice(&(now.as_secs() as u32).to_le_bytes());
                rec.extend_from_slice(&now.subsec_micros().to_le_bytes());
                rec.extend_from_slice(&(n as u32).to_le_bytes());
                rec.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
                rec.extend_from_slice(&pkt[..n]);
                if f.write_all(&rec).is_err() {
                    *g = Mode::Off; // a failing sink turns itself off
                }
            }
        }
    }

    pub fn is_on(&self) -> bool {
        !matches!(&*self.mode.lock(), Mode::Off)
    }
}

/// `proto src > dst len` of an IP packet.
fn summary(p: &[u8]) -> String {
    let proto = |n: u8| match n {
        1 => "icmp",
        6 => "tcp",
        17 => "udp",
        58 => "icmp6",
        _ => "ip",
    };
    match p.first().map(|b| b >> 4) {
        Some(4) if p.len() >= 20 => {
            let ihl = ((p[0] & 0x0f) as usize) * 4;
            let ports = (p.len() >= ihl + 4 && matches!(p[9], 6 | 17)).then(|| {
                (
                    u16::from_be_bytes([p[ihl], p[ihl + 1]]),
                    u16::from_be_bytes([p[ihl + 2], p[ihl + 3]]),
                )
            });
            let (s, d) = (
                Ipv4Addr::new(p[12], p[13], p[14], p[15]),
                Ipv4Addr::new(p[16], p[17], p[18], p[19]),
            );
            match ports {
                Some((sp, dp)) => format!("{} {s}:{sp} > {d}:{dp} {}", proto(p[9]), p.len()),
                None => format!("{} {s} > {d} {}", proto(p[9]), p.len()),
            }
        }
        Some(6) if p.len() >= 40 => {
            let s = Ipv6Addr::from(<[u8; 16]>::try_from(&p[8..24]).unwrap());
            let d = Ipv6Addr::from(<[u8; 16]>::try_from(&p[24..40]).unwrap());
            let ports = (p.len() >= 44 && matches!(p[6], 6 | 17)).then(|| {
                (
                    u16::from_be_bytes([p[40], p[41]]),
                    u16::from_be_bytes([p[42], p[43]]),
                )
            });
            match ports {
                Some((sp, dp)) => format!("{} [{s}]:{sp} > [{d}]:{dp} {}", proto(p[6]), p.len()),
                None => format!("{} {s} > {d} {}", proto(p[6]), p.len()),
            }
        }
        _ => format!("? {}", p.len()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_pcap() {
        let dir = std::env::temp_dir().join(format!("rr-pcap-{}", std::process::id()));
        let _ = std::fs::remove_file(&dir);
        let p = Pcap::default();
        p.set(dir.to_str().unwrap()).unwrap();
        assert_eq!(p.mode(), "file");
        let pkt = [
            0x45u8, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 1, 1, 1, 1,
        ];
        p.record(true, &pkt);
        p.set("").unwrap();
        assert!(!p.is_on());
        let b = std::fs::read(&dir).unwrap();
        assert_eq!(&b[..4], &0xa1b2c3d4u32.to_le_bytes());
        assert_eq!(
            u32::from_le_bytes(b[20..24].try_into().unwrap()),
            LINKTYPE_RAW
        );
        assert_eq!(b.len(), 24 + 16 + pkt.len());
        assert_eq!(&b[40..], &pkt);
        let _ = std::fs::remove_file(&dir);
        assert_eq!(summary(&pkt), "udp 10.0.0.1 > 1.1.1.1 20");
    }
}

/// Entry point for the fuzzers (`--cfg fuzzing`): the per-packet text log.
#[cfg(fuzzing)]
pub fn fuzz_summary(p: &[u8]) -> String {
    summary(p)
}
