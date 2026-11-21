// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2020 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/dnsx/rethinkdns.go

//! Blockstamps (`backend.RDNS`): which blocklists a user selected, packed as a 16-bit header (one bit per group of
//! 16 lists) followed by one 16-bit word per set header bit, encoded as `1:<base64url>` or `1-<base32>`; legacy
//! `0:` stamps are url-escaped base64 of a UTF-8 string whose runes are the words.

use crate::goenc::{self, Codec};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::path::Path;

/// `backend.EB32` / `backend.EB64`.
pub const EB32: i64 = 0;
pub const EB64: i64 = 1;

pub const ERR_REMOTE: &str = "op not valid in remote block mode";
pub const ERR_NO_STAMPS: &str = "no stamp set";
pub const ERR_MISSING_CSV: &str = "zero comma-separated flags";

const COLONSEP: &str = ":";
const HYPHENSEP: &str = "-";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Local,
    Remote,
}

/// One selected blocklist: its id and `group:name`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListInfo {
    pub pos: usize,
    pub name: String,
}

/// firestack `rethinkdns`.
pub struct Rdns {
    /// value -> subgroup:vname
    flags: Vec<String>,
    /// uname -> subgroup:vname
    tags: HashMap<String, String>,
    mode: Mode,
    stamp: Mutex<String>,
}

/// firestack `load`: filetag.json → (flags by value, names by uname).
pub fn load(path: &Path) -> Result<(Vec<String>, HashMap<String, String>), String> {
    let data = std::fs::read(path).map_err(|e| e.to_string())?;
    let obj: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(&data).map_err(|e| e.to_string())?;
    let mut rflags = vec![String::new(); obj.len()];
    let mut fdata = HashMap::with_capacity(obj.len());
    let s = |v: &serde_json::Value, k: &str| {
        v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string()
    };
    for (key, v) in &obj {
        if !v.is_object() {
            continue;
        }
        let index = v.get("value").and_then(|x| x.as_f64()).unwrap_or(0.0) as i64;
        let mut name = s(v, "vname");
        let mut subgroup = s(v, "subg");
        let group = s(v, "group");
        if subgroup.is_empty() {
            subgroup = group.clone();
        }
        if name.is_empty() {
            name = subgroup;
            subgroup = group;
        }
        let full = format!("{subgroup}:{name}");
        // firestack indexes out of range (and panics) on such files
        if index < 0 || index as usize >= rflags.len() {
            return Err(format!("blocklist {key}: value {index} out of range"));
        }
        rflags[index as usize] = full.clone();
        fdata.insert(key.clone(), full);
    }
    Ok((rflags, fdata))
}

impl Rdns {
    pub fn new(flags: Vec<String>, tags: HashMap<String, String>, mode: Mode) -> Self {
        Rdns {
            flags,
            tags,
            mode,
            stamp: Mutex::new(String::new()),
        }
    }

    pub fn from_filetag(path: &Path, mode: Mode) -> Result<Self, String> {
        let (flags, tags) = load(path)?;
        Ok(Self::new(flags, tags, mode))
    }

    pub fn on_device_block(&self) -> bool {
        self.mode == Mode::Local
    }

    pub fn get_stamp(&self) -> Result<String, String> {
        if !self.on_device_block() {
            return Err(ERR_REMOTE.into());
        }
        Ok(self.stamp.lock().clone())
    }

    pub fn set_stamp(&self, stamp: &str) -> Result<(), String> {
        if !self.on_device_block() {
            return Err(ERR_REMOTE.into());
        }
        let nm = if stamp.is_empty() {
            String::new()
        } else {
            self.normalize_stamp(stamp)? // also validates the stamp
        };
        *self.stamp.lock() = nm;
        Ok(())
    }

    /// Blockstamp for comma-separated blocklist ids.
    pub fn flags_to_stamp(&self, flagscsv: &str, enctyp: i64) -> Result<String, String> {
        let fstr: Vec<&str> = flagscsv.split(',').collect();
        if fstr.first().is_none_or(|s| s.is_empty()) {
            return Err(ERR_MISSING_CSV.into());
        }
        let flags = fstr
            .iter()
            .map(|s| goenc::atoi(s).map(|v| v as u16))
            .collect::<Result<Vec<u16>, String>>()?;
        encode("1", &flagtostamp(&flags), enctyp)
    }

    /// Comma-separated blocklist ids for a stamp.
    pub fn stamp_to_flags(&self, stamp: &str) -> Result<String, String> {
        let l = self.stamp_to_blocklist(stamp)?;
        Ok(l.iter()
            .map(|x| x.pos.to_string())
            .collect::<Vec<_>>()
            .join(","))
    }

    /// Comma-separated `group:name` for a stamp.
    pub fn stamp_to_names(&self, stamp: &str) -> Result<String, String> {
        let l = self.stamp_to_blocklist(stamp)?;
        Ok(l.into_iter().map(|x| x.name).collect::<Vec<_>>().join(","))
    }

    pub fn stamp_to_blocklist(&self, stamp: &str) -> Result<Vec<ListInfo>, String> {
        if stamp.is_empty() {
            return Err(ERR_NO_STAMPS.into());
        }
        let isb32 = is_b32(stamp);
        let (versep, enctyp) = if isb32 {
            (HYPHENSEP, EB32)
        } else {
            (COLONSEP, EB64)
        };
        let s: Vec<&str> = stamp.split(versep).collect();
        if s.len() > 1 {
            self.decode(s[1], s[0], enctyp)
        } else {
            self.decode(stamp, "0", enctyp)
        }
    }

    /// `uname`s → `group:name`, skipping unknown ones.
    pub fn key_to_names(&self, list: &[String]) -> Vec<String> {
        list.iter()
            .filter_map(|l| self.tags.get(l).filter(|x| !x.is_empty()).cloned())
            .collect()
    }

    fn decode(&self, stamp: &str, ver: &str, enctyp: i64) -> Result<Vec<ListInfo>, String> {
        let haspad = stamp.contains('=');
        let (mut decoder, decoder32) = if haspad {
            (Codec::Std, Codec::B32)
        } else {
            (Codec::RawStd, Codec::RawB32)
        };
        let text: Vec<u8> = match ver {
            "0" => goenc::unescape(stamp, true)?,
            "1" => {
                decoder = if haspad { Codec::Url } else { Codec::RawUrl };
                stamp.as_bytes().to_vec()
            }
            _ => return Err(format!("version {ver} unsupported")),
        };
        // non-UTF-8 input can only fail to decode; any non-symbol byte will do as its stand-in
        let text = String::from_utf8(text).unwrap_or_else(|_| "\u{1}".into());
        let buf = if enctyp == EB32 {
            decoder32.decode(&text.to_uppercase())?
        } else {
            decoder.decode(&text)?
        };
        let u16s = if ver == "0" {
            goenc::runes_u16(&buf)
        } else {
            goenc::le_u16(&buf)
        };
        self.flagstoinfo(&u16s)
    }

    fn flagstoinfo(&self, flags: &[u16]) -> Result<Vec<ListInfo>, String> {
        // firestack indexes flags[0] unconditionally (and panics on an empty stamp)
        let Some(&header) = flags.first() else {
            return Err("empty flags".into());
        };
        let tag_indices = header_indices(header);
        if tag_indices.len() != flags.len() - 1 {
            return Err(format!(
                "{tag_indices:?} {flags:?} flags and header mismatch"
            ));
        }
        let mut values = Vec::new();
        for (i, &flag) in flags.iter().enumerate().skip(1) {
            let index = tag_indices[i - 1];
            let mut mask: u16 = 0x8000;
            for j in 0..16 {
                if flag << j == 0 {
                    break;
                }
                if flag & mask == mask {
                    let pos = index * 16 + j;
                    // stamps may encode more blocklists than are loaded (firestack#5)
                    if pos < self.flags.len() {
                        values.push(ListInfo {
                            pos,
                            name: self.flags[pos].clone(),
                        });
                    }
                }
                mask >>= 1;
            }
        }
        Ok(values)
    }

    /// Converts base32 stamps to padded base64url (`1:`), which the trie lookup expects.
    fn normalize_stamp(&self, s: &str) -> Result<String, String> {
        let flagscsv = self.stamp_to_flags(s)?;
        if !is_b32(s) {
            return Ok(s.to_string());
        }
        self.flags_to_stamp(&flagscsv, EB64)
    }
}

/// `1:YAYBACABEDAgAA==` is base64, `1-madacabaaeidaiaa` base32: base32 when a hyphen comes before any colon.
fn is_b32(stamp: &str) -> bool {
    let colon = stamp.find(COLONSEP);
    match stamp.find(HYPHENSEP) {
        Some(h) => colon.is_none_or(|c| h < c),
        None => false,
    }
}

/// Indices (MSB first) of the set bits of a header word.
pub(crate) fn header_indices(header: u16) -> Vec<usize> {
    let mut out = Vec::new();
    let mut mask: u16 = 0x8000;
    for i in 0..16 {
        if header << i == 0 {
            break;
        }
        if header & mask == mask {
            out.push(i);
        }
        mask >>= 1;
    }
    out
}

/// `x << s` for u16 with Go semantics: shifts of 16 or more give 0.
fn shl(x: u16, s: u16) -> u16 {
    x.checked_shl(s as u32).unwrap_or(0)
}
fn shr(x: u16, s: u16) -> u16 {
    x.checked_shr(s as u32).unwrap_or(0)
}

/// firestack `flagtostamp`: blocklist ids → packed words (header first).
pub fn flagtostamp(fl: &[u16]) -> Vec<u16> {
    let mut res: Vec<u16> = vec![0];
    for &val in fl {
        let hindex = val / 16;
        let pos = val % 16;
        if res.len() == 1 {
            res[0] |= shl(1, 15u16.wrapping_sub(hindex));
            res.push(shl(1, 15u16.wrapping_sub(pos)));
            continue;
        }
        let mm = 16 - hindex as i64;
        if !(0..crate::bits::MASK_LO.len() as i64).contains(&mm) {
            continue; // should not happen
        }
        let h = res[0];
        let hmask = h & crate::bits::MASK_LO[mm as usize];
        let databit = shr(h, 15u16.wrapping_sub(hindex));
        let dataindex = hmask.count_ones() as usize + 1;
        if databit & 0x1 == 1 {
            if let Some(n) = res.get_mut(dataindex) {
                *n |= shl(1, 15u16.wrapping_sub(pos));
            }
        } else {
            res[0] |= shl(1, 15u16.wrapping_sub(hindex));
            let n = shl(1, 15u16.wrapping_sub(pos));
            res.insert(dataindex.min(res.len()), n);
        }
    }
    res
}

/// firestack `encode`: always version 1; base64url is padded (the trie lookup expects it).
pub fn encode(ver: &str, u16s: &[u16], enctyp: i64) -> Result<String, String> {
    if ver != "1" {
        return Err(format!(
            "version {ver} unsupported / len(input): {}",
            u16s.len()
        ));
    }
    let buf = goenc::u16_le(u16s);
    if enctyp == EB32 {
        return Ok(format!(
            "{ver}{HYPHENSEP}{}",
            Codec::RawB32.encode(&buf).to_lowercase()
        ));
    }
    Ok(format!("{ver}{COLONSEP}{}", Codec::Url.encode(&buf)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rdns() -> Rdns {
        let flags = (0..200).map(|i| format!("g:{i}")).collect();
        Rdns::new(flags, HashMap::new(), Mode::Local)
    }

    #[test]
    fn roundtrip() {
        let r = rdns();
        let s = r.flags_to_stamp("1,17,33,170", EB32).unwrap();
        assert!(s.starts_with("1-"));
        assert_eq!(r.stamp_to_flags(&s).unwrap(), "1,17,33,170");
        let b = r.flags_to_stamp("170,1,33,17", EB64).unwrap();
        assert!(b.starts_with("1:"));
        assert_eq!(r.stamp_to_flags(&b).unwrap(), "1,17,33,170");
        r.set_stamp(&s).unwrap();
        assert_eq!(
            r.get_stamp().unwrap(),
            b,
            "base32 normalizes to padded base64url"
        );
        assert_eq!(r.flags_to_stamp("", EB32).unwrap_err(), ERR_MISSING_CSV);
        assert!(r.stamp_to_flags("").is_err());
        let rem = Rdns::new(vec![], HashMap::new(), Mode::Remote);
        assert_eq!(rem.set_stamp("x").unwrap_err(), ERR_REMOTE);
    }
}
