// Copyright (c) 2026 RethinkReloaded contributors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Go standard library behaviour that blockstamps depend on: `encoding/base64` and `encoding/base32` decoders
//! (non-strict: `\r`/`\n` ignored, non-zero trailing bits accepted), `net/url` unescaping, `strconv.Atoi`, and
//! `[]rune(string(b))` (one U+FFFD per invalid UTF-8 byte).

use data_encoding::{BitOrder, Encoding, Specification};
use std::sync::LazyLock;

const B64_STD: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_URL: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const B32_STD: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn spec(symbols: &str, pad: bool) -> Encoding {
    let mut s = Specification::new();
    s.symbols.push_str(symbols);
    s.bit_order = BitOrder::MostSignificantFirst;
    s.check_trailing_bits = false;
    if pad {
        s.padding = Some('=');
    }
    s.ignore.push_str("\r\n");
    s.encoding().expect("valid encoding spec")
}

/// The decoders firestack and gotrie use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Codec {
    /// `base64.StdEncoding`
    Std,
    /// `base64.RawStdEncoding`
    RawStd,
    /// `base64.URLEncoding`
    Url,
    /// `base64.RawURLEncoding`
    RawUrl,
    /// `base32.StdEncoding` (padded)
    B32,
    /// `base32.StdEncoding.WithPadding(NoPadding)`
    RawB32,
}

static CODECS: LazyLock<[Encoding; 6]> = LazyLock::new(|| {
    [
        spec(B64_STD, true),
        spec(B64_STD, false),
        spec(B64_URL, true),
        spec(B64_URL, false),
        spec(B32_STD, true),
        spec(B32_STD, false),
    ]
});

impl Codec {
    fn enc(self) -> &'static Encoding {
        &CODECS[self as usize]
    }
    pub fn decode(self, s: &str) -> Result<Vec<u8>, String> {
        let err = |p: usize| format!("illegal base64 data at input byte {p}");
        if self == Codec::RawB32 {
            // Go drops a trailing quantum of 1, 3 or 6 symbols without error (6 symbols carry 3 bytes, which are
            // lost); every symbol is still validated
            let b: Vec<u8> = s.bytes().filter(|c| *c != b'\r' && *c != b'\n').collect();
            if let Some(p) = b.iter().position(|c| !B32_STD.as_bytes().contains(c)) {
                return Err(err(p));
            }
            let keep = match b.len() % 8 {
                1 | 3 | 6 => b.len() - b.len() % 8,
                _ => b.len(),
            };
            return self.enc().decode(&b[..keep]).map_err(|e| err(e.position));
        }
        self.enc().decode(s.as_bytes()).map_err(|e| err(e.position))
    }
    pub fn encode(self, b: &[u8]) -> String {
        self.enc().encode(b)
    }
}

fn unhex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// `url.QueryUnescape` (`plus_is_space`) or `url.PathUnescape`; the result may be invalid UTF-8, as in Go.
pub fn unescape(s: &str, plus_is_space: bool) -> Result<Vec<u8>, String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let hi = b.get(i + 1).copied().and_then(unhex);
                let lo = b.get(i + 2).copied().and_then(unhex);
                match (hi, lo) {
                    (Some(h), Some(l)) => out.push(h << 4 | l),
                    _ => {
                        let end = (i + 3).min(b.len());
                        return Err(format!(
                            "invalid URL escape {:?}",
                            String::from_utf8_lossy(&b[i..end])
                        ));
                    }
                }
                i += 3;
            }
            b'+' if plus_is_space => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    Ok(out)
}

/// `[]rune(string(b))` truncated to u16 per rune: invalid UTF-8 yields U+FFFD for each invalid byte.
pub fn runes_u16(b: &[u8]) -> Vec<u16> {
    let mut out = Vec::with_capacity(b.len());
    for chunk in b.utf8_chunks() {
        out.extend(chunk.valid().chars().map(|c| c as u32 as u16));
        out.extend(std::iter::repeat_n(0xFFFD, chunk.invalid().len()));
    }
    out
}

/// Little-endian u16 pairs; an odd trailing byte is dropped.
pub fn le_u16(b: &[u8]) -> Vec<u16> {
    b.as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect()
}

pub fn u16_le(u: &[u16]) -> Vec<u8> {
    u.iter().flat_map(|v| v.to_le_bytes()).collect()
}

/// `strconv.Atoi` on a 64-bit platform.
pub fn atoi(s: &str) -> Result<i64, String> {
    let digits = s.strip_prefix(['+', '-']).unwrap_or(s);
    if digits.is_empty() || !digits.bytes().all(|c| c.is_ascii_digit()) {
        return Err(format!("strconv.Atoi: parsing {s:?}: invalid syntax"));
    }
    s.parse::<i64>()
        .map_err(|_| format!("strconv.Atoi: parsing {s:?}: value out of range"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_compat() {
        assert_eq!(Codec::Std.decode("AA==").unwrap(), vec![0]);
        assert!(Codec::Std.decode("AA=").is_err());
        assert!(Codec::Std.decode("AA").is_err());
        assert_eq!(Codec::RawStd.decode("AA").unwrap(), vec![0]);
        assert!(Codec::RawStd.decode("AA==").is_err());
        assert_eq!(
            Codec::RawStd.decode("AB").unwrap(),
            vec![0],
            "trailing bits ignored"
        );
        assert_eq!(
            Codec::Std.decode("A\nA==").unwrap(),
            vec![0],
            "newlines ignored"
        );
        assert!(Codec::RawStd.decode("A").is_err());
        assert_eq!(Codec::RawB32.decode("ME").unwrap(), b"a");
        assert_eq!(Codec::RawB32.decode("M").unwrap(), b"");
        assert_eq!(
            Codec::RawB32.decode("MFRGGZ").unwrap(),
            b"",
            "Go drops 6-symbol tails"
        );
        assert_eq!(Codec::RawB32.decode("MFRGGZDFMZT").unwrap(), b"abcde");
        assert_eq!(Codec::RawB32.decode("MZXW6YTBAB").unwrap(), b"fooba\0");
        assert!(Codec::RawB32.decode("ME=").is_err() && Codec::RawB32.decode("M1").is_err());
        assert_eq!(Codec::B32.decode("ME======").unwrap(), b"a");
        assert_eq!(Codec::RawB32.encode(b"a"), "ME");
        assert_eq!(Codec::Url.encode(&[0xfb, 0xff]), "-_8=");
        assert_eq!(unescape("a%2Bb+c", true).unwrap(), b"a+b c");
        assert_eq!(unescape("a%2Bb+c", false).unwrap(), b"a+b+c");
        assert!(unescape("%zz", true).is_err());
        assert!(unescape("%4", true).is_err());
        assert_eq!(
            runes_u16(&[0x41, 0xE2, 0x82, 0x41]),
            vec![0x41, 0xFFFD, 0xFFFD, 0x41]
        );
        assert_eq!(runes_u16("ï¿½".as_bytes()), vec![0xEF, 0xBF, 0xBD]);
        assert_eq!(atoi("+5"), Ok(5));
        assert_eq!(atoi("-1"), Ok(-1));
        assert!(atoi(" 5").is_err() && atoi("").is_err() && atoi("+").is_err());
        assert!(atoi("99999999999999999999").is_err());
    }
}
