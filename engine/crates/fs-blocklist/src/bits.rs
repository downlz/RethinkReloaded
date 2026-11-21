// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2025 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/gotrie@a2756ab2f6bd:trie/bitstring.go
// Derived-From: celzero/gotrie@a2756ab2f6bd:trie/rankdirectory.go
// Derived-From: celzero/gotrie@a2756ab2f6bd:trie/commons.go (Bit0)

//! Bit strings over little-endian u16 words (read MSB first within a word) and the rank directory of the
//! succinct trie. Arithmetic follows gotrie exactly, except that reads outside the data return zero bits where
//! gotrie would index out of range and panic.

use std::ops::Deref;

pub const W: i64 = 16;
pub const L2: i64 = 32;

/// gotrie `MaskHi[16]`: `0xffff >> i`, plus a trailing 0.
pub const MASK_HI: [u16; 17] = {
    let mut m = [0u16; 17];
    let mut i = 0;
    while i < 16 {
        m[i] = 0xffff >> i;
        i += 1;
    }
    m
};

/// gotrie `MaskLo[16]`: `0xffff << i`, plus a trailing 0.
pub const MASK_LO: [u16; 17] = {
    let mut m = [0u16; 17];
    let mut i = 0;
    while i < 16 {
        m[i] = 0xffff << i;
        i += 1;
    }
    m
};

/// A bit string backed by any byte buffer (a memory map or a `Vec<u8>`); an odd trailing byte is ignored, as in
/// gotrie's `bytesToUint16`.
pub struct BinStr<B> {
    bytes: B,
    words: i64,
}

impl<B: Deref<Target = [u8]>> BinStr<B> {
    pub fn new(bytes: B) -> Self {
        let words = (bytes.len() / 2) as i64;
        BinStr { bytes, words }
    }

    /// Size in bits.
    pub fn size(&self) -> i64 {
        self.words * W
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[inline]
    fn word(&self, i: i64) -> u16 {
        if i < 0 || i >= self.words {
            return 0;
        }
        let i = i as usize * 2;
        u16::from_le_bytes([self.bytes[i], self.bytes[i + 1]])
    }

    /// gotrie `binstr.get`: `n` bits starting at bit `p`, as an integer.
    pub fn get(&self, p: i64, n: i64) -> u32 {
        if p < 0 {
            return 0;
        }
        let r = p % W;
        let mask = MASK_HI[r as usize];
        if r + n <= W {
            ((self.word(p / W) & mask) as u32) >> (W - r - n)
        } else {
            let (mut p, mut n) = (p, n);
            let mut result = (self.word(p / W) & mask) as u32;
            let l = W - r;
            p += l;
            n -= l;
            while n >= W {
                result = (result << W) | self.word(p / W) as u32;
                p += W;
                n -= W;
            }
            if n > 0 {
                result = (result << n) | (self.word(p / W) >> (W - n)) as u32;
            }
            result
        }
    }

    /// gotrie `binstr.pos0`: position of the `n`th 0 bit at or after `i`.
    pub fn pos0(&self, i: i64, n: i64) -> i64 {
        if n < 0 {
            return 0;
        }
        let (mut i, mut n) = (i, n);
        let mut step: i64 = 16;
        let mut index = i;
        while n > 0 {
            let d = self.get(i, step);
            let bits0 = step - d.count_ones() as i64;
            if n - bits0 < 0 {
                step = n.max(step / 2);
                continue;
            }
            n -= bits0;
            i += step;
            let diff = if n == 0 { bit0(d as i64, 1, step) } else { 1 };
            index = i - diff;
        }
        index
    }
}

/// gotrie `bit0p`: (index, scanned).
fn bit0p(n: i64, p: i64) -> (i64, i64) {
    if p == 0 {
        return (0, 0);
    }
    if n == 0 && p == 1 {
        return (1, 1);
    }
    let (mut n, mut c, mut i) = (n, 0i64, 0i64);
    while n > 0 && p > c {
        if n < (n ^ 0x1) {
            c += 1;
        }
        i += 1;
        n >>= 1;
    }
    (if p == c { i } else { 0 }, i)
}

/// gotrie `Bit0`.
pub fn bit0(n: i64, p: i64, pad: i64) -> i64 {
    let (index, scanned) = bit0p(n, p);
    if scanned <= 0 {
        return scanned;
    }
    if index > 0 {
        return scanned;
    }
    if pad > scanned { scanned + 1 } else { 0 }
}

/// gotrie `rankdir`: `dir` is the rank directory (rd), `data` the trie (td).
pub struct RankDir {
    l1_bits: i64,
    l2_size: i64,
}

impl RankDir {
    /// gotrie also derives `l2Bits` and `sectionBits` from `l1Size`, but never reads them.
    pub fn new(num_bits: i64, l2_size: i64) -> Self {
        RankDir {
            l1_bits: (num_bits as f64).log2().ceil() as i64,
            l2_size,
        }
    }

    /// gotrie `rankdir.rank(0, x)`.
    pub fn rank<D, T>(&self, dir: &BinStr<D>, data: &BinStr<T>, x: i64) -> i64
    where
        D: Deref<Target = [u8]>,
        T: Deref<Target = [u8]>,
    {
        let mut rank: i64 = -1;
        let mut x = x;
        if x >= self.l2_size {
            let section_pos = (x / self.l2_size) * self.l1_bits;
            rank = dir.get(section_pos - self.l1_bits, self.l1_bits) as i64;
            x %= self.l2_size;
        }
        if x > 0 { data.pos0(rank + 1, x) } else { rank }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_and_bits() {
        assert_eq!((MASK_HI[1], MASK_HI[15], MASK_HI[16]), (0x7fff, 0x0001, 0));
        assert_eq!((MASK_LO[1], MASK_LO[15], MASK_LO[16]), (0xfffe, 0x8000, 0));
        // words 0xA5F0, 0x0F0F (stored little-endian)
        let b = BinStr::new(vec![0xF0, 0xA5, 0x0F, 0x0F]);
        assert_eq!(b.size(), 32);
        assert_eq!(b.get(0, 4), 0xA);
        assert_eq!(b.get(4, 8), 0x5F);
        assert_eq!(b.get(12, 8), 0x00);
        assert_eq!(b.get(8, 16), 0xF00F);
        assert_eq!(b.get(0, 32), 0xA5F0_0F0F);
        assert_eq!(b.get(40, 4), 0, "past the end reads zeros");
        assert_eq!(bit0(0, 1, 16), 1);
        assert_eq!(bit0(0b1011, 1, 16), 3);
        assert_eq!(bit0(0xffff, 1, 16), 0);
        assert_eq!(bit0(0x7fff, 1, 16), 16);
        assert_eq!(bit0(0x7fff, 1, 15), 0);
    }
}
