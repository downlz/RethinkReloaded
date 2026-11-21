// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2015 Keita Sone (critbitgo), MIT License: see engine/LICENSES/MIT-critbitgo.txt
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: github.com/k-sone/critbitgo@v1.4.0:critbit.go (used by celzero/firestack@d3d530ea3e)

//! A faithful port of critbitgo's crit-bit trie. The trie shape is fully determined by its key set, so traversal
//! order and the pruning done by `walk_match`/`lookup` (in `net.rs`) match firestack exactly.

/// Most significant set bit of each byte value (critbitgo `msbMatrix`).
const fn msb(b: u8) -> u8 {
    let mut x = b;
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x & !(x >> 1)
}

pub(crate) enum Node<V> {
    Empty,
    Internal(Box<Internal<V>>),
    External(Box<External<V>>),
}

pub(crate) struct Internal<V> {
    pub child: [Node<V>; 2],
    pub offset: usize,
    pub bit: u8,
    /// if true, key of child[1] contains key of child[0]
    pub cont: bool,
}

pub(crate) struct External<V> {
    pub key: Vec<u8>,
    pub value: V,
}

impl<V> External<V> {
    /// Returns None when `key` equals this node's key (critbitgo: offset -1).
    fn critical_bit(&self, key: &[u8]) -> Option<(usize, u8, bool)> {
        let (nlen, klen) = (self.key.len(), key.len());
        let mlen = nlen.min(klen);
        if let Some((offset, (a, b))) = key
            .iter()
            .zip(self.key.iter())
            .enumerate()
            .find(|(_, (a, b))| a != b)
        {
            return Some((offset, msb(a ^ b), false));
        }
        if nlen < klen {
            Some((mlen, msb(key[mlen]), true))
        } else if nlen > klen {
            Some((mlen, msb(self.key[mlen]), true))
        } else {
            None
        }
    }
}

impl<V> Internal<V> {
    pub fn direction(&self, key: &[u8]) -> usize {
        if self.offset < key.len() && (key[self.offset] & self.bit != 0 || self.cont) {
            1
        } else {
            0
        }
    }
}

pub struct Trie<V> {
    pub(crate) root: Node<V>,
    size: usize,
}

impl<V> Default for Trie<V> {
    fn default() -> Self {
        Trie {
            root: Node::Empty,
            size: 0,
        }
    }
}

impl<V: Clone> Trie<V> {
    pub fn new() -> Self {
        Self::default()
    }

    fn search(&self, key: &[u8]) -> &Node<V> {
        let mut n = &self.root;
        while let Node::Internal(i) = n {
            n = &i.child[i.direction(key)];
        }
        n
    }

    fn search_mut(&mut self, key: &[u8]) -> &mut Node<V> {
        let mut n = &mut self.root;
        while let Node::Internal(i) = n {
            let d = i.direction(key);
            n = &mut i.child[d];
        }
        n
    }

    pub fn contains(&self, key: &[u8]) -> bool {
        matches!(self.search(key), Node::External(e) if e.key == key)
    }

    pub fn get(&self, key: &[u8]) -> Option<V> {
        match self.search(key) {
            Node::External(e) if e.key == key => Some(e.value.clone()),
            _ => None,
        }
    }

    fn insert_impl(&mut self, key: &[u8], value: V, replace: bool) -> bool {
        if self.size == 0 {
            self.root = Node::External(Box::new(External {
                key: key.to_vec(),
                value,
            }));
            self.size = 1;
            return true;
        }
        let crit = match self.search(key) {
            Node::External(e) => e.critical_bit(key),
            _ => unreachable!("non-empty trie search ends at an external node"),
        };
        let Some((off, bit, cont)) = crit else {
            if replace && let Node::External(e) = self.search_mut(key) {
                e.value = value;
                return true;
            }
            return false;
        };
        let mut new = Box::new(Internal {
            child: [Node::Empty, Node::Empty],
            offset: off,
            bit,
            cont,
        });
        let dir = new.direction(key);
        new.child[dir] = Node::External(Box::new(External {
            key: key.to_vec(),
            value,
        }));

        let mut wherep = &mut self.root;
        loop {
            let descend = match wherep {
                Node::Internal(i) => !(i.offset > off || (i.offset == off && i.bit < bit)),
                _ => false,
            };
            if !descend {
                break;
            }
            wherep = match wherep {
                Node::Internal(i) => {
                    let d = i.direction(key);
                    &mut i.child[d]
                }
                _ => unreachable!(),
            };
        }
        new.child[1 - dir] = std::mem::replace(wherep, Node::Empty);
        *wherep = Node::Internal(new);
        self.size += 1;
        true
    }

    /// Inserts `key` if absent; returns false (and keeps the old value) if present.
    pub fn insert(&mut self, key: &[u8], value: V) -> bool {
        self.insert_impl(key, value, false)
    }

    /// Inserts or replaces.
    pub fn set(&mut self, key: &[u8], value: V) {
        self.insert_impl(key, value, true);
    }

    pub fn delete(&mut self, key: &[u8]) -> Option<V> {
        if self.size == 0 {
            return None;
        }
        // record the path, then verify the leaf
        let mut dirs = Vec::new();
        let mut n = &self.root;
        while let Node::Internal(i) = n {
            let d = i.direction(key);
            dirs.push(d);
            n = &i.child[d];
        }
        match n {
            Node::External(e) if e.key == key => {}
            _ => return None,
        }
        self.size -= 1;
        let Some((&last, upper)) = dirs.split_last() else {
            return match std::mem::replace(&mut self.root, Node::Empty) {
                Node::External(e) => Some(e.value),
                _ => unreachable!(),
            };
        };
        let mut gp = &mut self.root;
        for &d in upper {
            gp = match gp {
                Node::Internal(i) => &mut i.child[d],
                _ => unreachable!(),
            };
        }
        let Node::Internal(mut i) = std::mem::replace(gp, Node::Empty) else {
            unreachable!()
        };
        let removed = std::mem::replace(&mut i.child[last], Node::Empty);
        *gp = std::mem::replace(&mut i.child[1 - last], Node::Empty);
        match removed {
            Node::External(e) => Some(e.value),
            _ => unreachable!(),
        }
    }

    pub fn clear(&mut self) {
        self.root = Node::Empty;
        self.size = 0;
    }

    pub fn len(&self) -> usize {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Calls `handle` for every key with `prefix`, in trie order; stops when `handle` returns false.
    pub fn all_prefixed(&self, prefix: &[u8], handle: &mut dyn FnMut(&[u8], &V) -> bool) -> bool {
        if self.size == 0 {
            return true;
        }
        let mut p = &self.root;
        let mut top = p;
        if !prefix.is_empty() {
            while let Node::Internal(q) = p {
                p = &q.child[q.direction(prefix)];
                if q.offset < prefix.len() {
                    top = p;
                }
            }
            match p {
                Node::External(e) if e.key.starts_with(prefix) => {}
                _ => return true,
            }
        }
        all_prefixed_rec(top, handle)
    }

    /// The longest stored key that is a prefix of `given` (critbitgo's search order).
    pub fn longest_prefix(&self, given: &[u8]) -> Option<(Vec<u8>, V)> {
        if self.size == 0 {
            return None;
        }
        longest_prefix_rec(&self.root, given)
    }
}

fn all_prefixed_rec<V>(n: &Node<V>, handle: &mut dyn FnMut(&[u8], &V) -> bool) -> bool {
    match n {
        Node::Internal(i) => {
            for c in &i.child {
                if !all_prefixed_rec(c, handle) {
                    return false;
                }
            }
            true
        }
        Node::External(e) => handle(&e.key, &e.value),
        Node::Empty => true,
    }
}

fn longest_prefix_rec<V: Clone>(n: &Node<V>, key: &[u8]) -> Option<(Vec<u8>, V)> {
    match n {
        Node::Internal(i) => {
            let d = i.direction(key);
            if let Some(r) = longest_prefix_rec(&i.child[d], key) {
                return Some(r);
            }
            if d == 1 {
                longest_prefix_rec(&i.child[0], key)
            } else {
                None
            }
        }
        Node::External(e) if key.starts_with(&e.key) => Some((e.key.clone(), e.value.clone())),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_get_delete_order() {
        let mut t = Trie::new();
        for k in ["b", "a", "ab", "abc", "c", ""] {
            assert!(t.insert(k.as_bytes(), k.to_string()));
        }
        assert!(!t.insert(b"a", "x".into()));
        assert_eq!(t.get(b"a").as_deref(), Some("a"));
        t.set(b"a", "A".into());
        assert_eq!(t.get(b"a").as_deref(), Some("A"));
        let mut keys = vec![];
        t.all_prefixed(b"", &mut |k, _| {
            keys.push(String::from_utf8(k.to_vec()).unwrap());
            true
        });
        assert_eq!(keys, ["", "a", "ab", "abc", "b", "c"]);
        let mut pre = vec![];
        t.all_prefixed(b"ab", &mut |k, _| {
            pre.push(String::from_utf8(k.to_vec()).unwrap());
            true
        });
        assert_eq!(pre, ["ab", "abc"]);
        assert_eq!(
            t.longest_prefix(b"abz").map(|(k, _)| k),
            Some(b"ab".to_vec())
        );
        assert_eq!(t.delete(b"ab").as_deref(), Some("ab"));
        assert_eq!(t.delete(b"ab"), None);
        assert_eq!(t.len(), 5);
        for k in ["", "a", "abc", "b", "c"] {
            assert!(t.delete(k.as_bytes()).is_some(), "{k}");
        }
        assert!(t.is_empty());
    }
}
