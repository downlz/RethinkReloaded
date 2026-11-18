// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Derived-From: celzero/firestack@d3d530ea3e:intra/backend/core_iptree.go

//! `IpTree`: a thread-safe trie of IP CIDR routes whose values are CSVs (`Vsep`), used by rethink-app for IP
//! firewall rules and proxy routing. Ordering of all CSV outputs follows critbitgo's trie order.

use crate::net::{IpNet, Net, ip2cidr, key_to_string};
use parking_lot::RwLock;

/// values separator (csv)
pub const VSEP: &str = ",";
/// key separator (csv)
pub const KSEP: &str = ",";
/// key@csv(v) delimiter
pub const KDELIM: &str = "@";
/// k1:v1|k2:v2 separator
pub const KVSEP: &str = "|";

#[derive(Default)]
struct Nets {
    t4: Net,
    t6: Net,
}

impl Nets {
    fn net(&self, r: &IpNet) -> &Net {
        if r.is_v4() { &self.t4 } else { &self.t6 }
    }
    fn net_mut(&mut self, r: &IpNet) -> &mut Net {
        if r.is_v4() {
            &mut self.t4
        } else {
            &mut self.t6
        }
    }
}

#[derive(Default)]
pub struct IpTree {
    t: RwLock<Nets>,
}

pub type Result<T> = std::result::Result<T, String>;

impl IpTree {
    pub fn new() -> Self {
        Self::default()
    }

    // ------------------------------------------------ primitives (each takes the lock once)

    fn get_r(&self, r: &IpNet) -> String {
        self.t.read().net(r).get(r).unwrap_or_default()
    }

    fn set_r(&self, r: &IpNet, v: &str) -> Result<()> {
        self.t.write().net_mut(r).add(r, v.to_string())
    }

    fn del_r(&self, r: &IpNet) -> bool {
        self.t.write().net_mut(r).delete(r).is_some()
    }

    fn walk(&self, r: &IpNet, f: &mut dyn FnMut(&[u8], &String) -> bool) {
        self.t.read().net(r).walk_match(r, f);
    }

    // ------------------------------------------------ API (core_iptree.go)

    /// Adds value `v` to the cidr route.
    pub fn add(&self, cidr: &str, v: &str) -> Result<()> {
        let r = ip2cidr(cidr)?;
        let x = self.get_r(&r);
        if v.is_empty() || x == v {
            Ok(())
        } else if x.is_empty() {
            self.set_r(&r, v)
        } else if x.contains(v) && x.split(VSEP).any(|val| val == v) {
            Ok(()) // v is definitely in x
        } else {
            self.set_r(&r, &format!("{x}{VSEP}{v}"))
        }
    }

    /// Sets cidr route to `v`, overwriting any previous value (an empty `v` just deletes the route).
    pub fn set(&self, cidr: &str, v: &str) -> Result<()> {
        self.del(cidr);
        self.add(cidr, v)
    }

    /// Deletes the cidr route. Returns true if it was found.
    pub fn del(&self, cidr: &str) -> bool {
        match ip2cidr(cidr) {
            Ok(r) => self.del_r(&r),
            Err(_) => false,
        }
    }

    /// Removes value `v` (all occurrences) from the cidr route.
    pub fn esc(&self, cidr: &str, v: &str) -> bool {
        let Ok(r) = ip2cidr(cidr) else { return false };
        let x = self.get_r(&r);
        if x.is_empty() || v.is_empty() {
            false
        } else if x == v {
            self.del_r(&r)
        } else if x.contains(v) {
            let cur: Vec<&str> = x.split(VSEP).filter(|val| *val != v).collect();
            if cur.is_empty() {
                self.del_r(&r)
            } else {
                self.set_r(&r, &cur.join(VSEP)).is_ok()
            }
        } else {
            false
        }
    }

    pub fn get(&self, cidr: &str) -> Result<String> {
        let r = ip2cidr(cidr)?;
        Ok(self.get_r(&r))
    }

    pub fn has(&self, cidr: &str) -> Result<bool> {
        let r = ip2cidr(cidr)?;
        Ok(self.t.read().net(&r).get(&r).is_some())
    }

    /// Csv of all routes matching cidr, or "".
    pub fn routes(&self, cidr: &str) -> String {
        let Ok(r) = ip2cidr(cidr) else {
            return String::new();
        };
        let mut rt = Vec::new();
        self.walk(&r, &mut |k, _| {
            rt.push(key_to_string(k));
            true
        });
        rt.join(KSEP)
    }

    /// Csv of values of all routes matching cidr, or "".
    pub fn values(&self, cidr: &str) -> String {
        let Ok(r) = ip2cidr(cidr) else {
            return String::new();
        };
        let mut vt = Vec::new();
        self.walk(&r, &mut |_, v| {
            if !v.is_empty() {
                vt.push(v.clone());
            }
            true
        });
        vt.join(VSEP)
    }

    /// `route@csv(value)` of the longest route matching cidr, or "".
    pub fn get_any(&self, cidr: &str) -> Result<String> {
        let r = ip2cidr(cidr)?;
        Ok(match self.t.read().net(&r).match_route(&r) {
            Some((k, v)) => format!("{}{KDELIM}{v}", key_to_string(&k)),
            None => String::new(),
        })
    }

    pub fn has_any(&self, cidr: &str) -> Result<bool> {
        let r = ip2cidr(cidr)?;
        Ok(self.t.read().net(&r).match_route(&r).is_some())
    }

    /// Removes values starting with `like` from the cidr route; returns how many (or -1 on a bad cidr).
    pub fn esc_like(&self, cidr: &str, like: &str) -> i32 {
        let Ok(r) = ip2cidr(cidr) else { return -1 };
        let x = self.get_r(&r);
        if x.is_empty() {
            0
        } else if like.is_empty() {
            self.del_all(cidr)
        } else if x == like {
            i32::from(self.del_r(&r))
        } else if x.contains(like) {
            let old: Vec<&str> = x.split(VSEP).collect();
            let cur: Vec<&str> = old
                .iter()
                .copied()
                .filter(|val| !val.starts_with(like))
                .collect();
            let n = (old.len() - cur.len()) as i32;
            if cur.is_empty() {
                self.del_r(&r);
            } else if cur.len() != old.len() {
                let _ = self.set_r(&r, &cur.join(VSEP));
            }
            n
        } else {
            0
        }
    }

    /// Csv of the cidr route's values that start with `like` (all values if `like` is empty).
    pub fn get_like(&self, cidr: &str, like: &str) -> String {
        let Ok(r) = ip2cidr(cidr) else {
            return String::new();
        };
        let x = self.get_r(&r);
        if x.is_empty() {
            String::new()
        } else if like.is_empty() || x == like {
            x
        } else if x.contains(like) {
            x.split(VSEP)
                .filter(|val| val.starts_with(like))
                .collect::<Vec<_>>()
                .join(VSEP)
        } else {
            String::new()
        }
    }

    /// Csv of matching routes having a value that starts with `like`.
    pub fn routes_like(&self, cidr: &str, like: &str) -> String {
        let Ok(r) = ip2cidr(cidr) else {
            return String::new();
        };
        let mut rt = Vec::new();
        self.walk(&r, &mut |k, s| {
            if !s.is_empty() && s.contains(like) && s.split(VSEP).any(|val| val.starts_with(like)) {
                rt.push(key_to_string(k));
            }
            true
        });
        rt.join(KSEP)
    }

    /// Csv of values, across matching routes, that start with `like`.
    pub fn values_like(&self, cidr: &str, like: &str) -> String {
        let Ok(r) = ip2cidr(cidr) else {
            return String::new();
        };
        let mut vt: Vec<String> = Vec::new();
        self.walk(&r, &mut |_, s| {
            if !s.is_empty() && s.contains(like) {
                vt.extend(
                    s.split(VSEP)
                        .filter(|val| val.starts_with(like))
                        .map(String::from),
                );
            }
            true
        });
        vt.join(VSEP)
    }

    /// All matching routes as `r1@csv(v)|r2@csv(v2)` (no `@` for empty values), or "".
    pub fn get_all(&self, cidr: &str) -> Result<String> {
        let r = ip2cidr(cidr)?;
        let mut rv = String::new();
        self.walk(&r, &mut |k, v| {
            rv.push_str(&key_to_string(k));
            if !v.is_empty() {
                rv.push_str(KDELIM);
                rv.push_str(v);
            }
            rv.push_str(KVSEP);
            true
        });
        Ok(rv.trim_end_matches(KVSEP).to_string())
    }

    /// Deletes all routes matching cidr; returns how many.
    pub fn del_all(&self, cidr: &str) -> i32 {
        let Ok(r) = ip2cidr(cidr) else { return 0 };
        let mut t = self.t.write();
        let net = t.net_mut(&r);
        let mut keys: Vec<Vec<u8>> = Vec::new();
        net.walk_match(&r, &mut |k, _| {
            keys.push(k.to_vec());
            true
        });
        let mut n = 0;
        for k in keys {
            let iplen = k.len() - 1;
            if net
                .delete(&IpNet {
                    ip: k[..iplen].to_vec(),
                    ones: k[iplen],
                })
                .is_some()
            {
                n += 1;
            }
        }
        n
    }

    pub fn clear(&self) {
        let mut t = self.t.write();
        t.t4.clear();
        t.t6.clear();
    }

    pub fn len(&self) -> usize {
        let t = self.t.read();
        t.t4.len() + t.t6.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_values() {
        let t = IpTree::new();
        t.add("10.0.0.0/8", "p1").unwrap();
        t.add("10.0.0.0/8", "p2").unwrap();
        t.add("10.0.0.0/8", "p1").unwrap(); // no dup
        t.add("10.0.0.0/8", "p").unwrap(); // "p" is a substring of x but not a value
        assert_eq!(t.get("10.0.0.0/8").unwrap(), "p1,p2,p");
        assert!(t.esc("10.0.0.0/8", "p2"));
        assert_eq!(t.get("10.0.0.0/8").unwrap(), "p1,p");
        assert_eq!(t.get_like("10.0.0.0/8", "p1"), "p1");
        assert_eq!(t.esc_like("10.0.0.0/8", "p"), 2);
        assert_eq!(t.len(), 0);
        assert!(t.get("bogus").is_err());
        assert_eq!(t.esc_like("bogus", "x"), -1);
    }

    #[test]
    fn routes_and_matches() {
        let t = IpTree::new();
        t.set("10.0.0.0/8", "a").unwrap();
        t.set("10.1.0.0/16", "b,x1").unwrap();
        t.set("10.1.2.3", "").unwrap(); // empty value: Set == Del + Add("") == nothing stored
        t.add("10.1.2.3", "c").unwrap();
        t.set("2001:db8::/32", "v6").unwrap();
        assert_eq!(t.routes("10.1.2.3"), "10.0.0.0/8,10.1.0.0/16,10.1.2.3/32");
        assert_eq!(t.values("10.1.2.3:80"), "a,b,x1,c");
        assert_eq!(t.get_any("10.1.2.99").unwrap(), "10.1.0.0/16@b,x1");
        assert_eq!(
            t.get_all("10.1.2.3").unwrap(),
            "10.0.0.0/8@a|10.1.0.0/16@b,x1|10.1.2.3/32@c"
        );
        assert_eq!(t.routes_like("10.1.2.3", "x"), "10.1.0.0/16");
        assert_eq!(t.values_like("10.1.2.3", "x"), "x1");
        assert_eq!(t.get_any("[2001:db8::5]:443").unwrap(), "2001:db8::/32@v6");
        assert!(t.has_any("2001:db8:1::1").unwrap());
        assert!(!t.has_any("2001:db9::1").unwrap());
        assert_eq!(t.del_all("10.1.2.3"), 3);
        assert_eq!(t.len(), 1);
        t.clear();
        assert!(t.is_empty());
    }
}
