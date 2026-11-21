// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! DNS messages and transports.

pub mod dns53;
pub mod dnscrypt;
pub mod doh;
pub mod dot;
pub mod msg;
pub mod stamp;
pub mod tls;
pub mod transport;

/// DNS transport ids with fixed meaning (backend constants).
pub mod ids {
    pub const PREFERRED: &str = "Preferred";
    pub const DEFAULT: &str = "Default";
    pub const SYSTEM: &str = "System";
    pub const GOOS: &str = "Goos";
    pub const BLOCK_FREE: &str = "BlockFree";
    pub const BLOCK_ALL: &str = "BlockAll";
    pub const PLUS: &str = "Plus";
    pub const FIXED: &str = "Fixed";
    pub const BOOTSTRAP: &str = "Bootstrap";
    pub const ALG: &str = "Alg";
    /// cache prefix in TIDCSV entries (`CachePreferred`)
    pub const CACHE_PREFIX: &str = "Cache";
}
