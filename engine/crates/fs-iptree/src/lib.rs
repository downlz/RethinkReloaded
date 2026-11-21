// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Thread-safe tries exposed to Kotlin as `backend.RadixTree` and `backend.IpTree`.

pub mod critbit;
pub mod iptree;
pub mod net;
pub mod radix;

pub use iptree::IpTree;
pub use radix::RadixTree;
