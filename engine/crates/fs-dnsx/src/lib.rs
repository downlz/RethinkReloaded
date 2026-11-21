// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! The resolver behind the tunnel's fake DNS addresses.

pub mod alg;
pub mod cache;
pub mod perf;
pub mod plus;
pub mod resolver;
pub mod undelegated;

pub use resolver::Resolver;
