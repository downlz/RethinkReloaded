// Copyright (c) 2026 RethinkReloaded contributors.
// Copyright (c) 2023 RethinkDNS and its authors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! WireGuard for the RethinkReloaded engine. Phase 0: keys (`backend.WgKey`). Tunnels arrive in Phase 2.

pub mod key;

pub use key::WgKey;
