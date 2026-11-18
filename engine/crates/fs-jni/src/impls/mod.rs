// Copyright (c) 2026 RethinkReloaded contributors.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

//! Real implementations of facade natives. Each function listed in `crates/fs-jni/impls.tsv` receives the JNI env,
//! `&this` (for instance methods) and the converted arguments, and returns `FsResult<T>`.

pub mod backend;
pub mod intra;
pub mod log;
pub mod seq;
pub mod settings;
