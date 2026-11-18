# RethinkReloaded engine (Rust port of firestack)

MPL-2.0. A Rust rewrite of [celzero/firestack](https://github.com/celzero/firestack), the network engine behind
Rethink DNS + Firewall. It ships as a drop-in replacement for `com.celzero:firestack:<sha>@aar`, so the
Kotlin app runs on it unchanged. Credit for firestack goes to Celzero and the RethinkDNS contributors; see [NOTICE](NOTICE).

* Architecture: [docs/fork/ARCHITECTURE.md](../docs/fork/ARCHITECTURE.md)
* Roadmap and status: [docs/fork/ENGINE_ROADMAP.md](../docs/fork/ENGINE_ROADMAP.md)
* Parity notes and deliberate deviations: [PARITY.md](PARITY.md)

## Layout

| Path | What |
|---|---|
| `api/PIN` | firestack commit whose API the engine implements (from the synced rethink-app release) |
| `api/firestack-api.txt` | javap ABI golden of upstream `classes.jar` (contract test input) |
| `api/natives.tsv` | every `native` method of the facade (jni-gen input) |
| `android/facade/src/main/java` | gobind-generated Java facade, vendored **verbatim** from upstream's sources jar |
| `android/facade` | Android library producing the AAR (`io.github.downlz.rethinkreloaded:firestack-rust`) |
| `crates/fs-jni` | `libgojni.so`: gobind refnum runtime, struct store, generated `Java_*` exports (`src/exports.rs`), `impls/` |
| `crates/fs-iptree` | RadixTree (done) / IpTree (next) ports |
| `tools/facade-sync.sh` | re-vendor the facade + regenerate API files at a new pin |
| `tools/jni-gen` | generates `crates/fs-jni/src/exports.rs` from `api/natives.tsv` + `crates/fs-jni/impls.tsv` |
| `tools/api-contract.sh` | API contract test (facade identical, ABI identical, all natives exported, glue fresh) |

## Build

```bash
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
cargo install cargo-ndk --locked
cargo test --workspace                 # host tests
# App with the Rust engine. Gradle runs cargo-ndk through the included build engine/android:
./gradlew -PfirestackRepo=rust :app:assembleFdroidFullDebug                 # from the repo root
./gradlew -PfirestackRepo=rust -PrustAbis=arm64-v8a -PrustProfile=android-dev :app:assembleFdroidFullDebug  # faster dev loop
engine/tools/api-contract.sh
```

## Porting a native

1. Implement it in `crates/fs-jni/src/impls/<area>.rs` with the signature `fn(env, [&this,] args…) -> FsResult<T>`.
   The engine logic itself belongs in a JNI-free crate (`crates/fs-*`) so it can be tested on the host.
2. List it in `crates/fs-jni/impls.tsv`, then run `cargo run -p jni-gen`.
3. Every ported Rust file starts with the MPL-2.0 header, keeps the original "Copyright (c) RethinkDNS and its authors"
   line, and names its source as `// Derived-From: celzero/firestack@<sha>:<path>`.
   Commits carry `Ported-from: celzero/firestack@<sha>:<path>` trailers.

## When upstream bumps firestack

Run `tools/facade-sync.sh <new-sha>`, then `cargo run -p jni-gen`. New natives become stubs automatically, and jni-gen
fails if a native listed in `impls.tsv` disappeared. Then port the behaviour changes; see
[UPSTREAM_SYNC.md §5](../docs/fork/UPSTREAM_SYNC.md).
