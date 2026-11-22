# Testing and parity validation

Parity is checked at four levels: the Java/JNI contract, deterministic logic against a Go oracle, the app's own
test suites run against both engines, and on-device end-to-end, performance and battery measurements.

## 1. API contract (CI, every PR)
`engine/tools/api-contract.sh` checks against the pin in `engine/api/PIN`:
1. The vendored facade Java is byte-identical to upstream's `firestack-<pin>-sources.jar`.
2. The `javap -p -s -constants` dump of our compiled facade equals `engine/api/firestack-api.txt`, the golden taken from
   upstream's `classes.jar`. Constants are included; compiler-synthesized `access$NNN` accessors are ignored.
3. Every one of the natives (1061 at `d3d530ea3e`) is exported as a `Java_…` symbol by each ABI's `libgojni.so`.
4. `crates/fs-jni/src/exports.rs` is up to date with `api/natives.tsv` and `impls.tsv` (`jni-gen --check`).

Checksums of everything downloaded from Maven Central are verified against the published `.sha1` files.
* `scripts/rr/firestack-api-diff.sh <old> <new>` shows the Java API delta between two upstream pins. It is used during syncs.

## 2. Go oracle (differential, deterministic logic)
`engine/tools/go-oracle/` holds `*_oracle_test.go` files. They are copied into a clean firestack checkout at the pinned
SHA (so they can reach unexported internals) and run in Docker:

```bash
engine/tools/go-oracle/run.sh --docker     # pin from engine/api/PIN; Docker image golang:<firestack go.mod version>
```

firestack only builds for Linux/Android, so on macOS the oracle runs in Docker. It writes TSV fixtures
(`op \t arg1 \t arg2 \t result \t err`) to `engine/testdata/oracle/<sha>/`, which are checked in.
`crates/*/tests/oracle.rs` replay them during `cargo test`. Operations on which firestack itself panics are recorded
as `panic` and skipped (see `engine/PARITY.md`). Results at `d3d530ea3e` are listed in `engine/PARITY.md`.

| Suite | Compared |
|---|---|
| IpTree *(done)* | 10040 seeded random ops over all 18 methods (v4/v6/mapped/zoned/invalid) |
| RadixTree *(done)* | 8040 seeded random ops (Unicode and empty keys) |
| WgKey *(done)* | parse/encode/derive for 70 inputs, including malformed ones |
| Settings *(done)* | mode strings, dialer options, auto mode |
| Blocklist trie | lookups for a pinned blocklist + domain corpus → identical flag sets |
| Blockstamps | flags↔stamp round trips (EB32 and legacy) |
| xdns transforms | block answers, TTL clamps, padding, DNS64 synthesis; compared semantically and byte-for-byte |
| ALG | sequences of query→fake-IP→reverse lookups |
| IpTree / RadixTree | random operation sequences, including exact CSV ordering of results |
| Dialer split plans | segmentation for split / desync modes |
| WgKey | key derivation (base64 / hex / public) |
| Settings | `mode2String`, `l3`, `engine` string mappings |

## 3. Rust test suites
* Unit tests and `proptest`, which replays the same operation sequences as the oracle: `cargo nextest run --workspace`.
* Fuzzing with `cargo fuzz` covers fs-wire packet parsing, DNS messages, stamps, WireGuard UAPI, and SOCKS/HTTP parsers.
* Concurrency: `loom` models RefTable and CallbackExecutor.
* Benchmarks with `criterion` cover the trie, cache and relay copy loop.
* Licences and advisories: `cargo deny check`.

## 4. App test suites against both engines
CI runs the **parity subset** listed in `scripts/rr/parity-tests.txt` against each engine. The subset covers tests that
exercise firestack classes through the gobind facade and its Robolectric shadows, plus tests for files the fork patches:
```bash
./gradlew :app:testFdroidFullDebugUnitTest $(scripts/rr/parity-test-args.sh)                       # Go engine
./gradlew -PfirestackRepo=rust :app:testFdroidFullDebugUnitTest $(scripts/rr/parity-test-args.sh)  # Rust engine
./gradlew -PfirestackRepo=rust :app:connectedFdroidFullDebugAndroidTest                            # emulator
```
The full upstream unit suite (`:app:testFdroidFullDebugUnitTest` with no filter) hangs in `ConnectionMonitorTest`,
blocked in WorkManager/Room `runBlocking`. This was reproduced on **pristine upstream v0.5.8** as well as on the fork,
both times right after `BraveVPNServiceLifecycleTest`. Run on its own, the class passes (28/28). It is an upstream
test-isolation issue, and upstream's own CI does not run unit tests.

Known flaky upstream test in the subset: `TunFirewallManagerTest` "RULE1B - Block new app". It verifies
`rdb.addNewApp` right after `firewall()` returns, but the production code launches that call on `Dispatchers.IO` in a
separate scope, so the check races. This is unrelated to the engine. `rr-ci` retries the unit-test step once.

## 5. JVM host tests
`engine/android/host-test` runs the vendored Java facade on the desktop JVM against a host build of `libgojni`
(`./gradlew -p engine/android :host-test:test`). Unlike the app's Robolectric tests, which replace the native library
with shadows, these exercise the real JNI path. They check:
* `go.Universe$proxyerror` exceptions;
* Go zero values;
* struct accessors and the generated `equals`;
* refnum release through GC (`Seq.destroyRef`);
* stubs.

CI runs them. Once the netstack exists, Linux CI can use `ip tuntap` to run `Intra.connect` end to end.

## 6. End-to-end on emulator / device
Local setup used so far: AVD `rr-api35` (`system-images;android-35;google_apis;arm64-v8a`, Pixel 6 profile).
```bash
~/Library/Android/sdk/emulator/emulator -avd rr-api35 -no-window -no-audio -no-boot-anim -no-snapshot &
adb install -r app/build/outputs/apk/fdroidFull/debug/app-fdroid-full-arm64-v8a-debug.apk
adb shell am start -n io.github.downlz.rethinkreloaded/com.celzero.bravedns.ui.activity.LauncherAliasAppLock
```

* Pre-authorize the VPN: `adb shell appops set io.github.downlz.rethinkreloaded ACTIVATE_VPN allow`.
* `engine/e2e/fs-probe` is a small Rust CLI pushed to `/data/local/tmp`. It checks DoH resolution through the tunnel,
  that blocklisted domains are blocked, and TCP/UDP/ICMP reachability.
* `engine/e2e/wg-peer` runs on the host (`cargo run -p wg-peer -- <out-dir> 10.0.2.2`). It provides:
  * an outer WireGuard peer on udp/51820 (tunnel 10.9.0.1);
  * an inner peer reachable only inside the outer tunnel (10.9.0.1:51821; tunnel 10.8.0.1), for multi-hop;
  * echo on port 7 and HTTP on port 80 inside both tunnels;
  * a fs-rnet SOCKS5 server with UDP on 127.0.0.1:10800.

  It writes importable client configs (`wg-outer.conf`, `wg-inner.conf`) with fixed test keys. Probe with
  `fs-probe echo|udp|get|ntp`. On macOS, the application firewall blocks inbound LAN traffic to the unsigned binary,
  so use a public UDP target (`fs-probe ntp`) through SOCKS5.
* `engine/e2e/probe-app` is a separate APK, so it has its own UID. It is used for per-app firewall rules.
* WireGuard is tested against a host `wg` / gotatun server.

### Sanitizers and fuzzing
* Fuzzing: `engine/fuzz` (see its README). It runs weekly in CI (`rr-fuzz.yml`).
* AddressSanitizer for the engine's unit tests (nightly):
  ```bash
  cd engine && RUSTFLAGS=-Zsanitizer=address cargo +nightly test -Zbuild-std --target aarch64-apple-darwin \
    --target-dir target/asan -p fs-jni -p fs-dialers -p fs-blocklist -p fs-iptree -p fs-dns --lib --tests
  ```
* AddressSanitizer for the real JNI path: build `fs-jni` the same way with `cargo +nightly build`, then run the JVM
  host tests with
  `-PrustHostLibDir=$PWD/engine/target/asan/aarch64-apple-darwin/debug -PhostPreload=<toolchain>/lib/rustlib/aarch64-apple-darwin/lib/librustc-nightly_rt.asan.dylib`.

### Soak
`engine/perf/soak.sh <hours> <cycle_minutes> <host> <port> <path>` keeps DNS, TCP and download traffic flowing
through the VPN. Each cycle it samples PSS, native heap, file descriptors (debuggable builds) and threads. It reports
growth per hour and stops if the app process restarts.

## 7. Performance and battery (physical arm64 + armv7 devices; Go baseline first)
| Metric | Tool |
|---|---|
| Memory | `dumpsys meminfo <pkg>` (PSS, native heap), `/proc/<pid>/status` (VmRSS, Threads) |
| Throughput | `iperf3 -c <host> -P4 -t30` and `-R` through the tunnel |
| DNS latency | fs-probe DNS bench, p50/p95 |
| CPU | `simpleperf record -g`, `simpleperf stat` deltas |
| Battery | `dumpsys batterystats --reset`, `dumpsys battery unplug`, `adb bugreport` → Battery Historian |
| Wakeups | Perfetto `sched_wakeup` / `cpu_idle`, per-thread counts via trace_processor |
| Startup | `benchmark/` VpnStartupBenchmark, plus `ATrace` sections emitted by Rust |
| Size | `libgojni.so` size per ABI, compared with Go's (19–21 MB) |

`engine/perf/capture.sh <label>` records PSS, native heap, RSS and thread count of the running app, plus the size of
`libgojni.so`, as JSON. `engine/perf/device-baseline.sh <label> [--no-vpn]` wraps it for a full device run. With
`ANDROID_SERIAL` set and RethinkReloaded's VPN connected, it adds:
* a wakeup proxy (context switches per minute across the app's threads);
* DNS latency through the VPN's DNS address, cached and uncached;
* TCP connect latency;
* download throughput together with the app's CPU seconds per GB.

The probe is `engine/e2e/fs-probe`, built with `cargo ndk -t arm64-v8a build --release -p fs-probe`. It runs as the
shell user, whose traffic goes through the VPN. For the download, serve a large file from a LAN host
(`python3 -m http.server`) and pass `RR_HTTP_TARGET="<ip> <port> /<file>"`; public test servers are often blocked or
throttled. Repeat the run with `--no-vpn` (no VPN active) for the network ceiling. Keep the phone on the same Wi-Fi band
for both runs: one router isolated 2.4 GHz clients from the LAN host. Recorded files contain no SSID, BSSID, MAC or
device IP. Baselines are stored as `engine/perf/baseline-<engine>-<firestack-sha>-<device>.json`.
Compare engines only on the same device and build type. Emulator numbers support relative comparison only. Each Phase 1+ exit gate compares against them
(see [ENGINE_ROADMAP.md](ENGINE_ROADMAP.md)).
