# Testing and parity validation

Parity is checked at four levels: the Java/JNI contract, deterministic logic against a Go oracle, the app's own
test suites run against both engines, and on-device end-to-end, performance and battery measurements.

## 1. API contract (CI, every PR)
* `engine/tools/api-contract.sh <sha>` downloads `com.celzero:firestack:<sha>` (AAR + sources jar) from Maven Central
  and verifies the `.sha1` checksums. It dumps `javap -p -s -constants` for every class in the upstream `classes.jar` and
  in ours, then diffs them. **The diff must be empty**, constants included.
* Native completeness: the host test loads the host-built `libgojni`. The number of natives it registers must equal
  the number of `native` methods javap reports.
* `scripts/rr/firestack-api-diff.sh <old> <new>` shows the Java API delta between two upstream pins. It is used during syncs.

## 2. Go oracle (differential, deterministic logic)
`engine/tools/go-oracle/` holds `*_oracle_test.go` files. They are copied into a clean firestack checkout at the pinned
SHA (so they can reach unexported internals) and run in Docker:

```bash
engine/tools/go-oracle/run.sh d3d530ea3e   # docker golang:1.27.3, -tags oracle -ldflags=-checklinkname=0
```

They write JSON fixtures to `engine/testdata/oracle/<sha>/`, which are checked in. Rust tests replay the fixtures.

| Suite | Compared |
|---|---|
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
```bash
./gradlew :app:testFdroidFullDebugUnitTest                              # Go engine
./gradlew -PfirestackRepo=rust :app:testFdroidFullDebugUnitTest         # Rust engine
./gradlew -PfirestackRepo=rust :app:connectedFdroidFullDebugAndroidTest # emulator
```

## 5. JVM host tests
`engine/android/host-test` runs the vendored Java facade on the desktop JVM against a host build of `libgojni`.
On Linux CI, `ip tuntap` provides a real TUN device, so `Intra.connect` can run end to end without an emulator.

## 6. End-to-end on emulator / device
* Pre-authorize the VPN: `adb shell appops set io.github.downlz.rethinkreloaded ACTIVATE_VPN allow`.
* `engine/e2e/fs-probe` is a small Rust CLI pushed to `/data/local/tmp`. It checks DoH resolution through the tunnel,
  that blocklisted domains are blocked, and TCP/UDP/ICMP reachability.
* `engine/e2e/probe-app` is a separate APK, so it has its own UID. It is used for per-app firewall rules.
* WireGuard is tested against a host `wg` / gotatun server.

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

Baselines are stored as `engine/perf/baseline-<firestack-sha>.json`. Each Phase 1+ exit gate compares against them
(see [ENGINE_ROADMAP.md](ENGINE_ROADMAP.md)).
