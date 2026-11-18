# Rust engine roadmap

The goal is behavioural parity with upstream firestack, starting from the commit pinned by the synced rethink-app
release. The first parity target is v0.5.8, which pins `firestackCommit=d3d530ea3e`. The target moves with every
upstream sync; see [UPSTREAM_SYNC.md §5](UPSTREAM_SYNC.md#5-firestack-api-drift-rust-engine).

The Go engine stays the default until Phase 4. Each phase has an exit gate that CI or a documented benchmark must pass.

| Phase | Share | Deliverables | Exit gate |
|---|---|---|---|
| **0 — Skeleton** | ~8% | Cargo workspace, toolchain pin, cargo-deny, licences/REUSE; `facade-sync` vendors gobind Java at the pin; javap API golden; `jni-gen` emits stub natives for every method; `fs-jni` `JNI_OnLoad` + Seq refnum runtime; real `Settings.*` setters, `Intra.build/logLevel/setupConsole/setCrashOutput/lowMem`, IpTree/RadixTree, WgKey; Gradle `rust` option; Go perf baseline captured on devices (`engine/perf/baseline-<sha>.json`) | API contract diff empty; registered-native count == javap native count; `./gradlew -PfirestackRepo=rust :app:assembleFdroidFullDebug :app:testFdroidFullDebugUnitTest` green; app launches; VPN start fails cleanly (no crash) |
| **1 — MVP DNS + firewall** | ~35% | fs-wire, fs-core, fs-log; fs-netstack (held-SYN TCP, UDP NAT, ICMP echo, fd swap, MTU); netstat UID; fs-dialers (protect/bind/pinning, basic retrier); dns53, DoT, DoH (h1/h2, padding); fs-dnsx (cache, RDNS local+remote, ALG); fs-blocklist; Base/Exit/Block proxies | iperf3 throughput ≥ 95% of Go; DoH p50 ≤ Go + 1 ms, p95 ≤ Go; CPU/GB ≤ Go; idle PSS ≤ 80% of Go; screen-off wakeups/min ≤ Go; VpnStartupBenchmark regression ≤ 5% |
| **2 — Proxies + WireGuard** | ~25% | SOCKS5 (TCP+UDP), HTTP CONNECT (+auth), Orbot, Auto (→ Exit, since RPN is excluded), multihost, hop/testHop, Router stats, proxy listener callbacks; fs-wg (gotatun + timer patch, UAPI, inflow, Amnezia parse-only like upstream); fs-rnet servers | e2e WireGuard to a local server; multi-hop; SOCKS UDP |
| **3 — Long tail** | ~22% | DNSCrypt + relays, ODoH, Plus (order/filter), rank/p50; DNS64/NAT64/NAT-PT; full split/desync, ECH, mDNS; pcap; full NetStat; memfd consoles + `LogConsumer` drain; traces; diagnostics stand-ins (`goMet`, `printStack`, profiles) | Stub census contains only RPN |
| **4 — Hardening + default** | ~10% | Fuzz campaign, 72 h soak (refnum table, fds, PSS slope), HWASan build, tuning (buffers, socket sharding, optional WireGuard L3 fast path), battery gates | Rust becomes the default engine for alpha, then release. Go stays selectable for N releases |

Total estimate: about 45–50 engineer-weeks.

## Status (2026-11-18)

**Phase 0: exit gate met.** Remaining items carried forward are listed below.

| Gate | Result |
|---|---|
| API contract diff empty | `engine/tools/api-contract.sh` OK at `d3d530ea3e` |
| All natives present | 1061/1061 exported on arm64-v8a, armeabi-v7a, x86, x86_64 |
| `./gradlew -PfirestackRepo=rust :app:assembleFdroidFullDebug` + unit tests | builds; 562 parity unit tests pass on both engines |
| App launches with the Rust engine | Android 15 arm64 emulator: welcome screen, home screen, About; no crashes; `rust engine loaded` |
| VPN start fails cleanly | `Intra.newDefaultDNS` / `Intra.connect` throw `go.Universe$proxyerror`; Kotlin logs `err new vpn-adapter`; app stays up |

Delivered in Phase 0:
* Workspace and tooling: `facade-sync`, `jni-gen` (1061 natives), the API contract check, and the CI engine job.
* gobind runtime: refnums, struct store (28 classes), Go-format errors and panics.
* Real implementations (67): `Intra` basics and toggles, all `Settings` natives, `IpTree` and `RadixTree` (faithful critbitgo
  port), `WgKey`.
* JVM host tests of the real JNI path (`engine/android/host-test`, 8 tests).
* Go oracle (`tools/go-oracle`, Docker): 18,204 recorded firestack operations, all reproduced by the Rust replay tests
  (`engine/PARITY.md`). It also found 107 inputs on which firestack itself panics.
* Go baseline on the emulator: `engine/perf/baseline-go-d3d530ea3e-emulator.json`. That is about 157 MB PSS for the whole app
  with the VPN connected and idle, 71–78 threads, and a 19.8 MB `libgojni.so`. Comparing it with a stub-only Rust
  engine is not meaningful yet.

Carried forward:
* Go baseline on physical reference devices (arm64 + armv7), including throughput, DNS latency and battery. This needs
  hardware; the capture script is `engine/perf/capture.sh`.
* Census: 67 real implementations, 616 struct accessors and 9 runtime natives are done; 105 RPN natives are permanent
  stubs and **264** natives remain for Phases 1–3.

**Next: Phase 1** (netstack, dialers, DNS transports, resolver/ALG, blocklists).

## Explicit non-goals
* **RPN** (Windscribe WIN, Exit64, PIP blind-RSA tokens). Kotlin still compiles against these APIs, so they exist in the
  facade, but they permanently throw `rpn: unsupported`.
* Go-runtime-specific diagnostics with no Rust analogue are best-effort: `Intra.goMet` reports tokio and allocator metrics,
  and `cpuProfile`/`memProfile` write simpleperf hints.

## Deliberate deviations (tracked in `engine/PARITY.md`)
* firestack `Connect()` builds two tunnels when `linkmtu <= 0`. The Rust engine builds one.
* firestack `Connect2()` ignores its `dtr` argument. The Rust engine honours it.

## Key risks
| Risk | Mitigation |
|---|---|
| smoltcp throughput / TCP edge cases vs gVisor | Phase 1 perf gate; pcap-diff tests; app compatibility matrix; shard interfaces if per-socket egress cost hurts |
| Blocking upcalls starving async runtime | Dedicated JVM-attached callback lanes; never upcall from tokio workers; loom tests |
| Refnum leaks / lifetime bugs | Table size exposed in `goMet`; soak assertions |
| Moving firestack target (weekly) | Per-release drift procedure; `Derived-From` headers → `engine/tools/drift` |
| Old kernels / 32-bit ABIs | Runtime feature detection (memfd → ashmem fallback); portable-atomic; armv7 device in test matrix |
| gotatun pre-1.0 + 250 ms tick | Pin version; vendored patch; offer patch upstream |
