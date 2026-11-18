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

**Phase 0: in progress.**

Done:
* `engine/` workspace with licences, NOTICE, cargo-deny, the toolchain pin and 16 KB page alignment.
* `facade-sync.sh`: gobind Java vendored verbatim at `d3d530ea3e`, plus the javap golden and `natives.tsv`.
* `jni-gen`: all **1061** natives exported on all four ABIs.
* Seq refnum runtime, `proxyerror` errors, panic containment with Go-format crash output.
* Struct store covering 28 classes (616 accessors).
* Real implementations of `Intra.build/logLevel/setupConsole/setCrashOutput/SELF_UID/lowMem/toggles`.
* `Backend.newRadixTree` and the full `RadixTree` port.
* Gradle `-PfirestackRepo=rust` composite build.
* `api-contract.sh` passes.
* `./gradlew -PfirestackRepo=rust :app:assembleFdroidFullDebug` builds.
* The 562-test parity unit subset passes on both engines.

Remaining before the Phase 0 exit gate:
* `IpTree` port. It needs critbitgo `Net` traversal order, verified against a Go oracle. Until then `Backend.newIpTree()`
  returns `null`, so the app cannot start with the Rust engine yet.
* Real `Settings.*` setters and `WgKey` (x25519).
* Go oracle harness (`engine/tools/go-oracle`) and the JVM host-test module.
* On-device check that the app launches and the VPN start fails cleanly. No emulator or device was available in the setup session.
* Go performance baseline captured on reference devices.

Current census: 25 real implementations, 616 struct accessors and 9 runtime natives are done; 105 RPN natives are
permanent stubs and 306 natives are still to port.

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
