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
* Go baselines on the emulator (`baseline-go-d3d530ea3e-emulator.json`) and on a physical phone (below).

### Go baseline on a physical device (2026-11-18)

The setup:
* motorola edge 60 pro, Android 17 (API 37), arm64.
* Wi-Fi 802.11ac on 5 GHz.
* `fdroidFullReleaseDebug` build.
* DNS set to Cloudflare DoH.

Files: `engine/perf/baseline-go-d3d530ea3e-edge60pro.json` (VPN on) and `engine/perf/reference-novpn-edge60pro.json` (no VPN).
Captured with `engine/perf/device-baseline.sh` and `engine/e2e/fs-probe`.

| Metric | Go engine (VPN on) | No VPN |
|---|---|---|
| App PSS, steady idle (screen on) | ~186 MB (native heap ~38 MB, RSS ~242 MB) | n/a |
| Threads | 86 | n/a |
| Context switches / min, idle (wakeup proxy) | ~4,800 | n/a |
| LAN HTTP download (300 MB from a LAN host) | **133 Mbit/s** | 206 Mbit/s (Go costs ~35%) |
| App CPU per GB downloaded | **86.9 s** | n/a |
| DNS, cached (via the VPN's DNS) | p50 23.5 ms, p95 26.2 ms | n/a |
| DNS, uncached | p50 79 ms, p95 2.19 s, 14/40 timed out | UDP 1.1.1.1: p50 49.7 ms, 7/40 lost |
| `libgojni.so` (arm64) | 19.8 MB | n/a |

TCP connect through the VPN measures about 4 ms because the netstack terminates the handshake locally. It is recorded
but is not a network latency. The Phase 1 performance gates compare against the VPN-on column, with the same device,
build type, network and DNS settings.

Carried forward:
* Baseline on an **armv7** device. The edge 60 pro is 64-bit only.
* A battery run of several hours, using `batterystats` and Battery Historian.
* Census: 67 real implementations, 616 struct accessors and 9 runtime natives are done; 105 RPN natives are permanent
  stubs and **264** natives remain for Phases 1–3.

### Phase 1 progress (2026-11-20)

**Phase 1: in progress.** The app runs a working VPN on the Rust engine (emulator, `-PfirestackRepo=rust`):
* DNS answers through the fake DNS address; warm-cache p50 is 6.4 ms, including Kotlin's `onQuery` over JNI.
* HTTP/TCP and UDP flows are relayed over protected sockets, with Kotlin's `preflow`/`flow` verdicts applied.
* Domains reach Kotlin's firewall.
* ping works.

| Area | Status |
|---|---|
| JNI callback executor (protect / flow / dns / notify lanes), Bridge over Kotlin | done |
| Protected sockets (`bind4`/`bind6` before connect; tcp, udp, icmp) | done |
| DNS messages (RData, padding, blocked answers), DoH (h2), DoT, DNS53, BlockAll | done (live-tested) |
| Resolver: onQuery → `[Cache]tid[:pid]` → cache → upstream → onUpstreamAnswer → onResponse | done (onUpstreamAnswer also for cached answers) |
| Default DNS (DoH with seeds, DNS53, system), System DNS, DNS proxy | done |
| TUN + netstack (netstack-smoltcp), fd swap / unlink / restart | done |
| TCP relay (half-close), UDP sessions (120 s idle), DNS over UDP/TCP to the fake DNS address | done |
| Flow decision (preflow 5 s, flow 15 s, judge, Mark.IP, Block stall, CloseConns) | done |
| ICMP echo (probe socket, synthesized reply, unreachable when blocked, flood stall) | done |
| Domains, real IPs and blocklists in Flow (through the gateway) | done |
| `/proc/net` uid lookup (Android 9 and older) | done (unit-tested; needs an API ≤ 28 device) |
| Rethink blocklists: gotrie port + blockstamps (`setRdnsLocal/Remote`, RDNS), remote stamps (`x-nile-flags`) | done (oracle: 32,715 firestack results reproduced) |
| UDP endpoint-independent mapping/filtering (`Intra.transparency`, `inflow`) | done |
| Per-transport caches: stale-while-revalidate, request barrier (coalescing), hangover | done |
| DNS gateway: ALG translation, internal cache, secondary transports, presets, Fixed; flow-side undo + re-resolve | done (oracle: 3,851 firestack results reproduced) |
| Performance gate vs the Go baseline (phone) | measured (below): memory, CPU, throughput, wakeups pass; cached DNS p95 borderline |

Census: 151 real implementations, 616 struct accessors and 9 runtime natives are done; 105 RPN natives are permanent
stubs and 180 natives remain.

### Phase 1 performance gate (2026-11-21)

Same phone, build type (`fdroidFullReleaseDebug`, arm64), Wi-Fi (802.11ac, RSSI −59 vs −56), DNS (Cloudflare DoH)
and LAN download target as the Go baseline. Files: `engine/perf/baseline-rust-2e51bbefe-edge60pro.json`, compared
with `engine/perf/compare.py`.

| Metric | Go | Rust | Gate | Result |
|---|---|---|---|---|
| Idle PSS (median) | 182 MB | **133 MB** (−27%) | ≤ 80% of Go | pass |
| Threads | 86 | 71 | | |
| Context switches / min, idle | 4,798 | **1,808** (−62%) | ≤ Go | pass |
| LAN download | 133 Mbit/s | **201 Mbit/s** (+51%; no-VPN reference 206) | ≥ 95% of Go | pass |
| App CPU per GB downloaded | 86.9 s | **30.1 s** (−65%) | ≤ Go | pass |
| DNS cached p50 / p95, gate run | 23.5 / 26.2 ms | 27.5 / 84.7 ms | p50 ≤ Go + 1 ms, p95 ≤ Go | fail (one run) |
| DNS cached p50 / p95, four more runs | | 22.1–25.4 / 25.9–28.5 ms | | p50 pass; p95 borderline |
| DNS uncached (internet) | p50 79 ms, p95 2.19 s, 14/40 lost | p50 72–80 ms, p95 90–134 ms, 0/40 lost | informational | |
| `libgojni.so`, stripped | 19.8 MB | **5.7 MB** | | |

Cached DNS is dominated by four Kotlin callbacks per probe query (preflow, flow, onQuery, onUpstreamAnswer) in both
engines; the gate run's 84.7 ms p95 did not reproduce in four further runs, and Go was measured once. Open items for
the latency gate: repeat both engines several times in one session, and profile the callback lanes.
Not yet measured: screen-off wakeups (Perfetto), `VpnStartupBenchmark`, a battery run, an armv7 device.

### Phase 2 status (2026-11-21)

| Area | Status |
|---|---|
| Proxy registry (`Proxies`): add/remove/get, `ProxyTo` (pins, stall, Auto → Exit), refresh, Router aggregates, listener callbacks | done |
| SOCKS5 client (TCP, UDP associate, credentials), HTTP CONNECT client (Basic, 407 retry, TLS to `https://` proxies) | done |
| WireGuard (gotatun + smoltcp per proxy): UAPI config, MTU reconciliation, status/stats, ping/refresh, pause/resume | done |
| Hops (`hop` / `testHop`): firestack's rules; WireGuard family/announce/route/MTU checks; replaced vias keep origins | done |
| DNS through Kotlin's proxies (`tid:pid`), `Intra.addProxyDNS` (WireGuard DNS transport, by address) | done |
| Local servers (`Tunnel.getServices`, fs-rnet): SOCKS5 (CONNECT, UDP) and HTTP (CONNECT, plain) | done (unused by the v0.5.8 app) |
| Exit gate, through the app on the Android 15 emulator against `engine/e2e/wg-peer` on the host | pass (below) |

Exit gate runs (adb shell uid routed by the app; `fs-probe` echo/udp/get/ntp):

| Check | Result |
|---|---|
| WireGuard to a local server (wg-peer, gotatun + userspace stack) | TCP echo, UDP echo, HTTP through the tunnel |
| Multi-hop: inner peer reachable only inside the outer tunnel, set as a Relay in the app | TCP echo, UDP echo, HTTP two tunnels deep |
| SOCKS5 UDP (app's SOCKS5 proxy → fs-rnet SOCKS5 server on the host) | NTP query and reply over UDP associate; TCP too |

Bugs the e2e run found, now fixed and covered by tests: `getProxy`/`refreshProxies`/`hop` panicked off the runtime
(Kotlin threads); a WireGuard hop never handshook (firestack refreshes on hop) and gotatun's unbounded
`force_handshake` held the device lock; DNS ignored Kotlin's proxy choice; Kotlin's WireGuard DNS transport
(`addProxyDNS`) was missing.

### Measurement pass after Phase 2 (2026-11-21, same phone, both engines in one session)

Both engines were built from `894abe77d` (`fdroidFullReleaseDebug`, arm64) and installed over each other on the
Phase 1 phone, with the same Wi-Fi and LAN target. Files in `engine/perf/`:
* `baseline-{go-d3d530ea3e,rust}-894abe77d-edge60pro.json`
* `ab-894abe77d-edge60pro.json` (three alternating rounds)
* `screenoff-*-894abe77d-edge60pro.json`
* `startup-*-894abe77d-edge60pro.json`

**Correction:** the Go baseline of 2026-11-18 overstated Go's idle cost: 182 MB PSS and 4,798 context switches/min,
against 142–153 MB and 1,763–6,271/min measured today. Idle context switches swing widely with other apps' traffic,
so single runs are not meaningful; the A/B rounds are.

| Metric | Go | Rust | Gate | Result |
|---|---|---|---|---|
| Idle PSS, A/B median of 3 (screen on) | 143 MB | 123 MB (−14%) | ≤ 80% of Go | **fail**: about 86% of Go. One Rust round read 175 MB; 36 MB of it was graphics (UI), not the engine |
| Idle context switches/min, A/B median of 3 | 5,037 | 1,337 (−73%) | ≤ Go | pass |
| **Screen off, 15 min**: voluntary switches (wakeups)/min | 2,304 | **93** (−96%) | ≤ Go | pass |
| Screen off, 15 min: app CPU | 9.03 s | **0.86 s** (−90%) | ≤ Go | pass |
| Screen off, 15 min: battery estimate (batterystats) | 0.430 mAh | **0.079 mAh** (−82%) | | |
| LAN download (baseline run) | 140 Mbit/s | 212 Mbit/s (+52%) | ≥ 95% of Go | pass |
| App CPU per GB | 79.5 s | 29.7 s (−63%) | ≤ Go | pass |
| DNS cached p50 / p95 (A/B, 3 runs each) | 32–34 / 87–96 ms | 25–32 / 82–86 ms | p50 ≤ Go + 1 ms, p95 ≤ Go | pass |
| Cold start (`am start -W` TotalTime, median of 5) | 152 ms | 150 ms | regression ≤ 5% | pass |
| Launch → first DNS answer through the VPN (median of 5) | 1,164 ms | 1,162 ms | | equal |

Notes:
* Screen-off windows: one per engine, back to back, with the charger reported unplugged and Doze not forced.
* Startup runs: the phone was locked; TotalTime measures the same launch for both engines.
* The memory gate is the one miss. Rust's idle PSS is consistently lower than Go's, but not by 20% in this session.
  Next steps: separate native heap from graphics in `ab.sh`, look at the 46 MB native heap (engine plus app
  libraries), and check whether the 80% target was set from the overstated Go baseline.

Findings (app-side, both engines):
* After an install, the app sometimes stops its own VPN right after starting it. Two "start VPN" calls race and the
  second finds no tunnel ("Cannot handle vpn adapter changes, no tunnel"). This is upstream Kotlin behaviour; seen with
  Go and Rust.
* RethinkReloaded on the phone had the universal rules "Block when DNS is bypassed" and "Block port 80" on. They block
  the probes (`fs-probe` by IP and over HTTP), so they were switched off for the runs.

Not measured: armv7 (this phone is arm64-only), a multi-hour battery drain.

Open items: the WireGuard list's rx/tx counters in the app did not visibly advance during the run, although engine
counters do (unit-tested), so check the UI refresh path in the measurement pass. Kotlin does not restore a relay after
a VPN restart (Kotlin's own state; check against the Go engine).

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
