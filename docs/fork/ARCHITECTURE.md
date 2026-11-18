# Architecture

## Engine swap model

Upstream rethink-app consumes the Go engine **firestack** as a prebuilt AAR, `com.celzero:firestack:<sha10>`.
The AAR is built with `gomobile bind` and pinned via `firestackCommit` in `gradle.properties`.
RethinkReloaded adds a second, Rust-built AAR with an **identical Java API**. The build picks between them:

| `-PfirestackRepo=` | Engine | Source |
|---|---|---|
| `ossrh` (default, from `gradle.properties`) | Go (upstream) | Maven Central `com.celzero:firestack:<sha>@aar` |
| `github` / `jitpack` | Go (upstream) | GitHub Packages / JitPack |
| `rust` | Rust (this fork) | Composite build `engine/android` → `io.github.downlz.rethinkreloaded:firestack-rust` |

The Kotlin app is unchanged: 71 upstream files import `com.celzero.firestack.*` and keep working against either engine.

```
Kotlin app (unchanged upstream) ── com.celzero.firestack.{intra,backend,settings} + go.{Seq,Universe,error}
  │  Java facade = gobind output vendored verbatim from firestack-<sha>-sources.jar (Maven Central)
  ▼  JNI: one exported Java_* symbol per native (library name stays "gojni")   ▲ upcalls: Bridge / Controller / Console / LogConsumer
fs-jni (cdylib): Seq refnum table (gobind protocol), struct stores, Go-style errors & panic envelope,
                 CallbackExecutor lanes {protect | flow | dns | notify} on JVM-attached std threads
  ▼  pure-Rust traits (host-testable, no JNI below this line)
fs-intra Tunnel ─► fs-netstack  stack thread: TUN ↔ smoltcp, held-SYN TCP, UDP NAT, ICMP, seamless fd swap
                ─► fs-dialers   protect/bind via Controller, IP pinning, retrier, TCP/TLS split & desync, ECH
                ─► fs-dnsx      resolver: cache, ALG (fake IPs), RDNS blocklists, Plus ─► fs-dns transports
                                (dns53 / DoT / DoH / ODoH / DNSCrypt / mDNS / system)
                ─► fs-proxy     base / exit / block / auto / socks5 / http1 / hop ─► fs-wg (gotatun + smoltcp client)
                ─► fs-rnet      local SOCKS5 / HTTP servers        fs-x64 DNS64/NAT64     fs-log consoles & traces
```

### Why vendor gobind's generated Java
* The public API is identical by construction, including generated `equals`/`hashCode`/`toString`.
* Upstream's Robolectric shadows (`app/src/test/.../shadows/ShadowGoJni.kt`, `ShadowGoSeq.kt`, `ShadowBackend.kt`)
  hook gobind internals (`go.Seq`, `__New`, `incRefnum`). They keep working only if the Java side is gobind's.
* Object lifetimes use gobind's refnum + `Seq.GoRefQueue` phantom-reference protocol, which works at minSdk 23
  (`java.lang.ref.Cleaner` needs API 33).

### Threading
* `fs-stack`: current-thread tokio runtime that owns smoltcp, TUN I/O and TCP relays.
* `fs-io`: multi-thread runtime with 2 workers (1 on low-memory devices) for DNS transports, dials, proxies and WireGuard crypto.
* Upcalls into Kotlin are **synchronous and may block**; Kotlin uses `runBlocking`. They never run on tokio workers.
  Instead they run on elastic, permanently attached callback threads, each inside a `PushLocalFrame`/`PopLocalFrame` pair,
  and no lock is held across an upcall.
* No periodic timers while idle: expiry is lazy, and gotatun's 250 ms device tick is patched to sleep until the next deadline.

### JNI glue generation
`engine/tools/facade-sync.sh <sha>` vendors the Java from upstream's sources jar and writes `engine/api/natives.tsv`
(1061 natives at `d3d530ea3e`). `engine/tools/jni-gen` turns that list, plus `crates/fs-jni/impls.tsv`, into
`crates/fs-jni/src/exports.rs`, which exports one `Java_…` symbol per native. Each symbol is routed to:
* a real implementation listed in `impls.tsv`;
* the generic struct store (`__New` and getters/setters of the 28 gobind struct classes);
* the gobind runtime (`Seq.init`, `destroyRef`, `proxyerror.error`, package `_init`s);
* the permanent RPN stub; or
* the "unimplemented" stub, which throws `proxyerror` for `throws Exception` methods and returns Go's zero value otherwise.

Exported symbols are used instead of `RegisterNatives`, matching gobind's own C glue. Completeness is checked by
`engine/tools/api-contract.sh`, which compares the `.so` exports with javap's native list.

## Repository layout (fork-owned paths)

```
engine/          Rust workspace (MPL-2.0) + android/ Gradle build producing the AAR
app/fork/        Branding layer: rethinkreloaded.gradle + res overlays
scripts/rr/      Sync / ledger / API-diff / tripwire scripts
docs/fork/       This documentation
.github/README.md, .github/workflows/rr-*.yml, NOTICE, FORK_CHANGES.md, .fork/UPSTREAM
```

## Crate map (engine/crates)

| Crate | Ports firestack | Notes |
|---|---|---|
| `fs-wire` | `intra/core/wire` | zero-copy IPv4/6/TCP/UDP/ICMP parse/build; fuzzed |
| `fs-core` | `intra/core`, `intra/settings` | expiring maps, sieve, singleflight, sockopts, rate limiter, settings globals |
| `fs-log` | `intra/log` | levels, console sink, memfd rings, traces, Go-style panic envelope |
| `fs-dialers` | `intra/protect`, `intra/dialers` | protect/bind, ipmap, retrier, split/desync, TLS, ECH |
| `fs-netstack` | `intra/netstack`, `tunnel`, `intra/netstat` | smoltcp TUN stack, UDP NAT, ICMP, pcap, /proc/net UID |
| `fs-dns` | `intra/dns53`, `intra/doh`, `intra/dnscrypt`, `intra/xdns` | transports + message utilities |
| `fs-dnsx` | `intra/dnsx` | registry/mux, cache, ALG, Plus, rank, RDNS |
| `fs-blocklist` | `github.com/celzero/gotrie` + stamps | bit-exact succinct trie, flags↔stamp |
| `fs-iptree` | `k-sone/critbitgo` (+ backend IpTree/RadixTree) | identical CSV ordering |
| `fs-x64` | `intra/x64` | DNS64 / NAT64 / NAT-PT |
| `fs-proxy` | `intra/ipn`, `intra/ipn/h1`, `intra/ipn/multihost` | RPN permanently stubbed |
| `fs-wg` | `intra/ipn/wg`, `wgproxy.go` | gotatun + smoltcp client stack, UAPI, Amnezia parse-only |
| `fs-rnet` | `intra/rnet` | local SOCKS5 / HTTP servers |
| `fs-intra` | `intra` | Tunnel lifecycle, handlers, bootstrap |
| `fs-jni` | gomobile `seq` runtime | cdylib `libgojni.so`, generated JNI glue |

## Branding layer
See [BRANDING.md](BRANDING.md). Applying `app/fork/rethinkreloaded.gradle` from `app/build.gradle.kts` changes the
`applicationId`, the versionCode scheme and the RPN flag, and adds resource overlays. No upstream resources are edited.
