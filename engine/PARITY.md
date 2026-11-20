# Parity notes

This file records where the Rust engine intentionally differs from firestack, or reproduces a firestack quirk on
purpose. Read it before "fixing" any behaviour toward or away from Go.

## Object model
* Every Java proxy object receives its own negative refnum, so `Seq.destroyRef` drops exactly one reference.
  `Seq.incGoRef` is therefore a no-op: Rust reads a proxy's `refnum` field directly instead of using gobind's
  `incRefnum()` round trip.
* Errors are thrown as `go.Universe$proxyerror`, as in gobind. `getMessage()` returns the Rust error text.
* Not-yet-ported natives:
  * those declared `throws Exception` throw `proxyerror("unimplemented in RethinkReloaded rust engine: X")`;
  * all others return Go's zero value (`""` for strings, `null` for objects, `0`/`false`).
* RPN natives (Rpn*, Pip*, `Proxies.rpn`, `Backend.*pip*`) are permanently unsupported: they throw
  `rpn: unsupported` or return zero values. RethinkReloaded does not offer RPN.

## Verified against firestack
Seeded random operation sequences are recorded from firestack itself (`tools/go-oracle`, run in Docker on Linux) and
replayed by the Rust tests (`crates/*/tests/oracle.rs`). At `d3d530ea3e`:

| Fixture | Operations | Result |
|---|---|---|
| `iptree.tsv` | 10040 (all 18 IpTree methods, v4/v6/mapped/zoned/invalid inputs) | identical, except 17 firestack panics |
| `radixtree.tsv` | 8040 (all 10 RadixTree methods, Unicode and empty keys) | identical, except 90 firestack panics |
| `wgkey.tsv` | 70 (parse, hex, base64, isZero, mult) | identical |
| `settings.tsv` | 54 (mode2String, l3, engine, setDialerOpts, setAutoMode) | identical |

## Reproduced quirks
* `IpTree` CSV handling: `add` checks `strings.Contains` before splitting, so a value that is a substring of another is
  still appended. `Set(cidr, "")` deletes the route. `esc` returns true even when the value was not present but
  resembled one.
* `RadixTree.delAll(prefix)` also deletes the empty key, if present. firestack seeds its delete list with ten nil keys
  (`make([][]byte, 10)`).

## Phase 1 notes
* The TCP handshake with the app completes before the policy decision, as in firestack with happy eyeballs off.
  Blocked connections are closed after the stall, not reset.
* Upstream DNS failures send **no reply** to the app, as firestack.
* ICMP echo replies are synthesized whenever the probe socket opened, even if the remote stayed silent, as firestack.
* `onPrequery` is not called. Kotlin always returns null for it; it will be wired up if it ever carries policy.
* `Goos` (Go's system resolver) is served by the `System` transport, i.e. the network's DNS servers set via
  `setSystemDNS`.
* DoH POSTs carry `content-length`. Go always sends it, and Cloudflare's h2 front end rejects requests without it.
* Not yet ported:
  * cache stale-while-revalidate and coalescing of identical in-flight queries;
  * UDP endpoint-independent mapping (`Intra.transparency`);
  * ALG translation (`Resolver.translate(true, …)`);
  * pcap.
  `Tunnel.stat()` still throws; Kotlin catches it.

## Deliberate deviations
* `RadixTree.getAny/hasAny`: when only the empty key matches, Go indexes `rev[-1]` and panics; Rust reports no match.
  The oracle recorded 90 such panics in 8040 operations.
* `IpTree`: critbitgo panics (index out of range) when a route key is longer than its address family allows. That
  happens with IPv4-mapped routes such as `::ffff:10.1.2.0/120` (stored as 4 bytes plus a /120 prefix), and also with
  IPv4-mapped queries against such keys. Rust treats these as "no match"; the oracle recorded 17 panics in
  10040 operations. In firestack such a panic would take down the engine.
* `Intra.connect` with `linkmtu <= 0`: firestack constructs two tunnels; the Rust engine will construct one.
* `Intra.connect2` ignores its `dtr` argument in firestack; the Rust engine will honour it.
* `Intra.build()` reports `rethinkreloaded-rust/<version> (firestack-api@<pin>)`, so bug reports identify the engine.
