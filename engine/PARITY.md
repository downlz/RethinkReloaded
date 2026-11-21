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
| `rdns.tsv` | 7065 (flagsToStamp, stampToFlags, stampToNames, setStamp; b32/b64, padded/unpadded, v0, malformed) | identical, except 17 firestack panics |
| `alg.tsv` | 3851 (ALG address generation, registrations, translate/split, transport stops, X, PTR, RDNSBL, resolv) | identical (lists compared as sets) |
| `rdnstrie.tsv` | 25650 (trie lookups, blockQuery for A/HTTPS/TXT, blockAnswer on CNAME targets, 9 stamps) | identical |

`rdnstrie.tsv` was recorded against the on-device blocklist with `tdmd5` `ae5d0e6e0dca1451aeb51fc7f3debc21` (about
180 MB, not committed). To replay it, download `td.txt`, `rd.txt`, `basicconfig.json` and `filetag.json` as the app
does (`https://dl.rethinkdns.com/{trie?compressed,rank?compressed,basicconfig,blocklists}`) and set
`RR_BLOCKLIST_DIR`; the test skips itself when the directory is missing or holds another trie. Re-record with
`RR_BLOCKLIST_DIR=… tools/go-oracle/run.sh --docker`.

## Reproduced quirks
* `IpTree` CSV handling: `add` checks `strings.Contains` before splitting, so a value that is a substring of another is
  still appended. `Set(cidr, "")` deletes the route. `esc` returns true even when the value was not present but
  resembled one.
* `RadixTree.delAll(prefix)` also deletes the empty key, if present. firestack seeds its delete list with ten nil keys
  (`make([][]byte, 10)`).
* Blockstamps: Go's unpadded base32 decoder silently drops a trailing group of 1, 3 or 6 symbols (6 symbols carry
  3 bytes, which are lost), so `1-<stamp>A` decodes like `1-<stamp>`. Base64 decoding ignores `\r`/`\n` and accepts
  non-zero trailing bits. The trie lookup only accepts padded base64url `1:` stamps, so an unpadded base64 stamp set
  with `setStamp` validates but blocks nothing.
* DNS cache: every answer through a `Cache<tid>` transport is reported `cached`; answers that are not cacheable
  (NXDOMAIN, local addresses) are still returned with their answer TTLs set to 15 s, because firestack treats a
  cache miss as "not fresh".

## Phase 1 notes
* The TCP handshake with the app completes before the policy decision, as in firestack with happy eyeballs off.
  Blocked connections are closed after the stall, not reset.
* Upstream DNS failures send **no reply** to the app, as firestack.
* ICMP echo replies are synthesized whenever the probe socket opened, even if the remote stayed silent, as firestack.
* `onPrequery` is not called. Kotlin always returns null for it; it will be wired up if it ever carries policy.
* `onUpstreamAnswer` runs for cached answers too (Kotlin applies IP rules and lockdown there).
* Caches are per transport, as firestack's `ctransport`: stale entries are served with 15 s TTLs plus a background
  refresh, identical in-flight queries share one exchange (outcomes reused 30 s, errors 6 s), and after 10 s of send
  failures a transport's cache serves nothing (hangover).
* `Goos` (Go's system resolver) is served by the `System` transport, i.e. the network's DNS servers set via
  `setSystemDNS`.
* DoH POSTs carry `content-length`. Go always sends it, and Cloudflare's h2 front end rejects requests without it.
* UDP endpoint-independent mapping/filtering (`Intra.transparency`) follows firestack's `udpmux`: one socket per
  (proxy, app source); unsolicited peers go through `inflow` only with filtering on. Muxers stop after three idle
  120 s windows.
* The DNS gateway (ALG) is ported: translation to per-domain 100.64.0.0/10 and 64:ff9b:1:da19:100::/80 addresses,
  the internal A/AAAA cache, secondary transports (`TIDSECCSV`), preset answers (`IPCSV`), `Fixed` answers, and on
  the flow side `undoAlg` (real addresses, names, probable names, blocklists for Kotlin's `flow`), re-resolution of
  expired translations for the app's uid, and dialing the real addresses in turn (15 s retry window). The gateway
  runs with translation off too: it is the IP -> name map behind `flow`'s domains.
* Kotlin receives normalized query names (no trailing dot, lowercase) in `onQuery` and every summary, as firestack.
* Blocked answers carry TTL 0 (firestack's `BustDnsproxydResNetCache`), as do ALG answers.
* Not yet ported:
  * DNS64/NAT64 (Phase 3): nothing is synthesized or un-NAT64'd;
  * undelegated / special-use domains (`requiresGoosOrLocal`, `CacheUndelegatedQueries`) and mDNS (`Local`);
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
* Choosing among several tids in `TIDCSV` picks at random among healthy transports; firestack also ranks remote,
  recovered and proxied transports first (`Categorize`).
* The DNS cache bounds its size (dropping expired entries, then those closest to expiry, beyond 64k entries per
  transport); firestack only logs an overflow. Non-ASCII query names bypass the cache; firestack fails those queries.
* Blocklist files with an out-of-range `value` or a missing `uname` fail `setRdnsLocal`; firestack panics on them.
* `Intra.build()` reports `rethinkreloaded-rust/<version> (firestack-api@<pin>)`, so bug reports identify the engine.
