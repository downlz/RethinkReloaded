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
* Undelegated / special-use names (firestack's list of 148) go to the system resolver when Kotlin enables
  `Intra.undelegatedDomains`, and are never cached. As in firestack, entries without a leading dot (the private reverse
  zones) match only themselves.
* Kotlin receives normalized query names (no trailing dot, lowercase) in `onQuery` and every summary, as firestack.
* Blocked answers carry TTL 0 (firestack's `BustDnsproxydResNetCache`), as do ALG answers.
* Not yet ported:
  * (pcap and `Tunnel.stat()`: see Phase 3 notes)

## Phase 2 notes
* Proxies follow firestack's `ipn`: Base/Exit/Block/Auto (Auto → Exit; RPN is excluded), SOCKS5 (TCP, UDP
  associate, credentials), HTTP CONNECT (Basic, one 407 retry, TLS to `https://` proxies, no UDP) and WireGuard.
  WireGuard tunnels run gotatun with a userspace smoltcp stack per proxy. Config text is parsed as firestack does
  (UAPI keys, an empty line ends parsing, the configured MTU is treated as the network MTU). Amnezia keys are parsed
  and ignored, as firestack.
* Hops (`Proxies.hop` / `testHop`) apply firestack's rules: no self or triple hops, no stopped proxies, the via must
  route ip4 or ip6. WireGuard additionally needs a via that carries its address family, announces UDP, routes every
  peer endpoint and has a known MTU (`calcTunMtu` of the via's router MTU, reconciled). A SOCKS5 or HTTP proxy has no
  MTU (`errNoMtu`), so WireGuard hops only through WireGuard. A WireGuard router reports `calcNetMtu` (tunnel MTU
  + 80), as firestack.
* DNS queries dial through the proxies Kotlin names in `TIDCSV` (`tid:pid`); with several, the first usable one
  (`ProxyTo`). `Intra.addProxyDNS` registers a DNS53 transport with the proxy's id for its first DNS address;
  firestack also accepts a host name there.
* A hop (and a refresh) handshakes right away, as firestack's `Refresh`. Handshake waits are bounded to 500 ms;
  gotatun's `force_handshake` otherwise waits forever for an unreachable peer.
* Updating a WireGuard proxy re-creates it (firestack updates a running device in place when only peers changed).
* gotatun's timers tick every 250 ms while a tunnel is up (Phase 4 tuning item).
* Local servers (`Tunnel.getServices`, firestack `rnet`): SOCKS5 (CONNECT, UDP associate) and HTTP (CONNECT and
  plain `http://` requests) servers. Every connection is routed by Kotlin (`svcRoute`), dialled out protected as
  the server or through the bridged proxy, and summarized (`onSvcComplete`, 50 ms later). HTTPS servers are
  unimplemented, as in firestack. v0.5.8's app never starts a server.

## Phase 3 notes
* DNSCrypt (firestack `dnscrypt`, from dnscrypt-proxy):
  * Stamps are parsed as by the go-dnsstamps version firestack pins: DNSCrypt, DoH and DNSCrypt-relay stamps
    only, default port 443.
  * Certificates are fetched over Exit, never through relays. Four racing attempts alternate UDP and TCP; the first
    answer wins (firestack prefers the fastest, which only matters when several answer).
  * The newest valid certificate is kept; certificates are refreshed every 4 h. When none is valid, timestamps are
    ignored on retry.
  * Queries: XSalsa20 or XChaCha20 secretbox, padded as firestack. UDP (two tries) then TCP. A random relay gets
    the anonymization header, and the relay is reported as the summary's pid.
  * Relays are kept by stamp and removed with `DNSResolver.remove(stamp)`.
  * Not ported: a proxy registered under the server's id acting as its relay.
  * Answers are not truncated for UDP clients (as DoH and DNS53 in this engine). firestack truncates DNSCrypt answers
    above the client's EDNS size.

* ODoH (RFC 9230, firestack `doh/odoh.go`):
  * HPKE via Cloudflare's odoh-rs.
  * Queries go to the target, or through the relay with `targethost`/`targetpath`. Relay paths default to `/proxy`,
    target paths to `/dns-query`.
  * The target config comes from its HTTPS record (SvcParam 32769) and is cached for the record's TTL. firestack asks
    the default DNS first, then 1.1.1.1 over DoH; here 1.1.1.1 over DoH is asked directly. Otherwise the config comes
    from `/.well-known/odohconfigs`, cached 1 h. The source that worked last goes first.
  * A client error (4xx) drops the cached config.

* Rethink Plus (firestack `dnsx/plus.go`):
  * Transports with ids prefixed `Plus` join Plus, without `onDNSAdded`; `get` of such an id is Plus itself.
  * Each query tries up to six members in this order: the one that answered last, the complete ones by p50,
    Default, fresh or soft-failed ones, then recoverable ones. Errored ones are added when fewer than six remain.
  * The order follows the Plus strategy (safest, random, fastest, robust) and the Plus filter (ad-block, security,
    family; matched on the member's address, as firestack). The order is reused for 10 s.
  * SERVFAIL, blocked and error answers move on to the next member. Empty answers do too, until half the tries are
    spent.
  * `DNSResolver.getMult` serves `Plus` and `DcProxy`.
* `DNSTransport.measure` follows firestack `Perf`, but uses its preset domains instead of hosts sampled from the IP
  map. Percentiles are exact rather than P² estimates. `getRelay` is null: no transport here dials through a
  relay proxy registered under its id.
* As firestack, `http://` DoH URLs mean HTTPS without certificate verification, and DoT verifies certificates only
  for `tls:`/`tls://` URLs. Kotlin uses both for resolvers the user marked insecure, as Plus members.

* DNS64 / NAT64 (firestack `x64`):
  * NAT64 prefixes per resolver come from `ipv4only.arpa AAAA` (RFC 7050): the System transport's answer is the
    network's prefix. The engine's local 464 prefix `64:ff9b:1:fffe::/96` is always the last resort.
  * Active per PT mode: `none` off, `auto` only when the link has IPv6, `force*` on.
  * AAAA questions answered without AAAA records (and not authenticated, unless forced) are answered from the name's
    A records, asked of the same transport, under that resolver's prefix, else the network's, else the local one.
  * Flows to the local prefix are dialed over the IPv4 they encode. IPv4 targets go through the network's prefix
    on IPv6-only links or with `force46`.
  * Address arithmetic reproduces firestack's, including its two `ip4to6` variants: synthesis skips RFC 6052's
    byte 8, `X46` does not. The oracle covers 520 cases.
  * The stdlib resolver's prefix (`net.DefaultResolver`) is not looked up.
* mDNS (`Local`, firestack's one-shot mode):
  * The question goes from protected unicast sockets to 224.0.0.251 and ff02::fb (port 5353) on the link's
    families.
  * The first response within 3 s carrying an address for the name (or for an alias of it) answers.
  * The answer is rebuilt around the app's question and id; firestack returns the raw mDNS message.

* `Tunnel.stat()` (Kotlin's network stats screen):
  * Reports what this engine tracks: TUN packets and bytes, open TCP and UDP connections, link, resolver, proxy and
    settings state.
  * firestack fills these structs from gVisor's counters; the remaining counters read 0.
* `setPcap`: as firestack, "" turns it off, one character logs a line per packet, and a path is appended to in
  pcap format (raw IP link type).
* Engine logs reach Kotlin's console (they did not before):
  * Over firestack's memfd double buffer (`logMemFD`, 801-byte slots, drained when a buffer is full or 2.5 s after
    its first line).
  * Without memfd, via `Console.log` per line; the pipe (`logFD`) is not used.
* Go runtime diagnostics, reproduced in shape only:
  * `goMet`: process memory, threads and CPUs.
  * `printStack`: the engine's threads and the caller's backtrace.
  * `memProfile` / `cpuProfile`: text reports of memory and of CPU time sampled over 10–120 s.
  * `crash`: report, then abort or not, per type.
  * `setFlightRecordOutput`: the path is remembered.
* Settings and summaries:
  * `DNSOptions` and `ProxyOptions` (with their `Settings.new…` constructors) parse addresses as firestack does.
  * `DNSSummary`, `FlowSummary` and `DialerOpts` `string()` use firestack's formats, including `FmtBytes` /
    `FmtPeriod`; unit tests pin the output.
  * `DNSOpts` / `DomainOpts` `copy()` copy every field.
* `Proxy.client()` `IP4/IP6` (the exit IP and location shown on the WireGuard screen):
  * Plain HTTP/1.1 GETs over the proxy, with firestack's 4 s limit, 128 KiB body cap and DNS-transport choice.
  * Providers in firestack's order: dl.rethinkdns.com/ip, Cloudflare trace, WARP, Mullvad.
  * As in firestack, answers are cached per proxy, family and address for 1 h (12 min for built-ins), and the
    proxy must have dialed (OK/KO status).
* `Proxies.underlay(id, controller)` (an untracked Base) and `Intra.controlledRouter` (the router of an untracked
  Exit) route sockets through the given `Controller`.
* Split, desync and retry (`DialerOpts`) for Exit/Base TCP to public servers on ports 443 and 853 (firestack's
  `doSplit`; as in Go, loopback counts as public):
  * Strategies per attempt, reply timeouts (`calcTimeout`), the replay of everything written before the first
    reply, and the "short TLS reply to a split" retry all follow `retrier.go`; table and timing tests pin them.
  * The TCP split happens at 32–64 bytes, and the TLS record fragmentation at 6–64 bytes, as in firestack.
  * Desync sends firestack's decoy POST through `sendfile` from a memfd page, at the largest TTL that a UDP
    traceroute saw expire (cached 30 s per address), then overwrites the page and restores TTL 64.
  * The mechanics are tested on an Android kernel (emulator). Measuring the TTL needs real ICMP, which the
    emulator's user-mode network does not deliver.
  * Desync is Linux-only, as in firestack; elsewhere the connection is plain.
  * `DialAny` (Auto's multi-dialer retrier) is not ported. The Auto proxy keeps its own fallback order.
* ECH for DoH (and so for ODoH relays):
  * The `ech` parameter of the server's HTTPS record is looked up through the Default transport, in the
    background, as firestack does.
  * On a rejection, the server's retry configs are used, else a fresh lookup.
  * `DNSSummary.ECH` reports an accepted ECH.
  * rustls performs the handshake, with client-side HPKE (X25519/HKDF-SHA256 and AES-GCM or ChaCha20-Poly1305)
    supplied through the `hpke` crate.
  * Live test: sky.rethinkdns.com accepts it.
  * firestack's `DialWithTls` (ECH for other TLS dials) has no caller among the engine paths ported so far.
* Census (Phase 3 exit):
  * Every native is implemented except the RPN stubs and 96 "unreachable" ones.
  * The unreachable natives belong to engine-side wrappers (`$proxyX`) of interfaces that the engine never hands
    to Kotlin: Bridge, Controller, Console, the listeners, LogConsumer, and the provider interfaces.
  * jni-gen derives this with a fixpoint over the API:
    * returns of reachable natives;
    * plus parameters of the callbacks the engine invokes on objects Kotlin passed in.
  * A test asserts that nothing else remains.

* DNSCrypt relays (anonymized DNSCrypt) only work with servers on standard ports. Public relays refuse to forward
  to non-standard ports such as AdGuard's 5443, so the app's AdGuard preset gets no answers once a relay is on. That is
  the relays' policy, and it affects firestack the same way. The emulator run and a live test through the app's
  relays to OpenDNS on port 443 confirm the relay path works.

## Deliberate deviations
* `Proxy.client()` skips firestack's second provider, Windscribe's geo API, because firestack calls it with a made-up
  bearer token and the fork does not send forged credentials to a third party. The remaining providers cover the
  same fields, except latitude and longitude, which the Cloudflare trace lacks.
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
* A replaced proxy's hop origins re-hop through its successor (firestack's via references follow the id; Rust's
  point at the instance).
* Local servers work. firestack's do not serve: its SOCKS5 `candial` refuses every connection while running, and its
  `start` refuses unless stopped. Its HTTP `start` refuses after a `stop`, and a proxied SOCKS5 connect fails on a
  non-TCP conn. In Rust, servers listen on `start()`, `refresh()` restarts them, and `addServer` succeeds when there
  is no namesake proxy to bridge (firestack returns the bridge error). HTTP credentials are read from
  `Proxy-Authorization` as well as `Authorization` (firestack reads only the latter). `svcRoute` gets the client
  address as `src` for CONNECTs (firestack passes the server's own address). A SOCKS5 UDP association relays only for
  the client that asked, and ends with its control connection.
