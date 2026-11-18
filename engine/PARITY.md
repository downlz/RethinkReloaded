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

## Reproduced quirks
* `RadixTree.delAll(prefix)` also deletes the empty key, if present. firestack seeds its delete list with ten nil keys
  (`make([][]byte, 10)`).

## Deliberate deviations
* `RadixTree.getAny/hasAny`: when only the empty key matches, Go indexes `rev[-1]` and panics; Rust reports no match.
* `Intra.connect` with `linkmtu <= 0`: firestack constructs two tunnels; the Rust engine will construct one.
* `Intra.connect2` ignores its `dtr` argument in firestack; the Rust engine will honour it.
* `Intra.build()` reports `rethinkreloaded-rust/<version> (firestack-api@<pin>)`, so bug reports identify the engine.
