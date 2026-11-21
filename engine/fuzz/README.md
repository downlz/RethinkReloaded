# Engine fuzzers

[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) targets for the parsers that read untrusted input. Each one
must never panic:

| Target | Input |
|---|---|
| `dns_msg` | DNS messages from apps and the network, through every transform the resolver applies |
| `stamp` | DNS stamps (`sdns://`) and NAT64 prefixes |
| `dnscrypt` | DNSCrypt certificate TXT records, and responses and queries through the interceptor |
| `odoh_config` | ODoH target configs |
| `wg_config` | WireGuard configs and allowed-IP networks |
| `iptree` | IpTree operation sequences (IP rules) |
| `packets` | raw packets from the TUN: ICMP echo parsing, pcap summaries |
| `proxy_server` | local SOCKS5/HTTP server requests |

The fuzzers call private parsers through `#[cfg(fuzzing)]` modules. `cargo fuzz` sets that cfg itself, so these
modules are absent from normal builds.

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
cd engine/fuzz
mkdir -p corpus/dns_msg && cp seeds/dns_msg/* corpus/dns_msg/
cargo +nightly fuzz run -O dns_msg corpus/dns_msg -- -max_total_time=300
```

`seeds/` holds the starting inputs plus the reproducers of every crash found so far, which are fixed and covered by
unit tests:
* `seeds/packets/crash-icmp-short-total`: an IPv4 total length shorter than its header. It panicked the TUN reader,
  so any app could stop the VPN.
* `seeds/wg_config/crash-key-nonascii`: a non-ASCII character inside a key.

Generated corpora and artifacts are not committed.
