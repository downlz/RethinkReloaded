## RethinkReloaded

> **RethinkReloaded is a community fork of [Rethink DNS + Firewall + VPN](https://github.com/celzero/rethink-app) by [Celzero](https://github.com/celzero) and [its contributors](https://github.com/celzero/rethink-app/graphs/contributors).**
> It is not affiliated with or endorsed by Celzero. All credit for the app goes to its original authors: please [support upstream](https://svc.rethinkdns.com/r/sponsor).

RethinkReloaded tracks every upstream rethink-app release and adds one major change: a **Rust rewrite of the
[firestack](https://github.com/celzero/firestack) network engine** (DNS, firewall, user-space TCP/IP stack,
proxies, WireGuard). The goal is a lower memory footprint, less CPU, and better battery life for an always-on VPN.
The Kotlin app (UI, `VpnService`, database) is unchanged upstream code.

| | |
|---|---|
| Upstream app | [celzero/rethink-app](https://github.com/celzero/rethink-app) — Apache-2.0 |
| Upstream engine | [celzero/firestack](https://github.com/celzero/firestack) — MPL-2.0 (Go) |
| This fork's engine | [`engine/`](../engine) — MPL-2.0 (Rust port of firestack) |
| Synced upstream release | see [`.fork/UPSTREAM`](../.fork/UPSTREAM) |
| Upstream README | [`README.md`](../README.md) (kept verbatim) |

### Status

The Rust engine is under active development and **not yet feature-complete**. The default build still uses
upstream's Go engine. To build with the Rust engine, run `./gradlew -PfirestackRepo=rust :app:assembleFdroidFullDebug`.
See the [engine roadmap](../docs/fork/ENGINE_ROADMAP.md) for phases and parity gates.

### What differs from upstream

* Application id `io.github.downlz.rethinkreloaded`, so it installs alongside the original Rethink app. The app name is "RethinkReloaded".
* Only the F-Droid (de-Googled) flavor is built. Rethink Plus / RPN (Celzero's paid proxy service) is hidden because it is tied to Celzero's billing.
* Every upstream file the fork touches is listed in [`FORK_CHANGES.md`](../FORK_CHANGES.md).

### Documentation

* [Upstream sync workflow](../docs/fork/UPSTREAM_SYNC.md) — how each celzero release is merged in
* [Architecture](../docs/fork/ARCHITECTURE.md) · [Engine roadmap](../docs/fork/ENGINE_ROADMAP.md) · [Testing & parity](../docs/fork/TESTING.md)
* [Branding](../docs/fork/BRANDING.md) · [Releasing](../docs/fork/RELEASING.md)

### Credits & upstream

Everything that makes this app useful was built by **Celzero** and the **RethinkDNS contributors**.
That includes the firewall, DNS and blocklists, WireGuard split-tunnelling, the UI, and the translations.

* App: [celzero/rethink-app](https://github.com/celzero/rethink-app) · [contributors](https://github.com/celzero/rethink-app/graphs/contributors)
* Engine: [celzero/firestack](https://github.com/celzero/firestack) · [contributors](https://github.com/celzero/firestack/graphs/contributors)
* Resolver & blocklists: [serverless-dns](https://github.com/serverless-dns) — RethinkReloaded uses Celzero's public services
  (`dl.rethinkdns.com`, `sky.rethinkdns.com`, `max.rethinkdns.com`), subject to their [terms & privacy policy](https://rethinkdns.com/privacy).
* Translations: [Weblate](https://hosted.weblate.org/engage/rethink-dns-firewall/) — please contribute translations upstream.
* Also built on work by Jigsaw (Intra / Outline), WireGuard LLC, and ezelab (Android TV). See [`NOTICE`](../NOTICE).

Sponsor upstream: [GitHub Sponsors](https://github.com/sponsors/serverless-dns) · [svc.rethinkdns.com/r/sponsor](https://svc.rethinkdns.com/r/sponsor)

### License

App code: [Apache-2.0](../LICENSE) (unchanged from upstream). Engine (`engine/`): [MPL-2.0](../engine/LICENSE).
Original copyright notices are retained in all files.
