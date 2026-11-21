# Releasing RethinkReloaded

## Channel
Signed **fdroid** flavor APKs (per ABI + universal) are published as GitHub Releases on `downlz/RethinkReloaded`.
They can be installed directly or tracked with [Obtainium](https://github.com/ImranR98/Obtainium).
The fdroid flavor has no Play Services, no Firebase, no in-app update checks and no billing.

The `website`, `play` and `alpha` variants are **not** shipped:
* `website` checks `dl.rethinkdns.com` for updates and would offer Celzero's APK.
* `play` needs Celzero's Play / Firebase setup.
* `alpha` points at Celzero's nightly workflow.

Do not pass `-PwebsiteDegoogled=true` or `-Pizzyondroid=true`. Those switch to upstream's IzzyOnDroid signing.

## Version scheme
* Tag: annotated `vX.Y.Z-rr.N`, where `vX.Y.Z` is the upstream release in `.fork/UPSTREAM` and `N` counts fork releases on that base.
* versionName: `git describe --tags`, which gives `v0.5.8-rr.1`.
* versionCode: `abi*10,000,000 + VERSION_CODE*100 + N`. `N` comes from the tag via `-PrrRevision=N`.
  Upstream's `VERSION_CODE` in `gradle.properties` is never edited.

## One-time: signing key
```bash
keytool -genkeypair -v -keystore rr-release.jks -alias rethinkreloaded -keyalg RSA -keysize 4096 -validity 10000
gh secret set RR_KS_BASE64 -R downlz/RethinkReloaded < <(base64 -i rr-release.jks)
gh secret set RR_KS_STORE_PASSWORD -R downlz/RethinkReloaded
gh secret set RR_KS_ALIAS -R downlz/RethinkReloaded --body rethinkreloaded
gh secret set RR_KS_KEY_PASSWORD -R downlz/RethinkReloaded
```
Keep `rr-release.jks` offline and backed up. Losing it means users must reinstall.
Publish the certificate's SHA-256 digest in `.github/README.md` once the first release is out.

## Cutting a release
```bash
git switch main && git pull
scripts/rr/check-ledger.sh && scripts/rr/rpn-tripwire.sh
git tag -a v0.5.8-rr.1 -m "RethinkReloaded v0.5.8-rr.1, based on celzero/rethink-app v0.5.8"
git push origin v0.5.8-rr.1
```
`rr-release.yml` writes a temporary `keystore.properties` from the secrets and runs
`:app:assembleFdroidFullRelease -PrrRevision=1`. It then creates a **draft** release with the APKs and `SHA256SUMS`.
The release notes link to upstream's release. Review the draft and publish it.

## Engine choice
`rr-release.yml` picks the network engine for each release:

| Tag | Engine | Release |
|---|---|---|
| `vX.Y.Z-rr.N-alpha.M` | Rust (`-PfirestackRepo=rust`) | draft **prerelease** |
| `vX.Y.Z-rr.N` | repository variable `RR_ENGINE`: `go` (default when unset) or `rust` | draft release |

The release notes state which engine a build uses.

Rollout (Phase 4, see [ENGINE_ROADMAP.md](ENGINE_ROADMAP.md)):
1. Until the phone check passes, stable releases stay on Go. Alpha tags carry the Rust engine to testers.
2. Then set `RR_ENGINE=rust` (Settings → Secrets and variables → Actions → Variables) to make Rust the default for
   releases. To go back, set it to `go` or delete it. No code change is needed either way, and Go stays selectable
   for as many releases as needed.

An alpha uses the same `rr.N` revision, and so the same versionCode, as the stable release it precedes. To let
testers install the stable release over an alpha, tag the alpha with the next revision instead
(`v0.5.8-rr.2-alpha.1` before `v0.5.8-rr.2`).

CI (`rr-ci.yml`) builds both engines on every PR; those test builds are workflow artifacts, never releases.
