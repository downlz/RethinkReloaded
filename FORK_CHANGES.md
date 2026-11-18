# Fork change ledger

This file lists every **upstream** file (from [celzero/rethink-app](https://github.com/celzero/rethink-app)) that
RethinkReloaded modifies. It keeps the fork's diff against each upstream release small and reviewable, and it is the
"prominent notice" of modified files required by Apache-2.0 §4(b). Each modified line or block is also tagged `[rr]`
in the file itself.

`scripts/rr/check-ledger.sh` (run in CI) fails when an upstream file differs from the tag in `.fork/UPSTREAM` but is
not listed below, or when a listed file lacks an `[rr]` marker.

Fork-owned paths need no ledger entry because upstream never has them:
`engine/`, `app/fork/`, `docs/fork/`, `scripts/rr/`, `.fork/`, `.github/workflows/rr-*`, `.github/README.md`, `NOTICE`,
`FORK_CHANGES.md`.

## Modified upstream files

| File | Change | Why | Upstreamable |
|---|---|---|---|
| `.gitignore` | ignore `keystore.properties`, `*.jks`, `*.keystore` | never commit signing material | yes |

<!-- ledger:begin -->
- `.gitignore`
<!-- ledger:end -->

## Disabled upstream workflows (via `gh workflow disable`, files untouched)

| Workflow | Reason |
|---|---|
| `nightly.yml` | needs celzero's alpha keystore, Play dev-id and Telegram secrets |
| `izzyondroid.yml` | triggers on every `v*` tag (including fork tags) and needs celzero's IzzyOnDroid keystore |
| `telegram-notify.yml` | posts to celzero's Telegram channel |
| `ocr.yml` | needs celzero's LLM review credentials |
