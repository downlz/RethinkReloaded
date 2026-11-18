#!/usr/bin/env bash
# Regenerates engine/testdata/oracle/<sha>/*.tsv by running the injected oracle tests inside a clean checkout of
# celzero/firestack at <sha> (default: engine/api/PIN). Needs Go (GOTOOLCHAIN auto-downloads firestack's go.mod
# version) or Docker (--docker uses golang:<go.mod version>).
#
#   engine/tools/go-oracle/run.sh [--docker] [sha]
set -euo pipefail
docker=0; [ "${1:-}" = "--docker" ] && { docker=1; shift; }
engine=$(cd "$(dirname "$0")/../.." && pwd)
sha=${1:-$(cat "$engine/api/PIN")}
out=$engine/testdata/oracle/$sha
work=$(mktemp -d "${TMPDIR:-/tmp}/rr-oracle.XXXXXX"); trap 'rm -rf "$work"' EXIT

git -C "$work" init -q fs && git -C "$work/fs" remote add origin https://github.com/celzero/firestack.git
git -C "$work/fs" fetch -q --depth 1 origin "$sha" 2>/dev/null || git -C "$work/fs" fetch -q origin
git -C "$work/fs" checkout -q "$sha"
cp "$engine"/tools/go-oracle/inject/*_test.go "$work/fs/intra/backend/"
mkdir -p "$out"
gover=$(sed -n 's/^go //p' "$work/fs/go.mod")
toolchain=$(sed -n 's/^toolchain //p' "$work/fs/go.mod")
# a bare language version (go 1.27) is not a toolchain name; Go's first release of it is go1.27.0
if [ -z "$toolchain" ]; then case "$gover" in *.*.*) toolchain=go$gover ;; *) toolchain=go$gover.0 ;; esac; fi
args=(test -count=1 -tags oracle -ldflags=-checklinkname=0 -run Oracle ./intra/backend/)
if [ $docker -eq 1 ]; then
  docker run --rm -v "$work/fs:/src" -v "$out:/out" -w /src -e RR_ORACLE_OUT=/out "golang:${toolchain#go}" go "${args[@]}"
else
  (cd "$work/fs" && GOTOOLCHAIN="$toolchain" GOFLAGS=-mod=mod RR_ORACLE_OUT="$out" go "${args[@]}")
fi
echo "$sha" > "$out/PIN"
wc -l "$out"/*.tsv
