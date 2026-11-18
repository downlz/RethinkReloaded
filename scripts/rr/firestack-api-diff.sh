#!/usr/bin/env bash
# Shows the Java API delta of the gomobile-generated firestack facade between two pinned commits,
# using the sources jars published on Maven Central (com.celzero:firestack:<sha10>).
# Usage: scripts/rr/firestack-api-diff.sh <old-sha10> <new-sha10> [--full]
set -euo pipefail
[ $# -ge 2 ] || { echo "usage: $0 <old-sha10> <new-sha10> [--full]"; exit 2; }
old=$1; new=$2; mode=${3:-}
base=https://repo1.maven.org/maven2/com/celzero/firestack
work=$(mktemp -d "${TMPDIR:-/tmp}/fsapi.XXXXXX"); trap 'rm -rf "$work"' EXIT

fetch() { # $1=sha → $work/$1/src
  local v=$1 jar="firestack-$1-sources.jar"
  mkdir -p "$work/$v/src"
  curl -fsSL -o "$work/$v/$jar" "$base/$v/$jar"
  curl -fsSL -o "$work/$v/$jar.sha1" "$base/$v/$jar.sha1"
  local want got
  want=$(tr -d ' \n' < "$work/$v/$jar.sha1" | cut -c1-40)
  got=$(shasum -a 1 "$work/$v/$jar" | cut -c1-40)
  [ "$want" = "$got" ] || { echo "sha1 mismatch for $jar"; exit 1; }
  (cd "$work/$v/src" && unzip -q "../$jar")
}
fetch "$old"; fetch "$new"

# Reduce each Java file to its API surface: public/protected declarations and constants.
api() { # $1=dir
  (cd "$1" && find . -name '*.java' | sort | while read -r f; do
     grep -E '^[[:space:]]*(public|protected)[[:space:]]' "$f" | grep -v '^[[:space:]]*//' | sed -E 's/[[:space:]]+/ /g; s/ ?\{.*$//; s/^ //' \
       | sed "s|^|${f#./}: |"
   done)
}
if [ "$mode" = "--full" ]; then
  diff -ru "$work/$old/src" "$work/$new/src" || true
else
  diff <(api "$work/$old/src") <(api "$work/$new/src") | grep -E '^[<>]' \
    | sed 's/^</- removed:/; s/^>/+ added:  /' || echo "no public API change between $old and $new"
fi
