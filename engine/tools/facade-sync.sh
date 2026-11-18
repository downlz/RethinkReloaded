#!/usr/bin/env bash
# Vendors the gobind-generated Java facade of celzero/firestack at a pinned commit and records the API golden.
#
#   engine/tools/facade-sync.sh <firestack-sha10>
#
# Downloads com.celzero:firestack:<sha> (AAR + sources jar) from Maven Central, verifies sha1 checksums, then:
#   * replaces engine/android/facade/src/main/java with the sources jar's Java (verbatim; gobind output)
#   * writes engine/api/firestack-api.txt  (sorted `javap -p -s -constants` of upstream classes.jar)
#   * writes engine/api/natives.tsv        (class \t method \t descriptor \t static \t throws) for jni-gen
#   * writes engine/api/PIN                (the sha)
# Re-run on every upstream firestackCommit bump (docs/fork/UPSTREAM_SYNC.md §5), then run jni-gen.
set -euo pipefail
sha=${1:?usage: $0 <firestack-sha10>}
engine=$(cd "$(dirname "$0")/.." && pwd)
base=https://repo1.maven.org/maven2/com/celzero/firestack/$sha
work=$(mktemp -d "${TMPDIR:-/tmp}/facade.XXXXXX"); trap 'rm -rf "$work"' EXIT

get() {
  curl -fsSL -o "$work/$1" "$base/$1"
  curl -fsSL -o "$work/$1.sha1" "$base/$1.sha1"
  [ "$(cut -c1-40 < "$work/$1.sha1")" = "$(shasum -a 1 "$work/$1" | cut -c1-40)" ] || { echo "sha1 mismatch: $1"; exit 1; }
}
get "firestack-$sha.aar"
get "firestack-$sha-sources.jar"

java_dir=$engine/android/facade/src/main/java
rm -rf "$java_dir"; mkdir -p "$java_dir"
(cd "$java_dir" && unzip -qo "$work/firestack-$sha-sources.jar" -x 'META-INF/*')

mkdir -p "$work/aar" "$work/classes"
(cd "$work/aar" && unzip -qo "$work/firestack-$sha.aar")
(cd "$work/classes" && unzip -qo "$work/aar/classes.jar")
cp "$work/aar/proguard.txt" "$engine/android/facade/consumer-rules.pro"

"$engine/tools/javap-api.sh" "$work/classes" > "$engine/api/firestack-api.txt"
"$engine/tools/natives-tsv.sh" "$engine/api/firestack-api.txt" > "$engine/api/natives.tsv"
echo "$sha" > "$engine/api/PIN"
echo "facade synced to firestack@$sha: $(find "$java_dir" -name '*.java' | wc -l | tr -d ' ') java files," \
     "$(wc -l < "$engine/api/natives.tsv" | tr -d ' ') natives"
