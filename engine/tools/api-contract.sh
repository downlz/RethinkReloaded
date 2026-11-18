#!/usr/bin/env bash
# API contract test: the Rust engine must expose exactly the Java API of upstream firestack at api/PIN.
#
#  1. vendored facade == upstream sources jar (byte-for-byte; catches local edits / stale vendor)
#  2. javap dump of our compiled facade classes == api/firestack-api.txt (golden from upstream classes.jar)
#  3. every native in api/natives.tsv is exported by each built libgojni.so (and nothing is missing)
#  4. exports.rs is up to date with api/natives.tsv + impls.tsv (jni-gen --check)
#
# Usage: engine/tools/api-contract.sh   (run after `./gradlew -PfirestackRepo=rust ...` or the facade build)
set -euo pipefail
engine=$(cd "$(dirname "$0")/.." && pwd)
pin=$(cat "$engine/api/PIN")
work=$(mktemp -d "${TMPDIR:-/tmp}/contract.XXXXXX"); trap 'rm -rf "$work"' EXIT
fail=0

echo "== 1. vendored facade vs upstream firestack@$pin sources"
base=https://repo1.maven.org/maven2/com/celzero/firestack/$pin
curl -fsSL -o "$work/src.jar" "$base/firestack-$pin-sources.jar"
mkdir -p "$work/src" && (cd "$work/src" && unzip -qo ../src.jar -x 'META-INF/*')
if diff -r "$work/src" "$engine/android/facade/src/main/java" >/dev/null; then echo "   identical"; else
  echo "   MISMATCH (re-run tools/facade-sync.sh $pin)"; diff -rq "$work/src" "$engine/android/facade/src/main/java" | head; fail=1; fi

echo "== 2. javap ABI of our facade vs golden"
classes=$(find "$engine/android/facade/build" -type d -path '*javac*/classes' 2>/dev/null | head -1)
if [ -z "$classes" ]; then
  mkdir -p "$work/classes"
  android_jar=$(ls -d "${ANDROID_HOME:-$HOME/Library/Android/sdk}"/platforms/android-*/android.jar | sort -V | tail -1)
  find "$engine/android/facade/src/main/java" -name '*.java' > "$work/srcs.txt"
  javac -nowarn -encoding UTF-8 --release 17 -cp "$android_jar" -d "$work/classes" @"$work/srcs.txt" 2>/dev/null
  classes=$work/classes
fi
"$engine/tools/javap-api.sh" "$classes" > "$work/ours.txt"
if diff -u "$engine/api/firestack-api.txt" "$work/ours.txt" > "$work/api.diff"; then echo "   identical ($(grep -c ' native ' "$work/ours.txt") natives)"; else
  echo "   API DIFFERS:"; head -40 "$work/api.diff"; fail=1; fi

echo "== 3. exported JNI symbols"
expected=$(cargo run -q --manifest-path "$engine/Cargo.toml" -p jni-gen -- --symbols)
nm_bin=$(ls "${ANDROID_NDK_HOME:-$HOME/Library/Android/sdk/ndk/29.0.14206865}"/toolchains/llvm/prebuilt/*/bin/llvm-nm 2>/dev/null | head -1)
found_any=0
for so in "$engine"/android/facade/build/rustJniLibs/*/libgojni.so; do
  [ -f "$so" ] || continue; found_any=1
  missing=$(comm -23 <(printf '%s\n' "$expected" | sort) <("${nm_bin:-nm}" -D --defined-only "$so" | awk '{print $3}' | grep '^Java_' | sort))
  abi=$(basename "$(dirname "$so")")
  if [ -z "$missing" ]; then echo "   $abi: all $(printf '%s\n' "$expected" | wc -l | tr -d ' ') natives exported"; else
    echo "   $abi: MISSING $(printf '%s\n' "$missing" | wc -l | tr -d ' ')"; printf '%s\n' "$missing" | head; fail=1; fi
done
[ $found_any -eq 1 ] || echo "   (no libgojni.so built yet; skipped)"

echo "== 4. generated JNI glue up to date"
if cargo run -q --manifest-path "$engine/Cargo.toml" -p jni-gen -- --check 2>/dev/null; then echo "   up to date"; else echo "   STALE: cargo run -p jni-gen"; fail=1; fi

[ $fail -eq 0 ] && echo "API contract OK (firestack@$pin)"
exit $fail
