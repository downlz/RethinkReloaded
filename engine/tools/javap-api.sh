#!/usr/bin/env bash
# Prints a normalized, sorted ABI dump (javap -p -s -constants) of every class under a classes directory.
# Used both for the upstream golden and for our facade, so the two can be diffed (API contract test).
# Normalization: drops "Compiled from" lines and compiler-synthesized `access$NNN` accessors (emitted by javac for
# Java 8 targets, replaced by nestmates for 11+), which are not part of the API.
set -euo pipefail
dir=${1:?usage: $0 <classes-dir>}
(cd "$dir" && find . -name '*.class' | sed 's|^\./||; s|\.class$||; s|/|.|g' | LC_ALL=C sort \
  | xargs javap -p -s -constants -cp .) \
  | grep -v '^Compiled from' \
  | awk '
      /access\$[0-9]+\(/ { skip = 1; next }          # synthetic accessor ...
      skip == 1 && /descriptor:/ { skip = 0; next }  # ... and its descriptor line
      { skip = 0; print }' \
  | sed 's/[[:space:]]*$//' \
  | awk 'NF == 0 { blank = 1; next } { if (blank && $0 != "}") print ""; blank = 0; print }'
