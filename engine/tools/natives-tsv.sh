#!/usr/bin/env bash
# Extracts native methods from a javap -p -s dump: class<TAB>method<TAB>descriptor<TAB>static(0/1)<TAB>throws(0/1)
set -euo pipefail
awk '
  /^[^ ].*(class|interface) [^ ]+/ {
    for (i = 1; i <= NF; i++) if ($i == "class" || $i == "interface") { cls = $(i+1); break }
    sub(/<.*/, "", cls); next
  }
  / native / {
    decl = $0; st = (decl ~ / static /) ? 1 : 0; th = (decl ~ / throws /) ? 1 : 0
    name = decl; sub(/\(.*/, "", name); n = split(name, parts, " "); name = parts[n]
    getline; desc = $0; sub(/^[[:space:]]*descriptor: /, "", desc)
    printf "%s\t%s\t%s\t%d\t%d\n", cls, name, desc, st, th
  }
' "${1:?usage: $0 <javap-dump>}" | LC_ALL=C sort
