#!/usr/bin/env python3
# Copyright (c) 2026 RethinkReloaded contributors.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""Compares two device-baseline.sh captures (Go first, Rust second) against the Phase 1 gates
(docs/fork/ENGINE_ROADMAP.md) and prints a Markdown table.

    engine/perf/compare.py engine/perf/baseline-go-<pin>-<dev>.json engine/perf/baseline-rust-<sha>-<dev>.json
"""

import json
import statistics
import sys


def steady_pss_mb(d):
    """Median PSS of the idle samples after the first (which still includes start-up garbage)."""
    s = [x["pss_kb"] for x in d["idle"]["samples"]][1:] or [0]
    return statistics.median(s) / 1024


def rows(go, rs):
    g_pss, r_pss = steady_pss_mb(go), steady_pss_mb(rs)
    yield ("Idle PSS (MB, median)", f"{g_pss:.0f}", f"{r_pss:.0f}", "≤ 80% of Go", r_pss <= 0.8 * g_pss)
    g, r = go["wakeups"], rs["wakeups"]
    yield ("Threads", g["threads"], r["threads"], "", None)
    yield ("Context switches / min, idle", g["ctx_switches_per_min"], r["ctx_switches_per_min"], "≤ Go",
           r["ctx_switches_per_min"] <= g["ctx_switches_per_min"])
    g, r = go["download"], rs["download"]
    yield ("LAN download (Mbit/s)", g["mbit_s"], r["mbit_s"], "≥ 95% of Go", r["mbit_s"] >= 0.95 * g["mbit_s"])
    g, r = go["app_cpu_seconds_per_gb"], rs["app_cpu_seconds_per_gb"]
    yield ("App CPU s / GB", g, r, "≤ Go", r <= g)
    g, r = go["dns_cached"], rs["dns_cached"]
    yield ("DNS cached p50 (ms)", g["p50_ms"], r["p50_ms"], "≤ Go + 1 ms", r["p50_ms"] <= g["p50_ms"] + 1)
    yield ("DNS cached p95 (ms)", g["p95_ms"], r["p95_ms"], "≤ Go", r["p95_ms"] <= g["p95_ms"])
    g, r = go["dns_uncached"], rs["dns_uncached"]
    yield ("DNS uncached p50 (ms)", g["p50_ms"], r["p50_ms"], "(internet; informational)", None)
    yield ("DNS uncached ok / sent", f'{g["ok"]}/{g["count"]}', f'{r["ok"]}/{r["count"]}', "", None)
    g, r = go["idle"].get("libgojni_bytes"), rs["idle"].get("libgojni_bytes")
    if g and r:
        yield ("libgojni.so in APK (MB)", f"{g / 1e6:.1f}", f"{r / 1e6:.1f}", "", None)


def main():
    go, rs = (json.load(open(p)) for p in sys.argv[1:3])
    print(f"Go: {go['label']} ({go['captured']}); Rust: {rs['label']} ({rs['captured']})")
    print(f"network: Go `{go['network']}` / Rust `{rs['network']}`\n")
    print("| Metric | Go | Rust | Gate | Pass |\n|---|---|---|---|---|")
    for name, g, r, gate, ok in rows(go, rs):
        mark = "" if ok is None else ("yes" if ok else "**no**")
        print(f"| {name} | {g} | {r} | {gate} | {mark} |")


if __name__ == "__main__":
    main()
