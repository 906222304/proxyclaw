"""Performance baseline math & before/after comparison for stress-summary.json.

Used both as a library by tests/stress_backend.py (histogram window diffing,
RSS-vs-process-count regression) and as a CLI to compare two benchmark runs:

    python tests/compare_stress.py before.json after.json
    python tests/compare_stress.py before.json after.json --markdown
    python tests/compare_stress.py --self-test
"""
from __future__ import annotations

import argparse
import json
import math
import pathlib
import sys
from typing import Any


def diff_latency_hist(before: dict[str, Any] | None,
                      after: dict[str, Any] | None) -> dict[str, Any] | None:
    """Compute exact window quantiles from two cumulative /api/stats histograms."""
    if not after or not isinstance(after.get("buckets"), list):
        return None
    bounds = after.get("bounds_us") or []
    a_buckets = after["buckets"]
    b_buckets = (before or {}).get("buckets")
    if isinstance(b_buckets, list) and len(b_buckets) == len(a_buckets):
        buckets = [max(0, int(a) - int(b)) for a, b in zip(a_buckets, b_buckets)]
        a_sum = int(after.get("count", 0)) * int(after.get("mean_us", 0))
        b_sum = int((before or {}).get("count", 0)) * int((before or {}).get("mean_us", 0))
        # Estimate sum from bucket midpoints if cumulative mean*count went backwards.
        delta_sum = max(0, a_sum - b_sum)
    else:
        buckets = [max(0, int(a)) for a in a_buckets]
        delta_sum = int(after.get("count", 0)) * int(after.get("mean_us", 0))

    total = sum(buckets)
    if total == 0:
        return {"count": 0, "mean_us": None, "p50_us": None,
                "p95_us": None, "p99_us": None, "cum_max_us": int(after.get("max_us", 0))}

    def quantile(p: float) -> int:
        rank = max(1, min(total, int(math.ceil(p * total))))
        seen = 0
        for i, bound in enumerate(bounds):
            seen += buckets[i]
            if seen >= rank:
                return int(bound)
        return int(after.get("max_us", 0)) or (int(bounds[-1]) if bounds else 0)

    # When before==None, trust cumulative mean_us directly; otherwise compute from
    # bucket midpoints if delta_sum is inconsistent with the buckets.
    if before is None and after.get("count"):
        mean_us = int(after.get("mean_us", 0))
    else:
        midpoint_sum = 0.0
        prev = 0
        for i, bound in enumerate(bounds):
            midpoint_sum += buckets[i] * ((prev + int(bound)) / 2.0)
            prev = int(bound)
        if len(buckets) > len(bounds):
            overflow_val = max(prev, int(after.get("max_us", prev)))
            midpoint_sum += buckets[len(bounds)] * overflow_val
        mean_us = int(round(delta_sum / total)) if delta_sum > 0 else int(round(midpoint_sum / total))

    return {
        "count": total,
        "mean_us": mean_us,
        "p50_us": quantile(0.50),
        "p95_us": quantile(0.95),
        "p99_us": quantile(0.99),
        "cum_max_us": int(after.get("max_us", 0)),
    }


def diff_counters(before: dict[str, Any] | None,
                  after: dict[str, Any] | None,
                  keys: list[str]) -> dict[str, int | None]:
    """Compute non-negative deltas for monotonic counters."""
    out: dict[str, int | None] = {}
    for k in keys:
        bv = (before or {}).get(k)
        av = (after or {}).get(k)
        if bv is not None and av is not None:
            out[k] = max(0, int(av) - int(bv))
        elif av is not None:
            out[k] = int(av)
        else:
            out[k] = None
    return out


def _linear_slope(xs: list[float], ys: list[float]) -> float | None:
    if len(xs) < 2:
        return None
    n = float(len(xs))
    mx = sum(xs) / n
    my = sum(ys) / n
    denom = sum((x - mx) ** 2 for x in xs)
    if denom <= 1e-9:
        return None
    numer = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    return numer / denom


def summarize_rss_vs_processes(
    points: list[tuple[int, int, int, int | None]],
    max_series: int = 60,
) -> dict[str, Any]:
    """Summarize (working_set_bytes, private_bytes, handles, process_count) samples.

    Returns min/median/max process_count, RSS at min/max process_count, linear
    slope (KB per process) when process_count spans >= 10, and a compact series.
    """
    valid = [(ws, pv, hd, pc) for (ws, pv, hd, pc) in points if pc is not None and pc > 0]
    if not valid:
        return {}
    mb = 1024.0 * 1024.0
    kb = 1024.0
    pcs = sorted(p[3] for p in valid)
    min_pt = min(valid, key=lambda p: p[3])
    max_pt = max(valid, key=lambda p: p[3])

    ws_kb_per_proc: float | None = None
    pv_kb_per_proc: float | None = None
    if max_pt[3] - min_pt[3] >= 10:
        xs = [float(p[3]) for p in valid]
        ws_slope = _linear_slope(xs, [p[0] / kb for p in valid])
        pv_slope = _linear_slope(xs, [p[1] / kb for p in valid])
        if ws_slope is not None:
            ws_kb_per_proc = round(ws_slope, 1)
        if pv_slope is not None:
            pv_kb_per_proc = round(pv_slope, 1)

    step = max(1, (len(valid) + max_series - 1) // max_series)
    series = [
        {"processes": p[3], "working_set_mb": round(p[0] / mb, 1),
         "private_mb": round(p[1] / mb, 1), "handles": p[2]}
        for p in valid[::step]
    ]
    return {
        "samples": len(valid),
        "process_count": {"min": pcs[0], "median": pcs[len(pcs) // 2], "max": pcs[-1]},
        "working_set_mb_at_min_proc": round(min_pt[0] / mb, 1),
        "working_set_mb_at_max_proc": round(max_pt[0] / mb, 1),
        "private_mb_at_min_proc": round(min_pt[1] / mb, 1),
        "private_mb_at_max_proc": round(max_pt[1] / mb, 1),
        "ws_kb_per_process": ws_kb_per_proc,
        "private_kb_per_process": pv_kb_per_proc,
        "series": series,
    }


def _get(d: dict[str, Any], *path: str) -> Any:
    cur: Any = d
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def _fmt_num(v: Any, unit: str = "") -> str:
    if v is None:
        return "-"
    if isinstance(v, float):
        s = f"{v:.1f}" if abs(v) >= 10 else f"{v:.2f}"
    else:
        s = str(v)
    return f"{s}{unit}"


def _fmt_delta(a: Any, b: Any, unit: str = "") -> str:
    if a is None or b is None:
        return "-"
    diff = b - a
    sign = "+" if diff > 0 else ""
    pct = f" ({sign}{(diff / a) * 100.0:.1f}%)" if a != 0 else ""
    if isinstance(diff, float):
        s = f"{sign}{diff:.2f}"
    else:
        s = f"{sign}{diff}"
    return f"{s}{unit}{pct}"


def build_comparison_rows(before: dict[str, Any], after: dict[str, Any]) -> list[tuple[str, str, str, str]]:
    """Build (metric, before, after, delta) rows comparing two stress summaries."""
    specs: list[tuple[str, tuple[str, ...], str]] = [
        ("CONNECT->publish p50",    ("decision_latency_us", "p50_us"), " us"),
        ("CONNECT->publish p95",    ("decision_latency_us", "p95_us"), " us"),
        ("CONNECT->publish p99",    ("decision_latency_us", "p99_us"), " us"),
        ("CONNECT->publish n",      ("decision_latency_us", "count"),  ""),
        ("Recv->publish p99",       ("dispatch_latency_us", "p99_us"), " us"),
        ("SYN park wait p99",       ("park_latency_us", "p99_us"),     " us"),
        ("Missed: late proxied",    ("missed_proxies", "late_rejected_proxied"), ""),
        ("Missed: SYN watchdog",    ("missed_proxies", "released_by_watchdog"),  ""),
        ("Missed: SYN pool full",   ("missed_proxies", "pool_exhausted"),        ""),
        ("Missed: IPv6 watchdog",   ("missed_proxies", "v6_watchdog"),           ""),
        ("Missed: UDP watchdog",    ("missed_proxies", "udp_park_watchdog"),     ""),
        ("Missed: UDP park full",   ("missed_proxies", "udp_park_full"),         ""),
        ("HTTP GET p50",            ("latency_ms", "p50"),             " ms"),
        ("HTTP GET p99",            ("latency_ms", "p99"),             " ms"),
        ("HTTP RPS",                ("rps",),                          "/s"),
        ("Hijack RTT p99",          ("hijack_rtt_ms", "p99"),          " ms"),
        ("Working set peak",        ("proxyclaw", "working_set_mb", "peak"), " MB"),
        ("Private bytes peak",      ("proxyclaw", "private_mb", "peak"),     " MB"),
        ("Handles peak",            ("proxyclaw", "handles", "peak"),        ""),
        ("Process count max",       ("rss_vs_processes", "process_count", "max"), ""),
        ("RSS slope (WS)",          ("rss_vs_processes", "ws_kb_per_process"),    " KB/proc"),
        ("RSS slope (Private)",     ("rss_vs_processes", "private_kb_per_process"), " KB/proc"),
    ]
    rows: list[tuple[str, str, str, str]] = []
    for label, path, unit in specs:
        bv = _get(before, *path)
        av = _get(after, *path)
        if bv is None and av is None:
            continue
        rows.append((label, _fmt_num(bv, unit), _fmt_num(av, unit), _fmt_delta(bv, av, unit)))
    return rows


def format_comparison(before: dict[str, Any], after: dict[str, Any],
                      before_name: str = "before", after_name: str = "after",
                      markdown: bool = False) -> str:
    rows = build_comparison_rows(before, after)
    if markdown:
        lines = [
            f"| Metric | {before_name} | {after_name} | Delta |",
            "| --- | ---: | ---: | ---: |",
        ]
        for m, b, a, d in rows:
            lines.append(f"| {m} | {b} | {a} | {d} |")
        return "\n".join(lines)
    headers = ("Metric", before_name, after_name, "Delta")
    widths = [max(len(h), *(len(r[i]) for r in rows)) for i, h in enumerate(headers)] if rows else [len(h) for h in headers]
    fmt = f"{{:<{widths[0]}}}  {{:>{widths[1]}}}  {{:>{widths[2]}}}  {{:>{widths[3]}}}"
    lines = [fmt.format(*headers), "-" * (sum(widths) + 6)]
    for r in rows:
        lines.append(fmt.format(*r))
    return "\n".join(lines)


def _self_test() -> int:
    bounds = [10, 50, 100, 500, 1000]
    before = {"bounds_us": bounds, "buckets": [10, 0, 0, 0, 0, 5], "count": 15, "mean_us": 500, "max_us": 2000}
    after  = {"bounds_us": bounds, "buckets": [10, 90, 9, 1, 0, 5], "count": 115, "mean_us": 100, "max_us": 2000}
    d = diff_latency_hist(before, after)
    assert d is not None and d["count"] == 100, d
    assert d["p50_us"] == 50 and d["p95_us"] == 100 and d["p99_us"] == 100, d

    c = diff_counters({"a": 2, "b": 5}, {"a": 2, "b": 9}, ["a", "b", "c"])
    assert c == {"a": 0, "b": 4, "c": None}, c

    mb = 1024 * 1024
    kb = 1024
    pts = [
        (40 * mb + 100 * 50 * kb, 30 * mb + 100 * 40 * kb, 300, 100),
        (40 * mb + 200 * 50 * kb, 30 * mb + 200 * 40 * kb, 310, 200),
        (40 * mb + 300 * 50 * kb, 30 * mb + 300 * 40 * kb, 320, 300),
    ]
    rss = summarize_rss_vs_processes(pts)
    assert rss["process_count"] == {"min": 100, "median": 200, "max": 300}, rss
    assert rss["ws_kb_per_process"] == 50.0, rss
    assert rss["private_kb_per_process"] == 40.0, rss

    s1 = {"decision_latency_us": {"p50_us": 50, "p95_us": 150, "p99_us": 500, "count": 200},
          "missed_proxies": {"late_rejected_proxied": 2, "released_by_watchdog": 3},
          "rps": 100.0, "rss_vs_processes": rss}
    s2 = {"decision_latency_us": {"p50_us": 40, "p95_us": 100, "p99_us": 250, "count": 220},
          "missed_proxies": {"late_rejected_proxied": 0, "released_by_watchdog": 1},
          "rps": 125.0, "rss_vs_processes": rss}
    md = format_comparison(s1, s2, "base", "opt", markdown=True)
    assert "CONNECT->publish p99" in md and "-250 us (-50.0%)" in md, md
    print("compare_stress self-test: PASS")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Compare two ProxyClaw stress-summary.json files")
    ap.add_argument("before", nargs="?", type=pathlib.Path)
    ap.add_argument("after", nargs="?", type=pathlib.Path)
    ap.add_argument("--markdown", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return _self_test()
    if not args.before or not args.after:
        ap.error("provide BEFORE and AFTER summary JSON files (or --self-test)")
    b = json.loads(args.before.read_text(encoding="utf-8"))
    a = json.loads(args.after.read_text(encoding="utf-8"))
    print(format_comparison(b, a, args.before.stem, args.after.stem, markdown=args.markdown))
    return 0


if __name__ == "__main__":
    sys.exit(main())
