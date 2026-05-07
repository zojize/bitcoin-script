"""Aggregate benchmark results and format reports."""

from __future__ import annotations

import csv
import io
import json
import statistics
from collections import defaultdict

from .runner import BenchmarkResult


def _percentile(values: list[int], pct: float) -> float:
    """Compute a percentile using linear interpolation (closest to numpy default)."""
    if not values:
        return 0.0
    s = sorted(values)
    if len(s) == 1:
        return float(s[0])
    k = (len(s) - 1) * (pct / 100)
    f = int(k)
    c = min(f + 1, len(s) - 1)
    if f == c:
        return float(s[f])
    return s[f] + (s[c] - s[f]) * (k - f)


def aggregate_overall(results: BenchmarkResult) -> dict:
    """Compute overall aggregate statistics."""
    k_times = [
        r.k_elapsed_ns for r in results.input_results if r.k_elapsed_ns is not None
    ]
    core_times = [
        r.core_elapsed_ns
        for r in results.input_results
        if r.core_elapsed_ns is not None
    ]

    k_total = sum(k_times) if k_times else 0
    core_total = sum(core_times) if core_times else 0
    ratio = k_total / core_total if core_total > 0 else None

    return {
        "total_inputs": len(results.input_results),
        "k_total_ns": k_total,
        "k_inputs": len(k_times),
        "k_mean_ns": statistics.mean(k_times) if k_times else None,
        "k_median_ns": statistics.median(k_times) if k_times else None,
        "k_inputs_per_sec": len(k_times) / (k_total / 1e9) if k_total > 0 else None,
        "core_total_ns": core_total,
        "core_inputs": len(core_times),
        "core_mean_ns": statistics.mean(core_times) if core_times else None,
        "core_median_ns": statistics.median(core_times) if core_times else None,
        "core_inputs_per_sec": (
            len(core_times) / (core_total / 1e9) if core_total > 0 else None
        ),
        "ratio": ratio,
    }


def _aggregate_group(results: BenchmarkResult, key_fn: object) -> dict[str, dict]:
    """Group results by a key function and aggregate each group."""
    groups: dict[str, list] = defaultdict(list)
    for r in results.input_results:
        groups[key_fn(r)].append(r)  # type: ignore[operator]

    out: dict[str, dict] = {}
    for key, items in sorted(groups.items()):
        k_times = [r.k_elapsed_ns for r in items if r.k_elapsed_ns is not None]
        core_times = [r.core_elapsed_ns for r in items if r.core_elapsed_ns is not None]
        k_total = sum(k_times) if k_times else 0
        core_total = sum(core_times) if core_times else 0

        out[key] = {
            "count": len(items),
            "k_total_ns": k_total,
            "k_median_ns": statistics.median(k_times) if k_times else None,
            "k_p95_ns": _percentile(k_times, 95) if k_times else None,
            "core_total_ns": core_total,
            "core_median_ns": statistics.median(core_times) if core_times else None,
            "ratio": k_total / core_total if core_total > 0 else None,
        }
    return out


def aggregate_by_era(results: BenchmarkResult) -> dict[str, dict]:
    """Aggregate results grouped by consensus era."""
    return _aggregate_group(results, lambda r: r.era)


def aggregate_by_category(results: BenchmarkResult) -> dict[str, dict]:
    """Aggregate results grouped by benchmark category."""
    return _aggregate_group(results, lambda r: r.category)


def _ns_to_human(ns: float | int | None) -> str:
    """Format nanoseconds as human-readable string."""
    if ns is None:
        return "N/A"
    if ns < 1_000:
        return f"{ns:.0f}ns"
    if ns < 1_000_000:
        return f"{ns / 1_000:.1f}us"
    if ns < 1_000_000_000:
        return f"{ns / 1_000_000:.1f}ms"
    return f"{ns / 1_000_000_000:.2f}s"


def format_table(results: BenchmarkResult) -> str:
    """Format results as a human-readable table string."""
    lines: list[str] = []
    lines.append("Bitcoin Script Verification Benchmark")
    lines.append("=" * 50)
    lines.append(f"Inputs: {len(results.input_results)}")
    lines.append("")

    # Noop baseline — isolates fixed call overhead from verification cost.
    noop = results.metadata.get("noop_baseline", {})
    k_noop_ns: int | None = noop.get("k_median_ns")
    core_noop_ns: int | None = noop.get("core_median_ns")
    if k_noop_ns is not None or core_noop_ns is not None:
        lines.append("Noop baseline (OP_TRUE — pure call overhead, not verification)")
        if k_noop_ns is not None:
            lines.append(f"  K Framework:         {_ns_to_human(k_noop_ns)}")
        if core_noop_ns is not None:
            lines.append(f"  libbitcoinconsensus: {_ns_to_human(core_noop_ns)}")
        lines.append("")

    overall = aggregate_overall(results)
    lines.append(
        "Overall throughput  (med = median, p95 = 95th-percentile latency, net = med - noop)"
    )
    k_total_s = overall["k_total_ns"] / 1e9 if overall["k_total_ns"] else 0
    core_total_s = overall["core_total_ns"] / 1e9 if overall["core_total_ns"] else 0
    if overall["k_inputs"]:
        k_med = overall["k_median_ns"]
        k_p95 = _percentile(
            [
                r.k_elapsed_ns
                for r in results.input_results
                if r.k_elapsed_ns is not None
            ],
            95,
        )
        k_net = (
            (k_med - k_noop_ns)
            if (k_med is not None and k_noop_ns is not None)
            else None
        )
        lines.append(
            f"  K Framework:         {overall['k_inputs']:,} inputs in {k_total_s:.1f}s"
            f"  ({overall['k_inputs_per_sec']:.1f} inp/s)"
            f"  med={_ns_to_human(k_med)}"
            f"  p95={_ns_to_human(k_p95)}"
            + (f"  net={_ns_to_human(k_net)}" if k_net is not None else "")
        )
    if overall["core_inputs"]:
        core_med = overall["core_median_ns"]
        core_p95 = _percentile(
            [
                r.core_elapsed_ns
                for r in results.input_results
                if r.core_elapsed_ns is not None
            ],
            95,
        )
        core_net = (
            (core_med - core_noop_ns)
            if (core_med is not None and core_noop_ns is not None)
            else None
        )
        lines.append(
            f"  libbitcoinconsensus: {overall['core_inputs']:,} inputs in {core_total_s:.1f}s"
            f"  ({overall['core_inputs_per_sec']:.0f} inp/s)"
            f"  med={_ns_to_human(core_med)}"
            f"  p95={_ns_to_human(core_p95)}"
            + (f"  net={_ns_to_human(core_net)}" if core_net is not None else "")
        )
    if overall["ratio"] is not None:
        lines.append(f"  Wall-time ratio K/Core: {overall['ratio']:.1f}x")
    lines.append("")

    by_era = aggregate_by_era(results)
    if by_era:
        lines.append("By Era  (med = median, p95 = 95th-percentile)")
        lines.append(
            f"  {'Era':<12} | {'Inputs':>7} | {'K med':>9} | {'K p95':>9} | {'Core med':>9} | {'Ratio':>6}"
        )
        lines.append(
            f"  {'-' * 12}-+-{'-' * 7}-+-{'-' * 9}-+-{'-' * 9}-+-{'-' * 9}-+-{'-' * 6}"
        )
        for era, stats in by_era.items():
            ratio_str = f"{stats['ratio']:.1f}x" if stats["ratio"] else "N/A"
            lines.append(
                f"  {era:<12} | {stats['count']:>7,} | "
                f"{_ns_to_human(stats['k_median_ns']):>9} | "
                f"{_ns_to_human(stats['k_p95_ns']):>9} | "
                f"{_ns_to_human(stats['core_median_ns']):>9} | "
                f"{ratio_str:>6}"
            )
        lines.append("")

    by_cat = aggregate_by_category(results)
    if by_cat:
        lines.append("By Category")
        lines.append(
            f"  {'Category':<16} | {'Inputs':>7} | {'K (total)':>10} | {'Core (total)':>12} | {'Ratio':>7}"
        )
        lines.append(f"  {'-' * 16}-+-{'-' * 7}-+-{'-' * 10}-+-{'-' * 12}-+-{'-' * 7}")
        for cat, stats in by_cat.items():
            k_s = stats["k_total_ns"] / 1e9 if stats["k_total_ns"] else 0
            core_s = stats["core_total_ns"] / 1e9 if stats["core_total_ns"] else 0
            ratio_str = f"{stats['ratio']:.1f}x" if stats["ratio"] else "N/A"
            lines.append(
                f"  {cat:<16} | {stats['count']:>7,} | "
                f"{k_s:>9.1f}s | "
                f"{core_s:>11.1f}s | "
                f"{ratio_str:>7}"
            )
        lines.append("")

    return "\n".join(lines)


def format_json(results: BenchmarkResult) -> str:
    """Format results as JSON."""
    data = {
        "overall": aggregate_overall(results),
        "noop_baseline": results.metadata.get("noop_baseline"),
        "by_era": aggregate_by_era(results),
        "by_category": aggregate_by_category(results),
        "input_results": [
            {
                "block_height": r.block_height,
                "tx_index": r.tx_index,
                "input_index": r.input_index,
                "era": r.era,
                "category": r.category,
                "k_elapsed_ns": r.k_elapsed_ns,
                "core_elapsed_ns": r.core_elapsed_ns,
                "k_success": r.k_success,
                "core_success": r.core_success,
                "ratio": r.ratio,
            }
            for r in results.input_results
        ],
    }
    return json.dumps(data, indent=2, default=str)


def format_csv(results: BenchmarkResult) -> str:
    """Format per-input results as CSV."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "block_height",
            "tx_index",
            "input_index",
            "era",
            "category",
            "k_elapsed_ns",
            "core_elapsed_ns",
            "k_success",
            "core_success",
            "ratio",
        ]
    )
    for r in results.input_results:
        writer.writerow(
            [
                r.block_height,
                r.tx_index,
                r.input_index,
                r.era,
                r.category,
                r.k_elapsed_ns,
                r.core_elapsed_ns,
                r.k_success,
                r.core_success,
                r.ratio,
            ]
        )
    return output.getvalue()
