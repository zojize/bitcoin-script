"""Tests for the benchmark report generator."""

from __future__ import annotations

from bitcoin_script.benchmark.runner import BenchmarkResult, InputResult
from bitcoin_script.benchmark.report import (
    format_table,
    format_json,
    format_csv,
    aggregate_by_era,
    aggregate_by_category,
    aggregate_overall,
)


def _make_results() -> BenchmarkResult:
    """Create a small result set for testing."""
    return BenchmarkResult(
        input_results=[
            InputResult(
                block_height=100,
                tx_index=1,
                input_index=0,
                era="pre-p2sh",
                category="continuous",
                k_elapsed_ns=50_000_000,
                k_success=True,
                k_error=None,
                core_elapsed_ns=65_000,
                core_success=True,
                core_error=None,
            ),
            InputResult(
                block_height=200,
                tx_index=1,
                input_index=0,
                era="pre-p2sh",
                category="continuous",
                k_elapsed_ns=60_000_000,
                k_success=True,
                k_error=None,
                core_elapsed_ns=70_000,
                core_success=True,
                core_error=None,
            ),
            InputResult(
                block_height=500_000,
                tx_index=1,
                input_index=0,
                era="segwit",
                category="representative",
                k_elapsed_ns=55_000_000,
                k_success=True,
                k_error=None,
                core_elapsed_ns=85_000,
                core_success=True,
                core_error=None,
            ),
        ]
    )


class TestAggregateOverall:
    def test_input_count(self) -> None:
        stats = aggregate_overall(_make_results())
        assert stats["total_inputs"] == 3

    def test_k_total_ns(self) -> None:
        stats = aggregate_overall(_make_results())
        assert stats["k_total_ns"] == 50_000_000 + 60_000_000 + 55_000_000

    def test_core_total_ns(self) -> None:
        stats = aggregate_overall(_make_results())
        assert stats["core_total_ns"] == 65_000 + 70_000 + 85_000


class TestAggregateByEra:
    def test_era_grouping(self) -> None:
        by_era = aggregate_by_era(_make_results())
        assert "pre-p2sh" in by_era
        assert "segwit" in by_era
        assert by_era["pre-p2sh"]["count"] == 2
        assert by_era["segwit"]["count"] == 1


class TestAggregateByCategory:
    def test_category_grouping(self) -> None:
        by_cat = aggregate_by_category(_make_results())
        assert "continuous" in by_cat
        assert "representative" in by_cat
        assert by_cat["continuous"]["count"] == 2


class TestFormatTable:
    def test_contains_header(self) -> None:
        table = format_table(_make_results())
        assert "Bitcoin Script Verification Benchmark" in table

    def test_contains_overall(self) -> None:
        table = format_table(_make_results())
        assert "Overall" in table


class TestFormatJson:
    def test_is_valid_json(self) -> None:
        import json

        output = format_json(_make_results())
        parsed = json.loads(output)
        assert "overall" in parsed
        assert "by_era" in parsed


class TestFormatCsv:
    def test_has_header_row(self) -> None:
        output = format_csv(_make_results())
        lines = output.strip().split("\n")
        assert len(lines) >= 2
        assert "block_height" in lines[0]
