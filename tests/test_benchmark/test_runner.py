"""Tests for the benchmark runner."""

from __future__ import annotations

from pathlib import Path

from bitcoin_script.benchmark.runner import (
    BenchmarkResult,
    InputResult,
    save_results,
    load_results,
)


def _make_input_result(
    *,
    k_ns: int = 50_000_000,
    core_ns: int = 65_000,
    k_success: bool = True,
    core_success: bool = True,
) -> InputResult:
    return InputResult(
        block_height=170,
        tx_index=1,
        input_index=0,
        era="pre-p2sh",
        category="continuous",
        k_elapsed_ns=k_ns,
        k_success=k_success,
        k_error=None,
        core_elapsed_ns=core_ns,
        core_success=core_success,
        core_error=None,
    )


class TestInputResult:
    def test_ratio(self) -> None:
        r = _make_input_result(k_ns=100_000, core_ns=1_000)
        assert r.ratio == 100.0

    def test_ratio_zero_core(self) -> None:
        r = _make_input_result(k_ns=100_000, core_ns=0)
        assert r.ratio is None


class TestResultsSerialization:
    def test_save_and_load(self, tmp_path: object) -> None:
        p = Path(str(tmp_path)) / "results.json"
        results = BenchmarkResult(
            input_results=[_make_input_result(), _make_input_result(k_ns=60_000_000)],
        )
        save_results(results, p)
        loaded = load_results(p)
        assert len(loaded.input_results) == 2
        assert loaded.input_results[0].k_elapsed_ns == 50_000_000
        assert loaded.input_results[1].k_elapsed_ns == 60_000_000
