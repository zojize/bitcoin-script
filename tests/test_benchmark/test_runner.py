"""Tests for the benchmark runner."""

from __future__ import annotations

from pathlib import Path

from bitcoin_script.benchmark.dataset import BenchmarkInput
from bitcoin_script.benchmark.runner import (
    BenchmarkResult,
    InputResult,
    _verify_with_k,
    load_results,
    save_results,
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


class TestKRunnerPath:
    def test_verify_with_k_uses_verify_script(self) -> None:
        class FakeK:
            def __init__(self) -> None:
                self.calls: list[dict[str, object]] = []

            def verify_script(self, **kwargs: object) -> object:
                self.calls.append(kwargs)
                return object()

            def success(self, result: object) -> bool:
                return True

            def error(self, result: object) -> str | None:
                return None

            def pattern(self, **kwargs: object) -> object:
                raise AssertionError("benchmark runner should use verify_script")

            def run_text(self, kore_text: str) -> object:
                raise AssertionError("benchmark runner should use verify_script")

        inp = BenchmarkInput(
            block_height=170,
            tx_index=1,
            input_index=0,
            txid=b"\x11" * 32,
            era="pre-p2sh",
            category="continuous",
            script_pubkey=b"\x51",
            script_sig=b"",
            amount=1_000,
            flags=0,
            witness=[],
            tx_serialized=b"tx",
            n_in=0,
            sighash_blob=b"",
            tx_version=1,
            n_locktime=0,
            n_sequence=0xFFFFFFFF,
            all_prevout_scriptpubkeys=[b"\x51", b"\x00\x51"],
            all_prevout_amounts=[1_000, 2_000],
        )

        fake_k = FakeK()
        elapsed_ns, success, error = _verify_with_k(fake_k, inp, iterations=2)

        expected_prevouts = (
            (1_000).to_bytes(8, "little")
            + b"\x01\x51"
            + (2_000).to_bytes(8, "little")
            + b"\x02\x00\x51"
        )
        assert elapsed_ns >= 0
        assert success is True
        assert error is None
        assert len(fake_k.calls) == 2
        assert fake_k.calls[0]["prevouts"] == expected_prevouts
        assert fake_k.calls[0]["tx"] == b"tx"


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
