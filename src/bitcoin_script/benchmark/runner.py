"""Benchmark runner: time K Framework and libbitcoinconsensus on dataset inputs."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .dataset import BenchmarkInput, Dataset

log = logging.getLogger(__name__)

WARMUP_COUNT = 5


@dataclass
class InputResult:
    """Timing result for a single input."""

    block_height: int
    tx_index: int
    input_index: int
    era: str
    category: str

    k_elapsed_ns: int | None
    k_success: bool | None
    k_error: str | None

    core_elapsed_ns: int | None
    core_success: bool | None
    core_error: str | None

    @property
    def ratio(self) -> float | None:
        """K time / Core time ratio. None if Core time is zero or either is missing."""
        if (
            self.k_elapsed_ns is None
            or self.core_elapsed_ns is None
            or self.core_elapsed_ns == 0
        ):
            return None
        return self.k_elapsed_ns / self.core_elapsed_ns


@dataclass
class BenchmarkResult:
    """Complete benchmark results."""

    input_results: list[InputResult]
    metadata: dict = field(default_factory=dict)


def _verify_with_k(k: object, inp: BenchmarkInput) -> tuple[int, bool, str | None]:
    """Run K Framework verification, returning (elapsed_ns, success, error)."""
    from bitcoin_script.script_utils import encode_witness_blob  # type: ignore[import-not-found]

    witness_blob = encode_witness_blob(inp.witness) if inp.witness else b""
    t0 = time.perf_counter_ns()
    result = k.verify_script(  # type: ignore[union-attr]
        script_sig=inp.script_sig,
        script_pubkey=inp.script_pubkey,
        sighash=inp.sighash_blob,
        witness=witness_blob,
        flags=inp.flags,
        tx_version=inp.tx_version,
        n_locktime=inp.n_locktime,
        n_sequence=inp.n_sequence,
    )
    elapsed = time.perf_counter_ns() - t0
    success = k.success(result)  # type: ignore[union-attr]
    error = k.error(result) if not success else None  # type: ignore[union-attr]
    return (elapsed, success, error)


def _verify_with_core(
    inp: BenchmarkInput, iterations: int
) -> tuple[int, bool, str | None]:
    """Run libbitcoinconsensus verification, returning (median_elapsed_ns, success, error).

    Runs multiple iterations and returns the median timing for stable results.
    """
    from bitcointx.core.bitcoinconsensus import (  # type: ignore[import-not-found]
        ConsensusVerifyScript,
        BITCOINCONSENSUS_ACCEPTED_FLAGS,
    )

    flags = inp.flags & BITCOINCONSENSUS_ACCEPTED_FLAGS  # type: ignore[operator]

    timings: list[int] = []
    success = True
    error: str | None = None

    for _ in range(iterations):
        t0 = time.perf_counter_ns()
        try:
            ConsensusVerifyScript(
                inp.script_pubkey,  # type: ignore[arg-type]
                inp.tx_serialized,  # type: ignore[arg-type]
                inp.n_in,  # type: ignore[arg-type]
                flags,  # type: ignore[arg-type]
                inp.amount,  # type: ignore[arg-type]
            )
        except Exception as e:
            success = False
            error = str(e)
        elapsed = time.perf_counter_ns() - t0
        timings.append(elapsed)

    timings.sort()
    median_ns = timings[len(timings) // 2]
    return (median_ns, success, error)


def run_benchmark(
    dataset: Dataset,
    *,
    run_k: bool = True,
    run_core: bool = True,
    core_iterations: int = 100,
    on_input: object | None = None,
) -> BenchmarkResult:
    """Run the benchmark on all inputs in the dataset."""
    k = None
    if run_k:
        from bitcoin_script.k_semantics import KBitcoinScript  # type: ignore[import-not-found]

        k = KBitcoinScript()

    results: list[InputResult] = []
    total = len(dataset.inputs)

    for i, inp in enumerate(dataset.inputs):
        is_warmup = i < WARMUP_COUNT

        k_ns: int | None = None
        k_success: bool | None = None
        k_error: str | None = None
        if run_k and k is not None:
            k_ns, k_success, k_error = _verify_with_k(k, inp)
            if is_warmup:
                k_ns = None

        core_ns: int | None = None
        core_success: bool | None = None
        core_error: str | None = None
        if run_core:
            core_ns, core_success, core_error = _verify_with_core(inp, core_iterations)
            if is_warmup:
                core_ns = None

        if not is_warmup:
            results.append(
                InputResult(
                    block_height=inp.block_height,
                    tx_index=inp.tx_index,
                    input_index=inp.input_index,
                    era=inp.era,
                    category=inp.category,
                    k_elapsed_ns=k_ns,
                    k_success=k_success,
                    k_error=k_error,
                    core_elapsed_ns=core_ns,
                    core_success=core_success,
                    core_error=core_error,
                )
            )

        if on_input is not None:
            on_input(i + 1, total)  # type: ignore[operator]

    return BenchmarkResult(input_results=results)


def save_results(results: BenchmarkResult, path: Path) -> None:
    """Save benchmark results to a JSON file."""
    data = {
        "metadata": results.metadata,
        "input_results": [asdict(r) for r in results.input_results],
    }
    with path.open("w") as f:
        json.dump(data, f, indent=2, default=str)


def load_results(path: Path) -> BenchmarkResult:
    """Load benchmark results from a JSON file."""
    with path.open() as f:
        data = json.load(f)
    input_results = [InputResult(**r) for r in data["input_results"]]
    return BenchmarkResult(
        input_results=input_results,
        metadata=data.get("metadata", {}),
    )
