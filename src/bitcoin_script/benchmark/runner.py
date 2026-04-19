"""Benchmark runner: time K Framework and libbitcoinconsensus on dataset inputs."""

from __future__ import annotations

import ctypes
import json
import logging
import statistics
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


def _cs(n: int) -> bytes:
    """Bitcoin compactSize encoding (1/3/5/9 bytes)."""
    if n <= 252:
        return n.to_bytes(1, "little")
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def _verify_with_k(
    k: object, inp: BenchmarkInput, iterations: int
) -> tuple[int, bool, str | None]:
    """Run K Framework verification, returning (median_elapsed_ns, success, error)."""
    from bitcoin_script.script_utils import encode_witness_blob  # type: ignore[import-not-found]

    witness_blob = encode_witness_blob(inp.witness) if inp.witness else b""
    # Serialize per-tx prevouts (<8 LE amount><cs len><spk>, concatenated)
    # for BIP-341/BIP-342 K-side sighash. Empty when not all prevouts were
    # resolved at extraction time; the K dispatcher falls back to the blob.
    prevouts_blob = b""
    if (
        inp.all_prevout_scriptpubkeys is not None
        and inp.all_prevout_amounts is not None
    ):
        for spk, amt in zip(
            inp.all_prevout_scriptpubkeys, inp.all_prevout_amounts, strict=True
        ):
            prevouts_blob += amt.to_bytes(8, "little")
            prevouts_blob += _cs(len(spk)) + spk

    timings: list[int] = []
    success = True
    error: str | None = None

    for _ in range(iterations):
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
            tx=inp.tx_serialized,
            input_index=inp.input_index,
            amount=inp.amount,
            prevouts=prevouts_blob,
        )
        elapsed = time.perf_counter_ns() - t0
        timings.append(elapsed)

        if not k.success(result):  # type: ignore[union-attr]
            success = False
            error = k.error(result)  # type: ignore[union-attr]

    median_ns = int(statistics.median(timings))
    return (median_ns, success, error)


_FLAG_TAPROOT = 131072


class _UTXOStruct(ctypes.Structure):
    """Mirror of Bitcoin Core's libbitcoinconsensus UTXO struct.

    Layout must match ``struct UTXO { const unsigned char *scriptPubKey;
    unsigned int scriptPubKeyLen; int64_t value; }`` from
    src/script/bitcoinconsensus.h.
    """

    _fields_ = [
        ("scriptPubKey", ctypes.POINTER(ctypes.c_ubyte)),
        ("scriptPubKeyLen", ctypes.c_uint),
        ("value", ctypes.c_int64),
    ]


_consensus_lib_handle: object | None = None


def _get_consensus_handle() -> object:
    """Load libbitcoinconsensus, caching the handle.

    Falls back to direct ctypes loading if python-bitcointx rejects the
    library version (v27.2 returns API version 2, older python-bitcointx
    expects 1 — the ABI is compatible).
    """
    global _consensus_lib_handle  # noqa: PLW0603
    if _consensus_lib_handle is None:
        import os

        from bitcointx.core.bitcoinconsensus import (  # type: ignore[import-not-found]
            _add_function_definitions,
            load_bitcoinconsensus_library,
        )

        path = os.environ.get("BITCOINCONSENSUS_LIB_PATH")
        try:
            _consensus_lib_handle = load_bitcoinconsensus_library(path=path)
        except ImportError:
            if path is None:
                raise
            handle = ctypes.cdll.LoadLibrary(path)
            _add_function_definitions(handle)
            _consensus_lib_handle = handle

        # Declare the spent_outputs entry point; python-bitcointx only knows
        # about verify_script_with_amount, so argtypes aren't set for it.
        lib = _consensus_lib_handle
        assert isinstance(lib, ctypes.CDLL)
        if hasattr(lib, "bitcoinconsensus_verify_script_with_spent_outputs"):
            fn = lib.bitcoinconsensus_verify_script_with_spent_outputs
            fn.restype = ctypes.c_int
            fn.argtypes = [
                ctypes.c_char_p,  # scriptPubKey
                ctypes.c_uint,  # scriptPubKeyLen
                ctypes.c_int64,  # amount
                ctypes.c_char_p,  # txTo
                ctypes.c_uint,  # txToLen
                ctypes.POINTER(_UTXOStruct),  # spentOutputs
                ctypes.c_uint,  # spentOutputsLen
                ctypes.c_uint,  # nIn
                ctypes.c_uint,  # flags
                ctypes.POINTER(ctypes.c_uint),  # err
            ]
    return _consensus_lib_handle


# Mapping from our K flag bits to the C API's bit positions.
# Only flags accepted by libbitcoinconsensus; others are enforced internally.
_K_TO_CONSENSUS_BITS: list[tuple[int, int]] = [
    (1, 1 << 0),  # FLAG_P2SH -> bit 0
    (4, 1 << 2),  # FLAG_DERSIG -> bit 2
    (16, 1 << 4),  # FLAG_NULLDUMMY -> bit 4
    (512, 1 << 9),  # FLAG_CHECKLOCKTIMEVERIFY -> bit 9
    (1024, 1 << 10),  # FLAG_CHECKSEQUENCEVERIFY -> bit 10
    (2048, 1 << 11),  # FLAG_WITNESS -> bit 11
    (131072, 1 << 17),  # FLAG_TAPROOT -> bit 17
]


def _k_flags_to_consensus_int(k_flags: int) -> int:
    """Convert K Framework flag bitmask to libbitcoinconsensus int bitmask."""
    result = 0
    for k_bit, c_bit in _K_TO_CONSENSUS_BITS:
        if k_flags & k_bit:
            result |= c_bit
    return result


def _build_utxo_array(
    spks: list[bytes], amounts: list[int]
) -> tuple[ctypes.Array, list]:
    """Build a C array of UTXO structs for verify_script_with_spent_outputs.

    Returns the array plus the underlying byte buffers so callers can keep
    them alive for the duration of the C call (ctypes pointers are not GC
    roots for the target memory).
    """
    n = len(spks)
    arr = (_UTXOStruct * n)()
    buffers: list = []
    for i, (spk, amt) in enumerate(zip(spks, amounts, strict=True)):
        buf = (ctypes.c_ubyte * len(spk)).from_buffer_copy(spk)
        buffers.append(buf)
        arr[i].scriptPubKey = ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte))
        arr[i].scriptPubKeyLen = len(spk)
        arr[i].value = amt
    return arr, buffers


def _verify_with_core(
    inp: BenchmarkInput, iterations: int
) -> tuple[int, bool, str | None]:
    """Run libbitcoinconsensus verification via direct ctypes call.

    For pre-taproot inputs, uses ``verify_script_with_amount``. For taproot
    inputs (FLAG_TAPROOT set and all prevouts available), uses
    ``verify_script_with_spent_outputs``, required for BIP-341 sighash.
    """
    handle = _get_consensus_handle()
    assert isinstance(handle, ctypes.CDLL)

    script_pubkey = inp.script_pubkey
    tx_data = inp.tx_serialized
    flags = _k_flags_to_consensus_int(inp.flags)
    err = ctypes.c_uint(0)

    # Use spent_outputs path when the caller requests taproot validation and
    # we have the per-tx prevout array to feed it.
    use_spent_outputs = (
        (inp.flags & _FLAG_TAPROOT)
        and inp.all_prevout_scriptpubkeys is not None
        and inp.all_prevout_amounts is not None
    )

    utxo_arr = None
    _buffers: list = []
    n_utxos = 0
    if use_spent_outputs:
        utxo_arr, _buffers = _build_utxo_array(
            inp.all_prevout_scriptpubkeys,  # type: ignore[arg-type]
            inp.all_prevout_amounts,  # type: ignore[arg-type]
        )
        n_utxos = len(inp.all_prevout_scriptpubkeys)  # type: ignore[arg-type]

    timings: list[int] = []
    success = True
    error: str | None = None

    for _ in range(iterations):
        err.value = 0
        if use_spent_outputs:
            t0 = time.perf_counter_ns()
            ret = handle.bitcoinconsensus_verify_script_with_spent_outputs(
                script_pubkey,
                len(script_pubkey),
                inp.amount,
                tx_data,
                len(tx_data),
                utxo_arr,
                n_utxos,
                inp.n_in,
                flags,
                ctypes.byref(err),
            )
            elapsed = time.perf_counter_ns() - t0
        else:
            t0 = time.perf_counter_ns()
            ret = handle.bitcoinconsensus_verify_script_with_amount(
                script_pubkey,
                len(script_pubkey),
                inp.amount,
                tx_data,
                len(tx_data),
                inp.n_in,
                flags,
                ctypes.byref(err),
            )
            elapsed = time.perf_counter_ns() - t0
        timings.append(elapsed)

        if ret != 1:
            success = False
            error = f"consensus error code {err.value}"

    median_ns = int(statistics.median(timings))
    return (median_ns, success, error)


def run_benchmark(
    dataset: Dataset,
    *,
    run_k: bool = True,
    run_core: bool = True,
    k_iterations: int = 1,
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
            k_ns, k_success, k_error = _verify_with_k(k, inp, k_iterations)
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
