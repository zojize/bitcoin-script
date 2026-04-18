"""Canonical benchmark dataset: schema, serialization, and loading."""

from __future__ import annotations

from dataclasses import dataclass, field, fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import msgpack


@dataclass
class BenchmarkInput:
    """A single script verification input for benchmarking."""

    # Provenance
    block_height: int
    tx_index: int
    input_index: int
    txid: bytes
    era: str
    category: str

    # Script data
    script_pubkey: bytes
    script_sig: bytes
    amount: int
    flags: int

    # Witness (empty list for legacy)
    witness: list[bytes]

    # Full transaction (needed by libbitcoinconsensus)
    tx_serialized: bytes
    n_in: int

    # K Framework specific
    sighash_blob: bytes
    tx_version: int
    n_locktime: int
    n_sequence: int

    # All prevouts of the tx (needed by BIP-341 taproot sighash and
    # libbitcoinconsensus's verify_script_with_spent_outputs entry point).
    # None if not all inputs' UTXOs could be resolved at extraction time.
    all_prevout_scriptpubkeys: list[bytes] | None = None
    all_prevout_amounts: list[int] | None = None

    def to_dict(self) -> dict:
        """Serialize to a msgpack-friendly dict."""
        return {f.name: getattr(self, f.name) for f in fields(self)}

    @classmethod
    def from_dict(cls, d: dict) -> BenchmarkInput:
        """Deserialize from a msgpack dict."""
        d = dict(d)
        if "witness" in d and d["witness"] is not None:
            d["witness"] = [bytes(w) for w in d["witness"]]
        if d.get("all_prevout_scriptpubkeys") is not None:
            d["all_prevout_scriptpubkeys"] = [
                bytes(b) for b in d["all_prevout_scriptpubkeys"]
            ]
        for f in fields(cls):
            if f.type == "bytes" and f.name in d and d[f.name] is not None:
                d[f.name] = bytes(d[f.name])
        return cls(**d)


@dataclass
class Dataset:
    """A complete benchmark dataset with header metadata."""

    inputs: list[BenchmarkInput]
    header: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.header:
            block_heights = {inp.block_height for inp in self.inputs}
            self.header = {
                "version": 1,
                "created": datetime.now(timezone.utc).isoformat(),
                "input_count": len(self.inputs),
                "block_count": len(block_heights),
            }


def save_dataset(dataset: Dataset, path: Path) -> None:
    """Serialize a dataset to a MessagePack file.

    Deduplicates ``tx_serialized`` and the per-tx prevout arrays by storing
    each unique tx's data once in a separate ``txdata`` table keyed by
    ``txid``, and stripping the duplicated fields from each input.
    """
    # Build txid → {tx, prevout_spks, prevout_amounts} mapping (dedup).
    txdata: dict[bytes, dict] = {}
    for inp in dataset.inputs:
        if inp.txid not in txdata:
            txdata[inp.txid] = {
                "tx": inp.tx_serialized,
                "prevout_spks": inp.all_prevout_scriptpubkeys,
                "prevout_amounts": inp.all_prevout_amounts,
            }

    inputs_out = []
    for inp in dataset.inputs:
        d = inp.to_dict()
        d["tx_serialized"] = b""
        d["all_prevout_scriptpubkeys"] = None
        d["all_prevout_amounts"] = None
        inputs_out.append(d)

    data: dict[str, Any] = {
        "header": {**dataset.header, "version": 3},
        "txdata": txdata,
        "inputs": inputs_out,
    }
    with path.open("wb") as f:
        msgpack.pack(data, f, use_bin_type=True)


def load_dataset(path: Path) -> Dataset:
    """Deserialize a dataset from a MessagePack file.

    Supports v1 (inline tx_serialized), v2 (deduplicated tx_serialized),
    and v3 (also deduplicates per-tx prevout arrays for taproot).
    """
    with path.open("rb") as f:
        raw: Any = msgpack.unpack(f, raw=False)

    version = raw.get("header", {}).get("version", 1)
    txdata_raw = raw.get("txdata", {})

    # Normalize txdata shape across versions:
    #   v2: txid -> raw_tx_bytes
    #   v3: txid -> {tx, prevout_spks, prevout_amounts}
    tx_bytes: dict[bytes, bytes] = {}
    tx_prevouts: dict[bytes, tuple[list[bytes], list[int]] | None] = {}
    for k, v in txdata_raw.items():
        key = bytes(k)
        if version >= 3 and isinstance(v, dict):
            tx_bytes[key] = bytes(v.get("tx", b""))
            spks = v.get("prevout_spks")
            amounts = v.get("prevout_amounts")
            if spks is not None and amounts is not None:
                tx_prevouts[key] = ([bytes(s) for s in spks], list(amounts))
            else:
                tx_prevouts[key] = None
        else:
            tx_bytes[key] = bytes(v)
            tx_prevouts[key] = None

    inputs: list[BenchmarkInput] = []
    for d in raw["inputs"]:
        inp = BenchmarkInput.from_dict(d)
        if not inp.tx_serialized and inp.txid in tx_bytes:
            inp.tx_serialized = tx_bytes[inp.txid]
        if inp.all_prevout_scriptpubkeys is None:
            po = tx_prevouts.get(inp.txid)
            if po is not None:
                inp.all_prevout_scriptpubkeys, inp.all_prevout_amounts = po
        inputs.append(inp)

    return Dataset(inputs=inputs, header=raw["header"])


def append_inputs(path: Path, inputs: list[BenchmarkInput]) -> None:
    """Append inputs to a partial dataset file (one msgpack object per input)."""
    with path.open("ab") as f:
        for inp in inputs:
            msgpack.pack(inp.to_dict(), f, use_bin_type=True)


def load_partial_inputs(path: Path) -> list[BenchmarkInput]:
    """Load inputs from a partial dataset file written by append_inputs()."""
    inputs: list[BenchmarkInput] = []
    if not path.exists() or path.stat().st_size == 0:
        return inputs
    with path.open("rb") as f:
        unpacker = msgpack.Unpacker(f, raw=False)
        for obj in unpacker:
            inputs.append(BenchmarkInput.from_dict(obj))
    return inputs
