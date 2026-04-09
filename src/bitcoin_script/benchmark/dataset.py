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

    def to_dict(self) -> dict:
        """Serialize to a msgpack-friendly dict."""
        return {f.name: getattr(self, f.name) for f in fields(self)}

    @classmethod
    def from_dict(cls, d: dict) -> BenchmarkInput:
        """Deserialize from a msgpack dict."""
        d = dict(d)
        if "witness" in d and d["witness"] is not None:
            d["witness"] = [bytes(w) for w in d["witness"]]
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
    """Serialize a dataset to a MessagePack file."""
    data = {
        "header": dataset.header,
        "inputs": [inp.to_dict() for inp in dataset.inputs],
    }
    with path.open("wb") as f:
        msgpack.pack(data, f, use_bin_type=True)


def load_dataset(path: Path) -> Dataset:
    """Deserialize a dataset from a MessagePack file."""
    with path.open("rb") as f:
        raw: Any = msgpack.unpack(f, raw=False)
    inputs = [BenchmarkInput.from_dict(d) for d in raw["inputs"]]
    return Dataset(inputs=inputs, header=raw["header"])
