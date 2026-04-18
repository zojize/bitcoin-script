"""Tests for benchmark dataset schema and serialization."""

from __future__ import annotations

from bitcoin_script.benchmark.dataset import (
    BenchmarkInput,
    Dataset,
    load_dataset,
    save_dataset,
)


def _make_input(**overrides: object) -> BenchmarkInput:
    """Create a BenchmarkInput with sensible defaults."""
    defaults = {
        "block_height": 170,
        "tx_index": 1,
        "input_index": 0,
        "txid": b"\xaa" * 32,
        "era": "pre-p2sh",
        "category": "continuous",
        "script_pubkey": bytes.fromhex(
            "76a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba88ac"
        ),
        "script_sig": bytes.fromhex("483045022100abcdef0022020012340100"),
        "amount": 5000000000,
        "flags": 0,
        "witness": [],
        "tx_serialized": b"\x01\x00" * 50,
        "n_in": 0,
        "sighash_blob": b"\x01" + b"\x00\x00" + b"\xbb" * 32,
        "tx_version": 1,
        "n_locktime": 0,
        "n_sequence": 0xFFFFFFFF,
    }
    defaults.update(overrides)
    return BenchmarkInput(**defaults)


class TestBenchmarkInput:
    def test_to_dict_round_trip(self) -> None:
        inp = _make_input()
        d = inp.to_dict()
        restored = BenchmarkInput.from_dict(d)
        assert restored.block_height == inp.block_height
        assert restored.txid == inp.txid
        assert restored.script_pubkey == inp.script_pubkey
        assert restored.witness == inp.witness
        assert restored.era == inp.era

    def test_witness_round_trip(self) -> None:
        witness = [b"\x30" * 72, b"\x02" * 33]
        inp = _make_input(witness=witness, era="segwit")
        d = inp.to_dict()
        restored = BenchmarkInput.from_dict(d)
        assert restored.witness == witness


class TestDataset:
    def test_save_and_load(self, tmp_path: object) -> None:
        from pathlib import Path

        p = Path(str(tmp_path)) / "test.msgpack"
        inputs = [_make_input(block_height=i) for i in range(5)]
        ds = Dataset(inputs=inputs)
        save_dataset(ds, p)
        loaded = load_dataset(p)
        assert loaded.header["version"] == 3
        assert loaded.header["input_count"] == 5
        assert len(loaded.inputs) == 5
        assert loaded.inputs[0].block_height == 0
        assert loaded.inputs[4].block_height == 4

    def test_empty_dataset(self, tmp_path: object) -> None:
        from pathlib import Path

        p = Path(str(tmp_path)) / "empty.msgpack"
        ds = Dataset(inputs=[])
        save_dataset(ds, p)
        loaded = load_dataset(p)
        assert len(loaded.inputs) == 0
        assert loaded.header["input_count"] == 0
