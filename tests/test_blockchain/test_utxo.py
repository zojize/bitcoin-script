"""Tests for the SQLite-backed UTXO set."""

from __future__ import annotations

from bitcoin_script.blockchain.utxo import UTXOSet


class TestUTXOSet:
    def test_add_and_get(self) -> None:
        utxo = UTXOSet()
        txid = b"\x01" * 32
        utxo.add(txid, 0, b"\x76\xa9", 5000)
        result = utxo.get(txid, 0)
        assert result == (b"\x76\xa9", 5000)

    def test_get_missing(self) -> None:
        utxo = UTXOSet()
        assert utxo.get(b"\x00" * 32, 0) is None

    def test_spend(self) -> None:
        utxo = UTXOSet()
        txid = b"\x01" * 32
        utxo.add(txid, 0, b"\xab", 100)
        script, amount = utxo.spend(txid, 0)
        assert script == b"\xab"
        assert amount == 100
        assert utxo.get(txid, 0) is None

    def test_spend_missing_raises(self) -> None:
        utxo = UTXOSet()
        import pytest
        with pytest.raises(KeyError):
            utxo.spend(b"\x00" * 32, 0)

    def test_size(self) -> None:
        utxo = UTXOSet()
        assert utxo.size() == 0
        utxo.add(b"\x01" * 32, 0, b"", 0)
        utxo.add(b"\x01" * 32, 1, b"", 0)
        assert utxo.size() == 2
        utxo.spend(b"\x01" * 32, 0)
        assert utxo.size() == 1

    def test_checkpoint_height(self) -> None:
        utxo = UTXOSet()
        assert utxo.checkpoint_height == -1
        utxo.checkpoint_height = 42
        utxo.commit()
        assert utxo.checkpoint_height == 42

    def test_persistence(self, tmp_path) -> None:
        db = tmp_path / "utxo.db"
        txid = b"\xab" * 32
        utxo = UTXOSet(db)
        utxo.add(txid, 0, b"\xff", 999)
        utxo.checkpoint_height = 10
        utxo.commit()
        utxo.close()

        utxo2 = UTXOSet(db)
        assert utxo2.get(txid, 0) == (b"\xff", 999)
        assert utxo2.checkpoint_height == 10
        utxo2.close()
