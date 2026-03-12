"""Tests for transaction data structures."""

from bitcoin_script.model.transaction import OutPoint, Transaction, TxIn, TxOut
from bitcoin_script.types import ScriptBytes, TxId


class TestOutPoint:
    def test_from_bytes_roundtrip(self) -> None:
        """Serialize and deserialize should produce identical OutPoint."""
        ...

    def test_frozen(self) -> None:
        """OutPoint should be immutable."""
        ...


class TestTxIn:
    def test_from_bytes_roundtrip(self) -> None:
        """Serialize and deserialize should produce identical TxIn."""
        ...


class TestTxOut:
    def test_from_bytes_roundtrip(self) -> None:
        """Serialize and deserialize should produce identical TxOut."""
        ...

    def test_value_in_satoshis(self) -> None:
        """Value should be stored in satoshis."""
        ...


class TestTransaction:
    def test_from_bytes_roundtrip(self) -> None:
        """Serialize and deserialize should produce identical Transaction."""
        ...

    def test_txid_is_32_bytes(self) -> None:
        """Transaction ID should be 32 bytes."""
        ...

    def test_non_segwit_txid_equals_wtxid(self) -> None:
        """For non-segwit transactions, txid should equal wtxid."""
        ...

    def test_segwit_txid_differs_from_wtxid(self) -> None:
        """For segwit transactions, txid and wtxid should differ."""
        ...

    def test_weight_and_vsize(self) -> None:
        """Weight and vsize should be consistent."""
        ...
