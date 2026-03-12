"""Bitcoin transaction data structures."""

from __future__ import annotations

from dataclasses import dataclass

from bitcoin_script.types import ScriptBytes, TxId


@dataclass(frozen=True)
class OutPoint:
    """Reference to a specific output of a previous transaction."""

    txid: TxId
    vout: int  # uint32

    @classmethod
    def from_bytes(cls, data: bytes) -> OutPoint:
        """Deserialize an outpoint from 36 raw bytes (32 txid + 4 vout)."""
        ...

    def to_bytes(self) -> bytes:
        """Serialize to 36 raw bytes."""
        ...


@dataclass(frozen=True)
class TxIn:
    """Transaction input: references a previous output and provides unlocking script."""

    prevout: OutPoint
    script_sig: ScriptBytes
    sequence: int  # uint32
    witness: list[bytes]  # empty for non-segwit

    @classmethod
    def from_bytes(cls, data: bytes, offset: int = 0) -> tuple[TxIn, int]:
        """Deserialize a TxIn from raw bytes starting at offset.

        Returns the parsed TxIn and the new offset after parsing.
        """
        ...

    def to_bytes(self) -> bytes:
        """Serialize to raw bytes (without witness data)."""
        ...


@dataclass(frozen=True)
class TxOut:
    """Transaction output: specifies value and locking script."""

    value: int  # satoshis (int64)
    script_pubkey: ScriptBytes

    @classmethod
    def from_bytes(cls, data: bytes, offset: int = 0) -> tuple[TxOut, int]:
        """Deserialize a TxOut from raw bytes starting at offset.

        Returns the parsed TxOut and the new offset after parsing.
        """
        ...

    def to_bytes(self) -> bytes:
        """Serialize to raw bytes."""
        ...


@dataclass(frozen=True)
class Transaction:
    """A complete Bitcoin transaction."""

    version: int  # int32
    inputs: tuple[TxIn, ...]
    outputs: tuple[TxOut, ...]
    locktime: int  # uint32
    is_segwit: bool

    @classmethod
    def from_bytes(cls, data: bytes) -> Transaction:
        """Deserialize a transaction from raw bytes."""
        ...

    def to_bytes(self, *, include_witness: bool = True) -> bytes:
        """Serialize to raw bytes.

        Args:
            include_witness: If True and transaction is segwit, include witness data.
        """
        ...

    def txid(self) -> TxId:
        """Compute the transaction ID (double SHA-256 of non-witness serialization)."""
        ...

    def wtxid(self) -> TxId:
        """Compute the witness transaction ID (double SHA-256 of full serialization)."""
        ...

    def weight(self) -> int:
        """Compute transaction weight in weight units."""
        ...

    def vsize(self) -> int:
        """Compute virtual size in vbytes (weight / 4, rounded up)."""
        ...
