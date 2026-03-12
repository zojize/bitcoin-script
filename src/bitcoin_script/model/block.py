"""Bitcoin block data structures."""

from __future__ import annotations

from dataclasses import dataclass

from bitcoin_script.model.transaction import Transaction
from bitcoin_script.types import BlockHash


@dataclass(frozen=True)
class BlockHeader:
    """An 80-byte Bitcoin block header."""

    version: int  # int32
    prev_block_hash: BlockHash
    merkle_root: bytes  # 32 bytes
    timestamp: int  # uint32, Unix epoch
    bits: int  # uint32, compact target representation
    nonce: int  # uint32

    @classmethod
    def from_bytes(cls, data: bytes) -> BlockHeader:
        """Deserialize a block header from 80 raw bytes."""
        ...

    def to_bytes(self) -> bytes:
        """Serialize to 80 raw bytes."""
        ...

    def block_hash(self) -> BlockHash:
        """Compute the block hash (double SHA-256 of the 80-byte header)."""
        ...

    def target(self) -> int:
        """Decode the compact bits field into a full 256-bit target value."""
        ...

    def difficulty(self) -> float:
        """Compute the difficulty relative to the genesis block target."""
        ...


@dataclass(frozen=True)
class Block:
    """A complete Bitcoin block (header + transactions)."""

    header: BlockHeader
    transactions: tuple[Transaction, ...]

    @classmethod
    def from_bytes(cls, data: bytes) -> Block:
        """Deserialize a full block from raw bytes."""
        ...

    def merkle_root_computed(self) -> bytes:
        """Compute the Merkle root from the block's transactions."""
        ...

    def validate_merkle_root(self) -> bool:
        """Check that the header's merkle_root matches the computed one."""
        ...

    def validate_proof_of_work(self) -> bool:
        """Check that block_hash <= target from header.bits."""
        ...
