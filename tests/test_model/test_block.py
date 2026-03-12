"""Tests for block data structures."""

from bitcoin_script.model.block import Block, BlockHeader


class TestBlockHeader:
    def test_from_bytes_roundtrip(self) -> None:
        """Serialize and deserialize should produce identical BlockHeader."""
        ...

    def test_genesis_block_hash(self) -> None:
        """Genesis block header should produce the known genesis hash."""
        ...

    def test_target_from_bits(self) -> None:
        """Should correctly decode compact bits to full target."""
        ...

    def test_difficulty(self) -> None:
        """Difficulty should be relative to genesis target."""
        ...


class TestBlock:
    def test_genesis_block_valid(self) -> None:
        """Genesis block should pass all validation checks."""
        ...

    def test_validate_merkle_root(self) -> None:
        """Computed merkle root should match header's merkle_root."""
        ...

    def test_validate_proof_of_work(self) -> None:
        """Block hash should be less than or equal to target."""
        ...
