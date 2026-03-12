"""Tests for block file parsing."""

from bitcoin_script.blockchain.parser import BlockFileParser


class TestBlockFileParser:
    def test_iter_blocks_empty_dir(self) -> None:
        """Should yield nothing for an empty directory."""
        ...

    def test_parse_genesis_block(self) -> None:
        """Should correctly parse the genesis block from raw bytes."""
        ...

    def test_block_magic_number_validation(self) -> None:
        """Should reject files with incorrect magic numbers."""
        ...
