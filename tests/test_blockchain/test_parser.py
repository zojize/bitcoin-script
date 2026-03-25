"""Tests for block file parsing."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from bitcoin_script.blockchain.parser import (
    HEADER_SIZE,
    BlockFileParser,
    _xor_bytes,
)

# Raw genesis block entry: magic(4) + size(4) + serialized block(285)
_GENESIS_ENTRY = bytes.fromhex(
    "f9beb4d91d010000"
    "01000000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
    "29ab5f49ffff001d1dac2b7c"
    "01"
    "01000000"
    "01"
    "0000000000000000000000000000000000000000000000000000000000000000ffffffff"
    "4d"
    "04ffff001d0104455468652054696d65732030332f4a616e2f323030392043"
    "68616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261"
    "696c6f757420666f722062616e6b73"
    "ffffffff"
    "01"
    "00f2052a01000000"
    "43"
    "4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61"
    "deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf1"
    "1d5fac"
    "00000000"
)

GENESIS_HASH = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
GENESIS_MERKLE = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"


@pytest.fixture()
def data_dir(tmp_path: Path) -> Path:
    """Create a minimal Bitcoin data directory with a blocks/ subdir."""
    (tmp_path / "blocks").mkdir()
    return tmp_path


def _write_blk(data_dir: Path, index: int, payload: bytes) -> Path:
    """Write *payload* into blkINDEX.dat inside data_dir/blocks/."""
    path = data_dir / "blocks" / f"blk{index:05d}.dat"
    path.write_bytes(payload)
    return path


class TestXorBytes:
    """Unit tests for the _xor_bytes helper."""

    def test_identity_with_zero_key(self) -> None:
        data = b"\xf9\xbe\xb4\xd9"
        assert _xor_bytes(data, b"\x00" * 4, 0) == data

    def test_roundtrip(self) -> None:
        key = b"\xd2\x75\x9f\xb5\x54\xcd\x70\xe7"
        data = b"\xf9\xbe\xb4\xd9\x1d\x01\x00\x00"
        encrypted = _xor_bytes(data, key, 0)
        assert _xor_bytes(encrypted, key, 0) == data

    def test_offset_cycles_key(self) -> None:
        key = b"\xab\xcd"
        data = b"\x01\x02\x03"
        # offset=1 → key indices 1, 0, 1
        expected = bytes([0x01 ^ 0xCD, 0x02 ^ 0xAB, 0x03 ^ 0xCD])
        assert _xor_bytes(data, key, 1) == expected


class TestBlockFileParser:
    """Tests for the BlockFileParser class."""

    def test_iter_empty_dir(self, data_dir: Path) -> None:
        """Should yield nothing when no .blk files exist."""
        parser = BlockFileParser(data_dir)
        assert list(parser) == []

    def test_parse_genesis_block(self, data_dir: Path) -> None:
        """Should correctly parse the genesis block from a .blk file."""
        _write_blk(data_dir, 0, _GENESIS_ENTRY)
        parser = BlockFileParser(data_dir)

        blocks = list(parser)
        assert len(blocks) == 1

        genesis = blocks[0]
        assert genesis.GetHash()[::-1].hex() == GENESIS_HASH
        assert genesis.hashMerkleRoot[::-1].hex() == GENESIS_MERKLE
        assert len(genesis.vtx) == 1

    def test_block_magic_number_validation(self, data_dir: Path) -> None:
        """Should reject files with incorrect magic numbers."""
        bad_magic = b"\xde\xad\xbe\xef" + _GENESIS_ENTRY[4:]
        _write_blk(data_dir, 0, bad_magic)
        parser = BlockFileParser(data_dir)

        with pytest.raises(ValueError, match="bad magic"):
            list(parser)

    def test_multiple_blocks_in_single_file(self, data_dir: Path) -> None:
        """Should parse multiple concatenated blocks from one file."""
        _write_blk(data_dir, 0, _GENESIS_ENTRY * 3)
        parser = BlockFileParser(data_dir)

        blocks = list(parser)
        assert len(blocks) == 3
        for block in blocks:
            assert block.GetHash()[::-1].hex() == GENESIS_HASH

    def test_multiple_blk_files(self, data_dir: Path) -> None:
        """Should iterate across sequential blk?????.dat files."""
        _write_blk(data_dir, 0, _GENESIS_ENTRY)
        _write_blk(data_dir, 1, _GENESIS_ENTRY)
        parser = BlockFileParser(data_dir)

        blocks = list(parser)
        assert len(blocks) == 2

    def test_stops_at_gap_in_file_numbering(self, data_dir: Path) -> None:
        """Should stop when a .blk file number is missing (e.g. 0, 2 but no 1)."""
        _write_blk(data_dir, 0, _GENESIS_ENTRY)
        # skip blk00001.dat
        _write_blk(data_dir, 2, _GENESIS_ENTRY)
        parser = BlockFileParser(data_dir)

        blocks = list(parser)
        assert len(blocks) == 1  # only blk00000.dat

    def test_truncated_header_ignored(self, data_dir: Path) -> None:
        """Should silently stop on a truncated trailing header."""
        truncated = _GENESIS_ENTRY + b"\xf9\xbe"  # 2 bytes of next header
        _write_blk(data_dir, 0, truncated)
        parser = BlockFileParser(data_dir)

        blocks = list(parser)
        assert len(blocks) == 1  # the valid block before the truncated bytes

    def test_truncated_block_body_raises(self, data_dir: Path) -> None:
        """Should raise ValueError on a truncated block body."""
        # Valid header claiming 285 bytes, but only 10 bytes of body
        truncated = (
            _GENESIS_ENTRY[:HEADER_SIZE]
            + _GENESIS_ENTRY[HEADER_SIZE : HEADER_SIZE + 10]
        )
        _write_blk(data_dir, 0, truncated)
        parser = BlockFileParser(data_dir)

        with pytest.raises(ValueError, match="truncated block"):
            list(parser)

    def test_get_block_at_height_zero(self, data_dir: Path) -> None:
        """Should return genesis block for height 0."""
        _write_blk(data_dir, 0, _GENESIS_ENTRY * 3)
        parser = BlockFileParser(data_dir)

        block = parser.get_block_at_height(0)
        assert block.GetHash()[::-1].hex() == GENESIS_HASH

    def test_get_block_at_height_out_of_range(self, data_dir: Path) -> None:
        """Should raise IndexError when height exceeds available blocks."""
        _write_blk(data_dir, 0, _GENESIS_ENTRY)
        parser = BlockFileParser(data_dir)

        with pytest.raises(IndexError, match="beyond the available chain"):
            parser.get_block_at_height(5)

    def test_get_block_at_height_empty(self, data_dir: Path) -> None:
        """Should raise IndexError on an empty chain."""
        parser = BlockFileParser(data_dir)

        with pytest.raises(IndexError):
            parser.get_block_at_height(0)

    def test_xor_obfuscated_file(self, data_dir: Path) -> None:
        """Should transparently decode XOR-obfuscated .blk files."""
        key = b"\xd2\x75\x9f\xb5\x54\xcd\x70\xe7"
        # Write the XOR key
        (data_dir / "blocks" / "xor.dat").write_bytes(key)
        # Encrypt the genesis entry
        encrypted = _xor_bytes(_GENESIS_ENTRY, key, 0)
        _write_blk(data_dir, 0, encrypted)

        parser = BlockFileParser(data_dir)
        blocks = list(parser)
        assert len(blocks) == 1
        assert blocks[0].GetHash()[::-1].hex() == GENESIS_HASH

    def test_xor_multiple_blocks(self, data_dir: Path) -> None:
        """XOR offset should stay correct across multiple blocks in one file."""
        key = b"\xab\xcd\xef\x01\x23\x45\x67\x89"
        (data_dir / "blocks" / "xor.dat").write_bytes(key)

        plain = _GENESIS_ENTRY * 2
        encrypted = _xor_bytes(plain, key, 0)
        _write_blk(data_dir, 0, encrypted)

        parser = BlockFileParser(data_dir)
        blocks = list(parser)
        assert len(blocks) == 2
        for block in blocks:
            assert block.GetHash()[::-1].hex() == GENESIS_HASH

    def test_custom_magic(self, data_dir: Path) -> None:
        """Should accept a custom magic for non-mainnet networks."""
        custom_magic = b"\x0b\x11\x09\x07"  # testnet3 magic
        raw_block = _GENESIS_ENTRY[HEADER_SIZE:]  # strip mainnet header
        entry = custom_magic + struct.pack("<I", len(raw_block)) + raw_block
        _write_blk(data_dir, 0, entry)

        parser = BlockFileParser(data_dir, magic=custom_magic)
        blocks = list(parser)
        assert len(blocks) == 1
