"""Parse Bitcoin Core .blk files into Block objects."""

from __future__ import annotations

import hashlib
import struct
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO

from bitcoin.core import CBlock

# Mainnet magic bytes: 0xF9BEB4D9 (little-endian in files)
MAINNET_MAGIC = b"\xf9\xbe\xb4\xd9"
HEADER_SIZE = 8  # 4-byte magic + 4-byte block size


def _read_xor_key(data_dir: Path) -> bytes | None:
    """Read the XOR obfuscation key if present (Bitcoin Core v28+).

    Returns the key bytes, or None if no xor.dat exists.
    """
    xor_path = data_dir / "blocks" / "xor.dat"
    if xor_path.exists():
        return xor_path.read_bytes()
    return None


def _xor_bytes(data: bytes, key: bytes, offset: int) -> bytes:
    """XOR *data* with *key*, cycling the key from *offset*."""
    key_len = len(key)
    return bytes(b ^ key[(offset + i) % key_len] for i, b in enumerate(data))


class BlockFileParser:
    """Parse Bitcoin Core .blk data files.

    Bitcoin Core stores raw blocks in blk?????.dat files in the blocks/
    subdirectory. Each file contains multiple blocks, each prefixed with
    a 4-byte magic number (0xF9BEB4D9 for mainnet) and 4-byte size.

    Starting with Bitcoin Core v28, files may be XOR-obfuscated with a
    key stored in ``blocks/xor.dat``.  This parser detects and handles
    that automatically.
    """

    _data_dir: Path
    _magic: bytes
    _xor_key: bytes | None

    def __init__(self, data_dir: Path, *, magic: bytes = MAINNET_MAGIC) -> None:
        """Initialize parser pointing at a Bitcoin Core data directory.

        Args:
            data_dir: Path to the Bitcoin Core data directory
                      (containing a blocks/ subdirectory with .dat files).
            magic: 4-byte network magic to expect (default: mainnet).
        """
        self._data_dir = data_dir
        self._magic = magic
        self._xor_key = _read_xor_key(data_dir)

    def _blk_files(self) -> Iterator[Path]:
        """Yield .blk file paths in numerical order."""
        blocks_dir = self._data_dir / "blocks"
        for i in range(99_999 + 1):
            path = blocks_dir / f"blk{i:05d}.dat"
            if not path.exists():
                break
            yield path

    def _iter_blocks_in_file(self, f: BinaryIO) -> Iterator[CBlock]:
        """Yield CBlock objects from an open .blk file handle."""
        while True:
            file_offset = f.tell()
            header = f.read(HEADER_SIZE)
            if len(header) == 0:
                break  # EOF
            if len(header) < HEADER_SIZE:
                break  # truncated trailing bytes

            if self._xor_key is not None:
                header = _xor_bytes(header, self._xor_key, file_offset)

            magic, size = struct.unpack("<4sI", header)
            if magic != self._magic:
                msg = f"bad magic: expected {self._magic.hex()}, got {magic.hex()}"
                raise ValueError(msg)

            raw_offset = f.tell()
            raw = f.read(size)
            if len(raw) < size:
                msg = f"truncated block: expected {size} bytes, got {len(raw)}"
                raise ValueError(msg)

            if self._xor_key is not None:
                raw = _xor_bytes(raw, self._xor_key, raw_offset)

            yield CBlock.deserialize(raw)

    def _skip_block(self, f: BinaryIO) -> bool:
        """Skip one block in the file without deserializing. Returns False at EOF."""
        file_offset = f.tell()
        header = f.read(HEADER_SIZE)
        if len(header) < HEADER_SIZE:
            return False

        if self._xor_key is not None:
            header = _xor_bytes(header, self._xor_key, file_offset)

        _magic, size = struct.unpack("<4sI", header)
        f.seek(size, 1)
        return True

    def __iter__(self) -> Iterator[CBlock]:
        """Yield parsed Block objects from all .blk files in order.

        Iterates through blk00000.dat, blk00001.dat, etc., parsing each
        block from the raw file format.

        Note: Blocks in .blk files are stored in the order they were
        *received*, which may not match chain height order.
        """
        yield from self.iter_blocks()

    def iter_blocks(self, start: int = 0) -> Iterator[CBlock]:
        """Yield parsed Block objects, optionally skipping the first *start* blocks.

        Skipped blocks are not deserialized, so this is much faster than
        iterating and discarding with ``islice``.

        Args:
            start: Number of blocks to skip before yielding (default: 0).
        """
        skipped = 0
        for path in self._blk_files():
            with path.open("rb") as f:
                if skipped < start:
                    while skipped < start:
                        if not self._skip_block(f):
                            break
                        skipped += 1
                    if skipped < start:
                        continue
                yield from self._iter_blocks_in_file(f)

    def scan_headers(self) -> Iterator[tuple[bytes, bytes, Path, int, int]]:
        """Yield (block_hash, prev_hash, file_path, raw_offset, size) for every block.

        Only reads the 80-byte header per block — does NOT deserialize the
        full block.  Useful for building a chain index without loading all
        block data into memory.
        """
        for path in self._blk_files():
            with path.open("rb") as f:
                while True:
                    file_offset = f.tell()
                    header = f.read(HEADER_SIZE)
                    if len(header) < HEADER_SIZE:
                        break

                    if self._xor_key is not None:
                        header = _xor_bytes(header, self._xor_key, file_offset)

                    magic, size = struct.unpack("<4sI", header)
                    if magic != self._magic:
                        break

                    raw_offset = f.tell()

                    # Read only the 80-byte block header
                    blk_header = f.read(80)
                    if len(blk_header) < 80:
                        break
                    if self._xor_key is not None:
                        blk_header = _xor_bytes(blk_header, self._xor_key, raw_offset)

                    # SHA256d of the 80-byte header = block hash
                    block_hash = hashlib.sha256(
                        hashlib.sha256(blk_header).digest()
                    ).digest()
                    prev_hash = blk_header[4:36]

                    # Skip the rest of the block
                    f.seek(raw_offset + size)

                    yield (block_hash, prev_hash, path, raw_offset, size)

    def read_block_at(self, path: Path, offset: int, size: int) -> CBlock:
        """Deserialize a single block given its file location."""
        with path.open("rb") as f:
            f.seek(offset)
            raw = f.read(size)
            if self._xor_key is not None:
                raw = _xor_bytes(raw, self._xor_key, offset)
            return CBlock.deserialize(raw)

    def get_block_at_height(self, height: int) -> CBlock:
        """Retrieve the block at a specific height.

        Warning: This performs a sequential scan through every block up
        to the requested height. For repeated lookups, iterate once and
        build your own index.

        Args:
            height: Block height (0 = genesis block).

        Raises:
            IndexError: If the height is beyond the available chain.
        """
        count = 0
        for i, block in enumerate(self):
            if i == height:
                return block
            count = i + 1
        raise IndexError(
            f"height {height} is beyond the available chain ({count} blocks)"
        )
