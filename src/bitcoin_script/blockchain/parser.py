"""Parse Bitcoin Core .blk files into Block objects."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from bitcoin_script.model.block import Block


class BlockFileParser:
    """Parse Bitcoin Core .blk data files.

    Bitcoin Core stores raw blocks in blk?????.dat files in the blocks/
    subdirectory. Each file contains multiple blocks, each prefixed with
    a 4-byte magic number (0xF9BEB4D9 for mainnet) and 4-byte size.
    """

    _data_dir: Path

    def __init__(self, data_dir: Path) -> None:
        """Initialize parser pointing at a Bitcoin Core data directory.

        Args:
            data_dir: Path to the Bitcoin Core data directory
                      (containing a blocks/ subdirectory with .dat files).
        """
        ...

    def iter_blocks(self) -> Iterator[Block]:
        """Yield parsed Block objects from all .blk files in order.

        Iterates through blk00000.dat, blk00001.dat, etc., parsing each
        block from the raw file format.
        """
        ...

    def get_block_at_height(self, height: int) -> Block:
        """Retrieve the block at a specific height.

        Note: This requires an index or sequential scan. For efficient
        height-based lookup, build an index first.

        Args:
            height: Block height (0 = genesis block).

        Raises:
            IndexError: If the height is beyond the available chain.
        """
        ...
