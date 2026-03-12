"""Download and manage Bitcoin blockchain data."""

from __future__ import annotations

from pathlib import Path


class BlockchainDownloader:
    """Download and verify Bitcoin blocks from a Bitcoin Core node or network."""

    _data_dir: Path
    _rpc_url: str | None

    def __init__(
        self,
        data_dir: Path,
        rpc_url: str | None = None,
    ) -> None:
        """Initialize the downloader.

        Args:
            data_dir: Local directory to store block data.
            rpc_url: Optional Bitcoin Core RPC URL (e.g. http://user:pass@localhost:8332).
                     If None, will look for .blk files in data_dir.
        """
        ...

    def download_blocks(
        self,
        start_height: int = 0,
        end_height: int | None = None,
    ) -> None:
        """Download blocks in the given height range via RPC.

        Args:
            start_height: First block height to download (inclusive).
            end_height: Last block height to download (inclusive). None = chain tip.
        """
        ...

    def verify_chain(self, up_to_height: int | None = None) -> bool:
        """Verify the downloaded chain from genesis.

        Checks that each block's prev_block_hash links to the previous block
        and that proof-of-work is valid.

        Args:
            up_to_height: Stop verification at this height. None = all blocks.

        Returns:
            True if the chain is valid.
        """
        ...
