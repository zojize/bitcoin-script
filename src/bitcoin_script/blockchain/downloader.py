"""Download and manage Bitcoin blockchain data via Bitcoin Core RPC."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from bitcoin.rpc import RawProxy


class BlockchainDownloader:
    """Download and verify Bitcoin blocks from a Bitcoin Core node.

    Uses python-bitcoinlib's RPC proxy to communicate with a running
    Bitcoin Core instance.

    Usage::

        dl = BlockchainDownloader.from_url("http://user:pass@127.0.0.1:8332")
        info = dl.get_blockchain_info()
        print(info["blocks"])

        # Fetch the genesis block (raw hex)
        raw = dl.get_block_raw(0)

        # Fetch a block as a decoded dict
        block = dl.get_block(0, verbosity=1)
    """

    _data_dir: Path
    _proxy: RawProxy

    def __init__(
        self,
        data_dir: Path | None = None,
        *,
        service_url: str | None = None,
        btc_conf_file: str | None = None,
    ) -> None:
        """Initialize the downloader.

        Provide *either* ``service_url`` or ``btc_conf_file``.  If neither is
        given, python-bitcoinlib will try to locate ``bitcoin.conf``
        automatically (``~/.bitcoin/bitcoin.conf`` on Linux,
        ``~/Library/Application Support/Bitcoin/bitcoin.conf`` on macOS).

        Args:
            data_dir: Optional local directory to cache downloaded block data.
            service_url: Bitcoin Core RPC URL, e.g.
                ``http://user:pass@127.0.0.1:8332``.
            btc_conf_file: Path to a ``bitcoin.conf`` for automatic auth.
        """
        self._data_dir = data_dir or Path.cwd() / ".bitcoin_data"

        kwargs: dict[str, Any] = {}
        if service_url is not None:
            kwargs["service_url"] = service_url
        if btc_conf_file is not None:
            kwargs["btc_conf_file"] = btc_conf_file

        # RawProxy gives us raw JSON dicts — no model conversion yet.
        self._proxy = RawProxy(**kwargs)

    # -- construction helpers --------------------------------------------------

    @classmethod
    def from_url(cls, url: str, data_dir: Path | None = None) -> BlockchainDownloader:
        """Create a downloader from an explicit RPC URL."""
        return cls(data_dir=data_dir, service_url=url)

    @classmethod
    def from_conf(
        cls, conf_path: str, data_dir: Path | None = None
    ) -> BlockchainDownloader:
        """Create a downloader from a ``bitcoin.conf`` file."""
        return cls(data_dir=data_dir, btc_conf_file=conf_path)

    # -- blockchain info -------------------------------------------------------

    def get_blockchain_info(self) -> dict[str, Any]:
        """Return ``getblockchaininfo`` — chain name, height, progress, etc."""
        return self._proxy.getblockchaininfo()  # type: ignore[no-any-return]

    def get_block_count(self) -> int:
        """Return the height of the most-work fully-validated chain."""
        return self._proxy.getblockcount()  # type: ignore[no-any-return]

    # -- block fetching --------------------------------------------------------

    def get_block_hash(self, height: int) -> str:
        """Return the block hash (hex string) at the given height."""
        return self._proxy.getblockhash(height)  # type: ignore[no-any-return]

    def get_block(self, height: int, verbosity: int = 1) -> dict[str, Any] | str:
        """Fetch a block by height.

        *verbosity*:
            - ``0`` → raw hex string
            - ``1`` → JSON with txid list
            - ``2`` → JSON with full decoded transactions
        """
        block_hash = self.get_block_hash(height)
        return self._proxy.getblock(block_hash, verbosity)  # type: ignore[no-any-return]

    def get_block_raw(self, height: int) -> str:
        """Return the raw serialised block at *height* as a hex string."""
        block_hash = self.get_block_hash(height)
        return self._proxy.getblock(block_hash, 0)  # type: ignore[no-any-return]

    def get_block_by_hash(
        self, block_hash: str, verbosity: int = 1
    ) -> dict[str, Any] | str:
        """Fetch a block by its hash directly."""
        return self._proxy.getblock(block_hash, verbosity)  # type: ignore[no-any-return]

    # -- transaction fetching --------------------------------------------------

    def get_raw_transaction(
        self, txid: str, verbose: bool = False
    ) -> str | dict[str, Any]:
        """Fetch a transaction by txid.

        Returns hex string if *verbose* is ``False``, decoded dict otherwise.
        """
        return self._proxy.getrawtransaction(txid, verbose)  # type: ignore[no-any-return]

    # -- bulk download ---------------------------------------------------------

    def download_blocks(
        self,
        start_height: int = 0,
        end_height: int | None = None,
    ) -> list[dict[str, Any]]:
        """Download blocks in the given height range via RPC.

        Returns a list of decoded block dicts (verbosity=1).

        Args:
            start_height: First block height to download (inclusive).
            end_height: Last block height to download (inclusive).
                        ``None`` means current chain tip.
        """
        if end_height is None:
            end_height = self.get_block_count()

        blocks: list[dict[str, Any]] = []
        for h in range(start_height, end_height + 1):
            block = self.get_block(h, verbosity=1)
            assert isinstance(block, dict)
            blocks.append(block)

        return blocks

    def verify_chain(self, up_to_height: int | None = None) -> bool:
        """Verify the downloaded chain from genesis.

        Checks that each block's ``previousblockhash`` links to the
        previous block's hash.

        Args:
            up_to_height: Stop verification at this height.
                          ``None`` means current chain tip.
        """
        if up_to_height is None:
            up_to_height = self.get_block_count()

        prev_hash: str | None = None
        for h in range(0, up_to_height + 1):
            block = self.get_block(h, verbosity=1)
            assert isinstance(block, dict)

            if prev_hash is not None and block.get("previousblockhash") != prev_hash:
                return False
            prev_hash = block["hash"]

        return True
