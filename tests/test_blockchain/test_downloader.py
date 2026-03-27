"""Smoke tests for BlockchainDownloader against a Bitcoin Core regtest node.

These tests are skipped by default — run with ``-m rpc`` to include them::

    uv run pytest -m rpc

A regtest node is started and stopped automatically.  To use an existing node
instead, set ``BITCOIN_RPC_URL``::

    BITCOIN_RPC_URL=http://user:pass@127.0.0.1:18443 uv run pytest -m rpc
"""

from __future__ import annotations

from collections.abc import Generator
import os
import resource
import shutil
import subprocess
import tempfile
import time

import bitcoin
import pytest

from bitcoin_script.blockchain.downloader import BlockchainDownloader

# Select regtest network params so python-bitcoinlib uses the right RPC port, etc.
bitcoin.SelectParams("regtest")

# Well-known genesis block values (regtest)
GENESIS_HASH = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
GENESIS_PREV = "0" * 64
GENESIS_MERKLE_ROOT = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"

# Default regtest RPC URL matching tests/bitcoin-regtest.conf
DEFAULT_RPC_URL = "http://test:test@127.0.0.1:18443"
CONF_PATH = os.path.join(os.path.dirname(__file__), "..", "bitcoin-regtest.conf")


@pytest.fixture(scope="session")
def _regtest_node() -> Generator[str]:
    """Start a bitcoind regtest node for the test session.

    If ``BITCOIN_RPC_URL`` is set the fixture assumes the user is managing
    the node themselves and returns that URL without starting anything.

    Returns the RPC URL to connect to.
    """
    url = os.environ.get("BITCOIN_RPC_URL")
    if url:
        yield url
        return

    if not shutil.which("bitcoind"):
        pytest.skip(
            "bitcoind not found on PATH — install Bitcoin Core to run RPC tests"
        )

    datadir = tempfile.mkdtemp(prefix="btc-regtest-")
    conf = os.path.abspath(CONF_PATH)

    def _set_fd_limit() -> None:
        """Ensure a finite file-descriptor limit for bitcoind.

        When the soft limit is ``RLIM_INFINITY`` bitcoind reports -1 available
        descriptors and refuses to start.
        """
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft == resource.RLIM_INFINITY:
            resource.setrlimit(resource.RLIMIT_NOFILE, (4096, hard))

    proc = subprocess.Popen(
        [
            "bitcoind",
            "-regtest",
            f"-datadir={datadir}",
            f"-conf={conf}",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        preexec_fn=_set_fd_limit,
    )

    # Wait for RPC to become ready
    cli_base = ["bitcoin-cli", "-regtest", "-rpcuser=test", "-rpcpassword=test"]
    for _ in range(30):
        try:
            subprocess.run(
                [*cli_base, "getblockchaininfo"],
                capture_output=True,
                check=True,
            )
            break
        except (subprocess.CalledProcessError, FileNotFoundError):
            time.sleep(0.5)
    else:
        proc.terminate()
        shutil.rmtree(datadir, ignore_errors=True)
        pytest.fail("bitcoind did not become ready in time")

    yield DEFAULT_RPC_URL

    # Teardown: stop the node and clean up
    subprocess.run(cli_base + ["stop"], capture_output=True)
    proc.wait(timeout=10)
    shutil.rmtree(datadir, ignore_errors=True)


@pytest.fixture
def downloader(_regtest_node: str) -> BlockchainDownloader:
    """Create a downloader pointing at the regtest node."""
    return BlockchainDownloader.from_url(_regtest_node)


@pytest.fixture(autouse=True)
def _ensure_blocks(downloader: BlockchainDownloader) -> None:
    """Generate blocks if the regtest chain is too short.

    Several tests need at least 10 blocks.  In regtest mode we can mine
    instantly via ``generatetoaddress``.
    """
    height = downloader.get_block_count()
    if height < 10:
        # Ensure a wallet exists (Bitcoin Core v30+ doesn't auto-create one)
        try:
            downloader._proxy.createwallet("test")
        except Exception:
            # Wallet may already exist from a previous run
            try:
                downloader._proxy.loadwallet("test")
            except Exception:
                pass
        addr = downloader._proxy.getnewaddress()
        downloader._proxy.generatetoaddress(10 - height, addr)


@pytest.mark.rpc
class TestRPCConnectivity:
    """Basic connectivity checks — can we talk to Bitcoin Core at all?"""

    def test_get_blockchain_info(self, downloader: BlockchainDownloader) -> None:
        info = downloader.get_blockchain_info()
        assert "chain" in info
        assert info["chain"] == "regtest"
        assert "blocks" in info
        assert isinstance(info["blocks"], int)

    def test_get_block_count(self, downloader: BlockchainDownloader) -> None:
        height = downloader.get_block_count()
        assert isinstance(height, int)
        assert height >= 0


@pytest.mark.rpc
class TestGenesis:
    """Fetch the genesis block and verify well-known values."""

    def test_genesis_block_hash(self, downloader: BlockchainDownloader) -> None:
        block_hash = downloader.get_block_hash(0)
        assert block_hash == GENESIS_HASH

    def test_genesis_block_json(self, downloader: BlockchainDownloader) -> None:
        block = downloader.get_block(0, verbosity=1)
        assert isinstance(block, dict)
        assert block["hash"] == GENESIS_HASH
        assert block["height"] == 0
        assert "previousblockhash" not in block or block["previousblockhash"] is None
        assert block["merkleroot"] == GENESIS_MERKLE_ROOT

    def test_genesis_block_raw_hex(self, downloader: BlockchainDownloader) -> None:
        raw = downloader.get_block_raw(0)
        assert isinstance(raw, str)
        # Raw block hex must be non-empty and even-length
        assert len(raw) > 0
        assert len(raw) % 2 == 0

    def test_genesis_has_one_transaction(
        self, downloader: BlockchainDownloader
    ) -> None:
        block = downloader.get_block(0, verbosity=1)
        assert isinstance(block, dict)
        assert len(block["tx"]) == 1


@pytest.mark.rpc
class TestBlockFetching:
    """Fetch a small range of blocks."""

    def test_download_first_ten_blocks(self, downloader: BlockchainDownloader) -> None:
        blocks = downloader.download_blocks(start_height=0, end_height=9)
        assert len(blocks) == 10
        # Heights should be sequential
        for i, block in enumerate(blocks):
            assert block["height"] == i

    def test_verify_chain_first_ten(self, downloader: BlockchainDownloader) -> None:
        assert downloader.verify_chain(up_to_height=9) is True

    def test_block_by_hash(self, downloader: BlockchainDownloader) -> None:
        block = downloader.get_block_by_hash(GENESIS_HASH, verbosity=1)
        assert isinstance(block, dict)
        assert block["height"] == 0
