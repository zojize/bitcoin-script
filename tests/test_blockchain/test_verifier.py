"""Integration tests for the ChainVerifier.

Requires Bitcoin Core mainnet block files at the default location.
These tests are marked with @pytest.mark.mainnet and excluded by default.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from bitcoin_script.blockchain.verifier import ChainVerifier

_BITCOIN_DIR = Path.home() / "Library" / "Application Support" / "Bitcoin"
_HAS_BLOCKS = (_BITCOIN_DIR / "blocks" / "blk00000.dat").exists()

pytestmark = pytest.mark.mainnet


@pytest.fixture(scope="module")
def verifier():
    if not _HAS_BLOCKS:
        pytest.skip("Bitcoin Core block files not found")
    return ChainVerifier(_BITCOIN_DIR)


class TestEarlyBlocks:
    """Verify the first blocks of mainnet.

    Genesis through block ~170 have no non-coinbase transactions.
    Block 170 is the first block with a real transaction (Satoshi → Hal Finney).
    """

    def test_genesis_block(self, verifier: ChainVerifier) -> None:
        """Genesis block: 1 coinbase, no script verification needed."""
        result = verifier.verify_block(0)
        assert result.ok, f"Genesis failed: {result.errors}"
        assert result.tx_count == 1
        assert result.input_count == 0

    def test_first_200_blocks(self, verifier: ChainVerifier) -> None:
        """Verify blocks 0-199. Early chain has few real transactions."""
        result = verifier.verify_chain(start=0, end=199)
        assert result.ok, f"Failed: {result.errors}"
        assert verifier.utxo.checkpoint_height >= 199

    def test_utxo_state_after_200(self, verifier: ChainVerifier) -> None:
        """After 200 blocks, UTXO set should contain early coinbase outputs."""
        assert verifier.utxo.checkpoint_height >= 199
        # Block 170 had a real spend (block 9 coinbase → Hal Finney)
        # Verify the output was spent (should NOT be in UTXO set)
        spent_txid = bytes.fromhex(
            "c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd3704"
        )
        assert verifier.utxo.get(spent_txid, 0) is None, "Block 9 coinbase should be spent"
        # The receiving output from block 170's tx should exist
        assert verifier.utxo.size() > 0
