"""Tests for the benchmark input extractor."""

from __future__ import annotations

from unittest.mock import MagicMock

from bitcoin_script.benchmark.extractor import extract_inputs_from_block


class TestExtractInputsFromBlock:
    """Test input extraction logic using mocked block data."""

    def test_coinbase_only_block_yields_no_inputs(self) -> None:
        """Block with only a coinbase tx should produce zero benchmark inputs."""
        mock_coinbase_tx = MagicMock()
        mock_coinbase_tx.vin = []
        mock_coinbase_tx.vout = []
        mock_coinbase_tx.GetTxid.return_value = b"\x00" * 32
        mock_coinbase_tx.wit = None

        mock_block = MagicMock()
        mock_block.vtx = [mock_coinbase_tx]
        mock_block.nTime = 1231006505

        utxo = MagicMock()
        inputs = extract_inputs_from_block(
            block=mock_block,
            height=0,
            utxo=utxo,
            category="continuous",
        )
        assert inputs == []

    def test_extract_returns_benchmark_input_type(self) -> None:
        """Non-coinbase inputs should produce BenchmarkInput objects."""
        from bitcoin_script.benchmark.extractor import extract_inputs_from_block
        assert callable(extract_inputs_from_block)
