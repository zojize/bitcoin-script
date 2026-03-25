"""Tests for block and transaction validation."""


class TestBlockSubsidy:
    def test_genesis_subsidy(self) -> None:
        """Block 0 subsidy should be 50 BTC (5_000_000_000 satoshis)."""
        ...

    def test_first_halving(self) -> None:
        """Block 210,000 subsidy should be 25 BTC."""
        ...

    def test_second_halving(self) -> None:
        """Block 420,000 subsidy should be 12.5 BTC."""
        ...

    def test_subsidy_reaches_zero(self) -> None:
        """After ~33 halvings, subsidy should be 0."""
        ...


class TestBlockValidation:
    def test_genesis_block_valid(self) -> None:
        """Genesis block should pass validation."""
        ...

    def test_invalid_prev_hash_rejected(self) -> None:
        """Block with wrong prev_block_hash should fail."""
        ...


class TestTransactionValidation:
    def test_coinbase_valid(self) -> None:
        """A valid coinbase transaction should pass."""
        ...

    def test_missing_input_rejected(self) -> None:
        """Transaction referencing non-existent UTXO should fail."""
        ...
