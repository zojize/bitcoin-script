"""Tests for signature hash computation."""

from bitcoin_script.model.sighash import SigHashType, sighash_legacy, sighash_segwit_v0


class TestSigHashType:
    def test_all_flag_values(self) -> None:
        """ALL, NONE, SINGLE, ANYONECANPAY should have correct values."""
        ...

    def test_anyonecanpay_combined(self) -> None:
        """ANYONECANPAY should combine with other flags via OR."""
        ...


class TestSighashLegacy:
    def test_sighash_all_known_vector(self) -> None:
        """Verify against a known SIGHASH_ALL test vector."""
        ...

    def test_sighash_single_bug(self) -> None:
        """When input_index >= len(outputs), should return 1 + 31 zero bytes."""
        ...


class TestSighashSegwitV0:
    def test_bip143_test_vector(self) -> None:
        """Verify against the BIP143 test vectors."""
        ...
