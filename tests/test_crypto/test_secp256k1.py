"""Tests for ECDSA signature verification."""

from bitcoin_script.crypto.secp256k1 import verify_ecdsa


class TestVerifyECDSA:
    def test_valid_signature(self) -> None:
        """A valid ECDSA signature should return True."""
        ...

    def test_invalid_signature(self) -> None:
        """An invalid signature should return False."""
        ...

    def test_wrong_pubkey(self) -> None:
        """A valid signature with wrong pubkey should return False."""
        ...

    def test_compressed_pubkey(self) -> None:
        """Should accept 33-byte compressed public keys."""
        ...

    def test_uncompressed_pubkey(self) -> None:
        """Should accept 65-byte uncompressed public keys."""
        ...
