"""Tests for P2PKH script handling."""

from bitcoin_script.script_types.p2pkh import create_script_pubkey, create_script_sig, extract_pubkey_hash


class TestP2PKH:
    def test_extract_pubkey_hash(self) -> None:
        """Should extract the 20-byte hash from a P2PKH scriptPubKey."""
        ...

    def test_create_script_pubkey(self) -> None:
        """Should create a valid P2PKH scriptPubKey from a hash."""
        ...

    def test_create_script_sig(self) -> None:
        """Should create a valid P2PKH scriptSig from sig and pubkey."""
        ...

    def test_roundtrip(self) -> None:
        """Create then extract should return the original hash."""
        ...
