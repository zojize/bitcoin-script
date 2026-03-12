"""Tests for P2WPKH script handling."""

from bitcoin_script.script_types.p2wpkh import create_script_pubkey, extract_pubkey_hash, witness_to_script_code


class TestP2WPKH:
    def test_extract_pubkey_hash(self) -> None:
        """Should extract the 20-byte hash from a P2WPKH scriptPubKey."""
        ...

    def test_create_script_pubkey(self) -> None:
        """Should create a valid P2WPKH scriptPubKey."""
        ...

    def test_witness_to_script_code(self) -> None:
        """Script code should be equivalent to P2PKH scriptPubKey."""
        ...
