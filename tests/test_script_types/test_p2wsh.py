"""Tests for P2WSH script handling."""

from bitcoin_script.script_types.p2wsh import create_script_pubkey, extract_script_hash, extract_witness_script


class TestP2WSH:
    def test_extract_script_hash(self) -> None:
        """Should extract the 32-byte hash from a P2WSH scriptPubKey."""
        ...

    def test_create_script_pubkey(self) -> None:
        """Should create a valid P2WSH scriptPubKey."""
        ...

    def test_extract_witness_script(self) -> None:
        """Should extract the witness script from the witness stack."""
        ...
