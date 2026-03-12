"""Tests for P2SH script handling."""

from bitcoin_script.script_types.p2sh import create_script_pubkey, deserialize_redeem_script, extract_script_hash


class TestP2SH:
    def test_extract_script_hash(self) -> None:
        """Should extract the 20-byte hash from a P2SH scriptPubKey."""
        ...

    def test_create_script_pubkey(self) -> None:
        """Should create a valid P2SH scriptPubKey from a hash."""
        ...

    def test_deserialize_redeem_script(self) -> None:
        """Should extract the redeem script from a P2SH scriptSig."""
        ...
