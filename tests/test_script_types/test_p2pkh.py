"""Tests for P2PKH script handling."""

from __future__ import annotations

import pytest

from bitcoin_script.script_types.p2pkh import (
    create_script_pubkey,
    create_script_sig,
    extract_pubkey_hash,
)


class TestP2PKH:
    def test_extract_pubkey_hash(self) -> None:
        """Should extract the 20-byte hash from a P2PKH scriptPubKey."""
        pubkey_hash = bytes(range(20))
        script = create_script_pubkey(pubkey_hash)
        assert extract_pubkey_hash(script) == pubkey_hash

    def test_create_script_pubkey(self) -> None:
        """Should create a valid P2PKH scriptPubKey from a hash."""
        pubkey_hash = b"\xab" * 20
        script = create_script_pubkey(pubkey_hash)
        raw = bytes(script)
        assert len(raw) == 25
        assert raw[0] == 0x76  # OP_DUP
        assert raw[1] == 0xA9  # OP_HASH160
        assert raw[2] == 0x14  # PUSH 20
        assert raw[3:23] == pubkey_hash
        assert raw[23] == 0x88  # OP_EQUALVERIFY
        assert raw[24] == 0xAC  # OP_CHECKSIG

    def test_create_script_sig(self) -> None:
        """Should create a valid P2PKH scriptSig from sig and pubkey."""
        sig = b"\x30" + b"\x44" * 70 + b"\x01"
        pubkey = b"\x02" + b"\xab" * 32
        script = create_script_sig(sig, pubkey)
        pushes = list(script)
        assert pushes[0] == sig
        assert pushes[1] == pubkey

    def test_roundtrip(self) -> None:
        """Create then extract should return the original hash."""
        pubkey_hash = bytes(range(20))
        assert extract_pubkey_hash(create_script_pubkey(pubkey_hash)) == pubkey_hash

    def test_extract_invalid_raises(self) -> None:
        """Non-P2PKH script should raise ValueError."""
        from bitcoin.core.script import CScript

        with pytest.raises(ValueError):
            extract_pubkey_hash(CScript(b"\x00" * 25))

    def test_create_wrong_length_raises(self) -> None:
        """Wrong-length hash should raise ValueError."""
        with pytest.raises(ValueError):
            create_script_pubkey(b"\xab" * 19)
