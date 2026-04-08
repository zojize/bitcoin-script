"""Tests for P2SH script handling."""

from __future__ import annotations

import pytest
from bitcoin.core.script import CScript

from bitcoin_script.script_types.p2sh import (
    create_script_pubkey,
    deserialize_redeem_script,
    extract_script_hash,
)


class TestP2SH:
    def test_extract_script_hash(self) -> None:
        """Should extract the 20-byte hash from a P2SH scriptPubKey."""
        script_hash = bytes(range(20))
        script = create_script_pubkey(script_hash)
        assert extract_script_hash(script) == script_hash

    def test_create_script_pubkey(self) -> None:
        """Should create a valid P2SH scriptPubKey from a hash."""
        script_hash = b"\xcd" * 20
        script = create_script_pubkey(script_hash)
        raw = bytes(script)
        assert len(raw) == 23
        assert raw[0] == 0xA9  # OP_HASH160
        assert raw[1] == 0x14  # PUSH 20
        assert raw[2:22] == script_hash
        assert raw[22] == 0x87  # OP_EQUAL

    def test_deserialize_redeem_script(self) -> None:
        """Should extract the redeem script from a P2SH scriptSig."""
        redeem = b"\x51\xae"  # OP_1 OP_CHECKMULTISIG
        sig = b"\x30" + b"\x44" * 70 + b"\x01"
        script_sig = CScript([sig, redeem])  # type: ignore[arg-type]
        extracted = deserialize_redeem_script(script_sig)
        assert bytes(extracted) == redeem

    def test_roundtrip(self) -> None:
        """Create then extract should return the original hash."""
        script_hash = bytes(range(20))
        assert extract_script_hash(create_script_pubkey(script_hash)) == script_hash

    def test_extract_invalid_raises(self) -> None:
        """Non-P2SH script should raise ValueError."""
        with pytest.raises(ValueError):
            extract_script_hash(CScript(b"\x00" * 23))

    def test_create_wrong_length_raises(self) -> None:
        """Wrong-length hash should raise ValueError."""
        with pytest.raises(ValueError):
            create_script_pubkey(b"\xcd" * 21)

    def test_deserialize_empty_raises(self) -> None:
        """Empty scriptSig should raise ValueError."""
        with pytest.raises(ValueError):
            deserialize_redeem_script(CScript(b""))
