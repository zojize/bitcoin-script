"""Tests for P2TR script handling."""

from __future__ import annotations

import pytest
from bitcoin.core.script import CScript

from bitcoin_script.script_types.p2tr import (
    create_script_pubkey,
    extract_pubkey,
)

TWEAKED_PUBKEY = b"\xab" * 32


class TestP2TR:
    def test_extract_pubkey(self) -> None:
        """Should extract the 32-byte x-only key from a P2TR scriptPubKey."""
        script = create_script_pubkey(TWEAKED_PUBKEY)
        assert extract_pubkey(script) == TWEAKED_PUBKEY

    def test_create_script_pubkey(self) -> None:
        """Should create a valid P2TR scriptPubKey."""
        script = create_script_pubkey(TWEAKED_PUBKEY)
        raw = bytes(script)
        assert len(raw) == 34
        assert raw[0] == 0x51  # OP_1
        assert raw[1] == 0x20  # PUSH 32
        assert raw[2:] == TWEAKED_PUBKEY

    def test_roundtrip(self) -> None:
        """Create then extract should return the original key."""
        assert extract_pubkey(create_script_pubkey(TWEAKED_PUBKEY)) == TWEAKED_PUBKEY

    def test_extract_invalid_raises(self) -> None:
        """Non-P2TR script should raise ValueError."""
        with pytest.raises(ValueError):
            extract_pubkey(CScript(b"\x00" * 34))

    def test_create_wrong_length_raises(self) -> None:
        """Wrong-length key should raise ValueError."""
        with pytest.raises(ValueError):
            create_script_pubkey(b"\xab" * 31)
