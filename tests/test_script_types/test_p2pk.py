"""Tests for P2PK script handling."""

from __future__ import annotations

import pytest
from bitcoin.core.script import CScript

from bitcoin_script.script_types.p2pk import (
    create_script_pubkey,
    create_script_sig,
    extract_pubkey,
)

COMPRESSED_PUBKEY = b"\x02" + b"\xab" * 32
UNCOMPRESSED_PUBKEY = b"\x04" + b"\xcd" * 64


class TestP2PK:
    def test_extract_pubkey_compressed(self) -> None:
        """Should extract a 33-byte compressed public key."""
        script = create_script_pubkey(COMPRESSED_PUBKEY)
        assert extract_pubkey(script) == COMPRESSED_PUBKEY

    def test_extract_pubkey_uncompressed(self) -> None:
        """Should extract a 65-byte uncompressed public key."""
        script = create_script_pubkey(UNCOMPRESSED_PUBKEY)
        assert extract_pubkey(script) == UNCOMPRESSED_PUBKEY

    def test_create_script_pubkey_compressed(self) -> None:
        """Should create a valid P2PK scriptPubKey for a compressed key."""
        script = create_script_pubkey(COMPRESSED_PUBKEY)
        raw = bytes(script)
        assert len(raw) == 35
        assert raw[0] == 0x21  # PUSH 33
        assert raw[1:34] == COMPRESSED_PUBKEY
        assert raw[34] == 0xAC  # OP_CHECKSIG

    def test_create_script_pubkey_uncompressed(self) -> None:
        """Should create a valid P2PK scriptPubKey for an uncompressed key."""
        script = create_script_pubkey(UNCOMPRESSED_PUBKEY)
        raw = bytes(script)
        assert len(raw) == 67
        assert raw[0] == 0x41  # PUSH 65
        assert raw[1:66] == UNCOMPRESSED_PUBKEY
        assert raw[66] == 0xAC  # OP_CHECKSIG

    def test_create_script_sig(self) -> None:
        """Should create a scriptSig containing just the signature."""
        sig = b"\x30" + b"\x44" * 70 + b"\x01"
        script = create_script_sig(sig)
        pushes = list(script)
        assert pushes[0] == sig

    def test_roundtrip_compressed(self) -> None:
        """Create then extract should return the original compressed key."""
        assert (
            extract_pubkey(create_script_pubkey(COMPRESSED_PUBKEY)) == COMPRESSED_PUBKEY
        )

    def test_roundtrip_uncompressed(self) -> None:
        """Create then extract should return the original uncompressed key."""
        assert (
            extract_pubkey(create_script_pubkey(UNCOMPRESSED_PUBKEY))
            == UNCOMPRESSED_PUBKEY
        )

    def test_extract_invalid_raises(self) -> None:
        """Non-P2PK script should raise ValueError."""
        with pytest.raises(ValueError):
            extract_pubkey(CScript(b"\x00" * 35))

    def test_create_wrong_length_raises(self) -> None:
        """Wrong-length pubkey should raise ValueError."""
        with pytest.raises(ValueError):
            create_script_pubkey(b"\x02" * 32)
