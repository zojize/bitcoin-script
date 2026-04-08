"""Tests for bare multisig script handling."""

from __future__ import annotations

import pytest
from bitcoin.core.script import CScript

from bitcoin_script.script_types.multisig import (
    create_script_pubkey,
    create_script_sig,
    extract_pubkeys,
)

PK1 = b"\x02" + b"\x11" * 32
PK2 = b"\x02" + b"\x22" * 32
PK3 = b"\x02" + b"\x33" * 32


class TestMultisig:
    def test_extract_pubkeys_1of1(self) -> None:
        """Should extract m=1 and one pubkey from a 1-of-1 script."""
        script = create_script_pubkey(1, [PK1])
        m, pubkeys = extract_pubkeys(script)
        assert m == 1
        assert pubkeys == [PK1]

    def test_extract_pubkeys_2of3(self) -> None:
        """Should extract m=2 and three pubkeys from a 2-of-3 script."""
        script = create_script_pubkey(2, [PK1, PK2, PK3])
        m, pubkeys = extract_pubkeys(script)
        assert m == 2
        assert pubkeys == [PK1, PK2, PK3]

    def test_create_script_pubkey_structure(self) -> None:
        """Should produce correct byte structure for 1-of-2 multisig."""
        script = create_script_pubkey(1, [PK1, PK2])
        raw = bytes(script)
        assert raw[0] == 0x51  # OP_1
        assert raw[1] == 0x21  # PUSH 33
        assert raw[2:35] == PK1
        assert raw[35] == 0x21  # PUSH 33
        assert raw[36:69] == PK2
        assert raw[69] == 0x52  # OP_2
        assert raw[70] == 0xAE  # OP_CHECKMULTISIG

    def test_create_script_sig(self) -> None:
        """Should create scriptSig with OP_0 dummy followed by signatures."""
        sig1 = b"\x30" + b"\x44" * 70 + b"\x01"
        sig2 = b"\x30" + b"\x44" * 71 + b"\x01"
        script = create_script_sig([sig1, sig2])
        raw = bytes(script)
        assert raw[0] == 0x00  # OP_0 dummy

    def test_roundtrip_2of3(self) -> None:
        """Create then extract should return original m and pubkeys."""
        m, pubkeys = extract_pubkeys(create_script_pubkey(2, [PK1, PK2, PK3]))
        assert m == 2
        assert pubkeys == [PK1, PK2, PK3]

    def test_extract_invalid_raises(self) -> None:
        """Non-multisig script should raise ValueError."""
        with pytest.raises(ValueError):
            extract_pubkeys(CScript(b"\x00" * 10))

    def test_create_m_exceeds_n_raises(self) -> None:
        """m greater than n should raise ValueError."""
        with pytest.raises(ValueError):
            create_script_pubkey(3, [PK1, PK2])

    def test_create_invalid_pubkey_length_raises(self) -> None:
        """Wrong-length pubkey should raise ValueError."""
        with pytest.raises(ValueError):
            create_script_pubkey(1, [b"\x02" * 32])
