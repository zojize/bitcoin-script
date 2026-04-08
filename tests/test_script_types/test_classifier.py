"""Tests for script type classification."""

from __future__ import annotations

from bitcoin.core.script import CScript

from bitcoin_script.script_types.classifier import ScriptType, classify


class TestClassifier:
    def test_classify_p2pkh(self) -> None:
        """Should identify P2PKH scripts."""
        # OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        script = CScript(b"\x76\xa9\x14" + b"\xab" * 20 + b"\x88\xac")
        assert classify(script) == ScriptType.P2PKH

    def test_classify_p2sh(self) -> None:
        """Should identify P2SH scripts."""
        # OP_HASH160 <20 bytes> OP_EQUAL
        script = CScript(b"\xa9\x14" + b"\xcd" * 20 + b"\x87")
        assert classify(script) == ScriptType.P2SH

    def test_classify_p2wpkh(self) -> None:
        """Should identify P2WPKH scripts."""
        # OP_0 <20 bytes>
        script = CScript(b"\x00\x14" + b"\x11" * 20)
        assert classify(script) == ScriptType.P2WPKH

    def test_classify_p2wsh(self) -> None:
        """Should identify P2WSH scripts."""
        # OP_0 <32 bytes>
        script = CScript(b"\x00\x20" + b"\x22" * 32)
        assert classify(script) == ScriptType.P2WSH

    def test_classify_null_data(self) -> None:
        """Should identify OP_RETURN scripts."""
        script = CScript(b"\x6a\x04data")
        assert classify(script) == ScriptType.NULL_DATA

    def test_classify_nonstandard(self) -> None:
        """Unrecognized scripts should be NONSTANDARD."""
        script = CScript(b"\x51\x52\x93")  # OP_1 OP_2 OP_ADD
        assert classify(script) == ScriptType.NONSTANDARD

    def test_classify_p2pk_compressed(self) -> None:
        """Should identify compressed-key P2PK scripts."""
        script = CScript(b"\x21" + b"\x02" + b"\xab" * 32 + b"\xac")
        assert classify(script) == ScriptType.P2PK