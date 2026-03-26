"""Tests for hex script decoding and OP_EQUAL in K Framework semantics.

Tests that raw hex byte scripts are correctly decoded and executed,
covering pushdata (0x01-0x4b), simple opcodes, and OP_EQUAL for P2SH support.
"""

from __future__ import annotations

import hashlib

import pytest
from ecdsa import SECP256k1, SigningKey
from ecdsa.util import sigencode_der

from bitcoin_script.k_semantics import KBitcoinScript
from .script_helpers import script, push

pytestmark = pytest.mark.k


class TestHexDecodeSimple:
    """Test basic hex decoding of simple opcodes."""

    def test_op_1(self, k: KBitcoinScript) -> None:
        """0x51 = OP_1 -> pushes 1."""
        result = k.verify_script(script_pubkey=script("OP_1"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01"]

    def test_op_2(self, k: KBitcoinScript) -> None:
        """0x52 = OP_2 -> pushes 2."""
        result = k.verify_script(script_pubkey=script("OP_2"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x02"]

    def test_op_16(self, k: KBitcoinScript) -> None:
        """0x60 = OP_16 -> pushes 16."""
        result = k.verify_script(script_pubkey=script("OP_16"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x10"]

    def test_op_dup_add(self, k: KBitcoinScript) -> None:
        """OP_1 OP_DUP OP_ADD -> 1 + 1 = 2."""
        result = k.verify_script(
            script_pubkey=script("OP_1", "OP_DUP", "OP_ADD"),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x02"]


class TestHexDecodePushBytes:
    """Test hex decoding of pushdata opcodes (0x01-0x4b)."""

    def test_pushbytes_1(self, k: KBitcoinScript) -> None:
        """Push 1 byte: 0xff."""
        result = k.verify_script(script_pubkey=script(push("ff")))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\xff"]

    def test_pushbytes_2(self, k: KBitcoinScript) -> None:
        """Push 2 bytes: 0xabcd."""
        result = k.verify_script(script_pubkey=script(push("abcd")))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\xab\xcd"]

    def test_pushbytes_20(self, k: KBitcoinScript) -> None:
        """Push 20 bytes."""
        data = "ef" * 20
        result = k.verify_script(script_pubkey=script(push(data)))
        assert not k.is_stuck(result)
        assert k.stack(result) == [bytes.fromhex(data)]

    def test_pushbytes_32(self, k: KBitcoinScript) -> None:
        """Push 32 bytes."""
        data = "ab" * 32
        result = k.verify_script(script_pubkey=script(push(data)))
        assert not k.is_stuck(result)
        assert k.stack(result) == [bytes.fromhex(data)]

    def test_pushbytes_75(self, k: KBitcoinScript) -> None:
        """Push 75 bytes (max single-byte push)."""
        data = "cd" * 75
        result = k.verify_script(script_pubkey=script(push(data)))
        assert not k.is_stuck(result)
        assert k.stack(result) == [bytes.fromhex(data)]

    def test_multiple_pushes(self, k: KBitcoinScript) -> None:
        """Two pushes in sequence."""
        result = k.verify_script(
            script_pubkey=script(push("aabb"), push("ccddee")),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [bytes.fromhex("ccddee"), bytes.fromhex("aabb")]


class TestOpEqual:
    """Test OP_EQUAL (0x87) — pushes 1 if equal, 0 if not."""

    def test_equal_same_bytes(self, k: KBitcoinScript) -> None:
        """Two identical pushes followed by OP_EQUAL -> 1."""
        result = k.verify_script(
            script_pubkey=script(push("2a"), push("2a"), "OP_EQUAL"),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01"]

    def test_equal_different_bytes(self, k: KBitcoinScript) -> None:
        """Two different pushes followed by OP_EQUAL -> 0."""
        result = k.verify_script(
            script_pubkey=script(push("2a"), push("63"), "OP_EQUAL"),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b""]

    def test_equal_via_op_n(self, k: KBitcoinScript) -> None:
        """OP_1 OP_1 OP_EQUAL -> 1."""
        result = k.verify_script(
            script_pubkey=script("OP_1", "OP_1", "OP_EQUAL"),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01"]

    def test_not_equal_via_op_n(self, k: KBitcoinScript) -> None:
        """OP_1 OP_2 OP_EQUAL -> 0."""
        result = k.verify_script(
            script_pubkey=script("OP_1", "OP_2", "OP_EQUAL"),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b""]

    def test_equal_20_byte_hashes(self, k: KBitcoinScript) -> None:
        """Compare two 20-byte pushes with OP_EQUAL."""
        h = "aa" * 20
        result = k.verify_script(
            script_pubkey=script(push(h), push(h), "OP_EQUAL"),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01"]


class TestHexP2SHScriptPubKey:
    """Test P2SH scriptPubKey pattern: OP_HASH160 <20-byte-hash> OP_EQUAL.

    This tests the scriptPubKey portion of P2SH validation in hex format.
    The full P2SH flow (deserialize + execute redeem script) comes later.
    """

    def test_hash160_equal_passes(self, k: KBitcoinScript) -> None:
        """Push data, OP_HASH160, push expected hash, OP_EQUAL -> true."""
        pubkey_hex = (
            "04"
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
        )
        pubkey = bytes.fromhex(pubkey_hex)
        h160 = hashlib.new("ripemd160", hashlib.sha256(pubkey).digest()).digest()

        result = k.verify_script(
            script_pubkey=script(
                push(pubkey_hex),
                "OP_HASH160",
                push(h160.hex()),
                "OP_EQUAL",
            ),
        )
        assert not k.is_stuck(result)
        assert k.success(result)
        assert k.stack(result) == [b"\x01"]

    def test_hash160_equal_fails(self, k: KBitcoinScript) -> None:
        """Wrong hash -> OP_EQUAL pushes 0."""
        pubkey_hex = (
            "04"
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
        )
        wrong_hash = "00" * 20

        result = k.verify_script(
            script_pubkey=script(
                push(pubkey_hex),
                "OP_HASH160",
                push(wrong_hash),
                "OP_EQUAL",
            ),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b""]


class TestHexP2PKH:
    """Test a full P2PKH script in hex format."""

    def test_p2pkh_hex(self, k: KBitcoinScript) -> None:
        """Full P2PKH in hex with scriptSig/scriptPubKey separation."""
        privkey = (1).to_bytes(32, "big")
        sk = SigningKey.from_string(privkey, curve=SECP256k1)
        vk = sk.verifying_key
        assert vk is not None
        pubkey = b"\x04" + vk.to_string()
        msg_hash = hashlib.sha256(b"hex test").digest()
        sig = sk.sign_digest(msg_hash, sigencode=sigencode_der) + b"\x01"
        h160 = hashlib.new("ripemd160", hashlib.sha256(pubkey).digest()).digest()

        result = k.verify_script(
            script_sig=script(push(sig.hex()), push(pubkey.hex())),
            script_pubkey=script(
                "OP_DUP",
                "OP_HASH160",
                push(h160.hex()),
                "OP_EQUALVERIFY",
                "OP_CHECKSIG",
            ),
            sighash=msg_hash,
        )
        assert not k.is_stuck(result)
        assert k.success(result)
        assert k.stack(result) == [b"\x01"]
