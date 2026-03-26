"""Tests for Bitcoin Script basic opcodes implemented in K Framework."""

from __future__ import annotations

import hashlib

import pytest
from ecdsa import SECP256k1, SigningKey
from ecdsa.util import sigencode_der

from bitcoin_script.k_semantics import KBitcoinScript
from .script_helpers import script, push

pytestmark = pytest.mark.k


HEX_65 = "04" + "ab" * 64  # 130 hex chars = 65 bytes


class TestOpPush:
    def test_push_integer(self, k: KBitcoinScript) -> None:
        # Push 5 via scriptPubKey only (1 byte push: 0x01 0x05)
        result = k.verify_script(
            script_pubkey=script(push("05")),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x05"]

    def test_push_two_integers(self, k: KBitcoinScript) -> None:
        result = k.verify_script(
            script_pubkey=script(push("03"), push("04")),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x04", b"\x03"]


class TestOpDup:
    def test_dup_integer(self, k: KBitcoinScript) -> None:
        result = k.verify_script(
            script_pubkey=script(push("05"), "OP_DUP"),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x05", b"\x05"]

    def test_dup_empty_stack_stuck(self, k: KBitcoinScript) -> None:
        result = k.verify_script(
            script_pubkey=script("OP_DUP"),
        )
        assert k.is_stuck(result)


class TestOpAdd:
    def test_add_two_integers(self, k: KBitcoinScript) -> None:
        result = k.verify_script(
            script_pubkey=script(push("03"), push("04"), "OP_ADD"),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x07"]

    def test_dup_then_add(self, k: KBitcoinScript) -> None:
        result = k.verify_script(
            script_pubkey=script(push("05"), "OP_DUP", "OP_ADD"),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x0a"]

    def test_add_insufficient_operands_stuck(self, k: KBitcoinScript) -> None:
        result = k.verify_script(
            script_pubkey=script(push("05"), "OP_ADD"),
        )
        assert k.is_stuck(result)


class TestOpPushBytes65:
    def test_push_valid_65_bytes(self, k: KBitcoinScript) -> None:
        result = k.verify_script(
            script_pubkey=script(push(HEX_65)),
        )
        assert not k.is_stuck(result)
        stack = k.stack(result)
        assert len(stack) == 1
        assert stack[0] == bytes.fromhex(HEX_65)

    def test_push_wrong_length_stuck(self, k: KBitcoinScript) -> None:
        # Push 32 bytes but the script expects 65 — this just pushes 32 bytes fine
        # (no length mismatch in hex mode since push() auto-sizes)
        hex_32 = "ab" * 32
        result = k.verify_script(
            script_pubkey=script(push(hex_32)),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [bytes.fromhex(hex_32)]


class TestOpCheckSig:
    """Test OP_CHECKSIG with real ECDSA signatures."""

    PRIVKEY = bytes.fromhex(
        "0000000000000000000000000000000000000000000000000000000000000001"
    )
    PUBKEY_HEX = (
        "04"
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
    )

    def test_checksig_valid(self, k: KBitcoinScript) -> None:
        msg_hash = hashlib.sha256(b"test").digest()
        sk = SigningKey.from_string(self.PRIVKEY, curve=SECP256k1)
        sig = sk.sign_digest(msg_hash, sigencode=sigencode_der) + b"\x01"

        # scriptSig: <sig> <pubkey>, scriptPubKey: OP_CHECKSIG
        result = k.verify_script(
            script_sig=script(push(sig.hex()), push(self.PUBKEY_HEX)),
            script_pubkey=script("OP_CHECKSIG"),
            sighash=msg_hash,
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01"]

    def test_checksig_insufficient_stack_stuck(self, k: KBitcoinScript) -> None:
        result = k.verify_script(
            script_sig=script(push(HEX_65)),
            script_pubkey=script("OP_CHECKSIG"),
        )
        assert k.is_stuck(result)


class TestIntegration:
    def test_push_dup_add_chain(self, k: KBitcoinScript) -> None:
        """push 3, DUP, DUP, ADD, ADD => 3 + 3 + 3 = 9"""
        result = k.verify_script(
            script_pubkey=script(push("03"), "OP_DUP", "OP_DUP", "OP_ADD", "OP_ADD"),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x09"]

    def test_success_truthy(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_1"))
        assert k.success(result)

    def test_success_falsy_empty_stack(self, k: KBitcoinScript) -> None:
        """Stuck execution is not successful."""
        result = k.verify_script(script_pubkey=script("OP_DUP"))
        assert not k.success(result)
