"""Tests for Bitcoin Script basic opcodes implemented in K Framework."""

from __future__ import annotations

import hashlib

import pytest
from ecdsa import SECP256k1, SigningKey
from ecdsa.util import sigencode_der

from bitcoin_script.k_semantics import KBitcoinScript

pytestmark = pytest.mark.k


@pytest.fixture(scope="session")
def k() -> KBitcoinScript:
    return KBitcoinScript()


HEX_65 = "04" + "ab" * 64  # 130 hex chars = 65 bytes


class TestOpPush:
    def test_push_integer(self, k: KBitcoinScript) -> None:
        result = k.run(k.pattern("OP_PUSH 5"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x05"]

    def test_push_two_integers(self, k: KBitcoinScript) -> None:
        result = k.run(k.pattern("OP_PUSH 3 OP_PUSH 4"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x04", b"\x03"]


class TestOpDup:
    def test_dup_integer(self, k: KBitcoinScript) -> None:
        result = k.run(k.pattern("OP_PUSH 5 OP_DUP"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x05", b"\x05"]

    def test_dup_empty_stack_stuck(self, k: KBitcoinScript) -> None:
        result = k.run(k.pattern("OP_DUP"))
        assert k.is_stuck(result)


class TestOpAdd:
    def test_add_two_integers(self, k: KBitcoinScript) -> None:
        result = k.run(k.pattern("OP_PUSH 3 OP_PUSH 4 OP_ADD"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x07"]

    def test_dup_then_add(self, k: KBitcoinScript) -> None:
        result = k.run(k.pattern("OP_PUSH 5 OP_DUP OP_ADD"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x0a"]

    def test_add_insufficient_operands_stuck(self, k: KBitcoinScript) -> None:
        result = k.run(k.pattern("OP_PUSH 5 OP_ADD"))
        assert k.is_stuck(result)


class TestOpPushBytes65:
    def test_push_valid_65_bytes(self, k: KBitcoinScript) -> None:
        result = k.run(k.pattern(f"OP_PUSHBYTES_65 {HEX_65}"))
        assert not k.is_stuck(result)
        stack = k.stack(result)
        assert len(stack) == 1
        assert stack[0] == bytes.fromhex(HEX_65)

    def test_push_wrong_length_stuck(self, k: KBitcoinScript) -> None:
        hex_32 = "ab" * 32  # 64 hex chars, not 130
        result = k.run(k.pattern(f"OP_PUSHBYTES_65 {hex_32}"))
        assert k.is_stuck(result)


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
        script = (
            f"OP_PUSHBYTES_32 {msg_hash.hex()} "
            f"OP_PUSHBYTES_{len(sig)} {sig.hex()} "
            f"OP_PUSHBYTES_65 {self.PUBKEY_HEX} "
            f"OP_CHECKSIG"
        )
        result = k.run(k.pattern(script))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01"]

    def test_checksig_insufficient_stack_stuck(self, k: KBitcoinScript) -> None:
        result = k.run(k.pattern(f"OP_PUSHBYTES_65 {HEX_65} OP_CHECKSIG"))
        assert k.is_stuck(result)


class TestIntegration:
    def test_push_dup_add_chain(self, k: KBitcoinScript) -> None:
        """OP_PUSH 3 OP_DUP OP_DUP OP_ADD OP_ADD => 3 + 3 + 3 = 9"""
        result = k.run(k.pattern("OP_PUSH 3 OP_DUP OP_DUP OP_ADD OP_ADD"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x09"]

    def test_success_truthy(self, k: KBitcoinScript) -> None:
        result = k.run(k.pattern("OP_PUSH 1"))
        assert k.success(result)

    def test_success_falsy_empty_stack(self, k: KBitcoinScript) -> None:
        """Stuck execution is not successful."""
        result = k.run(k.pattern("OP_DUP"))
        assert not k.success(result)
