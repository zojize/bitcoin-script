"""Tests for Bitcoin Script crypto opcodes implemented in K Framework."""

from __future__ import annotations

import hashlib

import pytest
from ecdsa import SECP256k1, SigningKey
from ecdsa.util import sigencode_der

from bitcoin_script.k_semantics import KBitcoinScript
from .script_helpers import script, push

pytestmark = pytest.mark.k


# --- Test helpers ---


def _hash160(data: bytes) -> bytes:
    """RIPEMD160(SHA256(data)) — the same as OP_HASH160."""
    sha = hashlib.sha256(data).digest()
    return hashlib.new("ripemd160", sha).digest()


def _sign_der(privkey: bytes, msg_hash: bytes) -> bytes:
    """Sign a 32-byte message hash. Returns DER-encoded sig + SIGHASH_ALL byte."""
    sk = SigningKey.from_string(privkey, curve=SECP256k1)
    sig_der = sk.sign_digest(msg_hash, sigencode=sigencode_der)
    return sig_der + b"\x01"  # append SIGHASH_ALL


# Precomputed values for private key = 1
PRIVKEY = bytes.fromhex(
    "0000000000000000000000000000000000000000000000000000000000000001"
)
# G point on secp256k1 (uncompressed, 04 || x || y)
PUBKEY_65 = bytes.fromhex(
    "04"
    "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
)
PUBKEY_HEX = PUBKEY_65.hex()
PUBKEY_HASH = _hash160(PUBKEY_65)
PUBKEY_HASH_HEX = PUBKEY_HASH.hex()

# Test data hex constants
HEX_65 = "04" + "ab" * 64  # 130 hex chars = 65 bytes
HEX_33 = "02" + "cd" * 32  # 66 hex chars = 33 bytes
HEX_20 = "ef" * 20  # 40 hex chars = 20 bytes


class TestOpPushBytes20:
    def test_push_valid_20_bytes(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script(push(HEX_20)))
        assert not k.is_stuck(result)
        stack = k.stack(result)
        assert len(stack) == 1
        assert stack[0] == bytes.fromhex(HEX_20)


class TestOpPushBytes33:
    def test_push_valid_33_bytes(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script(push(HEX_33)))
        assert not k.is_stuck(result)
        stack = k.stack(result)
        assert len(stack) == 1
        assert stack[0] == bytes.fromhex(HEX_33)


class TestOpPushBytes65:
    def test_push_valid_65_bytes(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script(push(HEX_65)))
        assert not k.is_stuck(result)
        stack = k.stack(result)
        assert len(stack) == 1
        assert stack[0] == bytes.fromhex(HEX_65)


class TestOpHash160:
    def test_hash160_known_value(self, k: KBitcoinScript) -> None:
        """OP_HASH160 of the secp256k1 generator point pubkey."""
        result = k.verify_script(
            script_pubkey=script(push(PUBKEY_HEX), "OP_HASH160"),
        )
        assert not k.is_stuck(result)
        stack = k.stack(result)
        assert len(stack) == 1
        assert stack[0] == PUBKEY_HASH

    def test_hash160_empty_stack_stuck(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_HASH160"))
        assert k.is_stuck(result)


class TestOpEqualVerify:
    def test_equal_bytes(self, k: KBitcoinScript) -> None:
        """Two identical byte pushes should pass EQUALVERIFY."""
        result = k.verify_script(
            script_pubkey=script(push(HEX_20), push(HEX_20), "OP_EQUALVERIFY"),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == []  # both consumed

    def test_unequal_stuck(self, k: KBitcoinScript) -> None:
        """Different values should cause EQUALVERIFY to get stuck."""
        hex_a = "aa" * 20
        hex_b = "bb" * 20
        result = k.verify_script(
            script_pubkey=script(push(hex_a), push(hex_b), "OP_EQUALVERIFY"),
        )
        assert k.is_stuck(result)

    def test_insufficient_stack_stuck(self, k: KBitcoinScript) -> None:
        result = k.verify_script(
            script_pubkey=script(push(HEX_20), "OP_EQUALVERIFY"),
        )
        assert k.is_stuck(result)


class TestOpCheckSig:
    def test_checksig_valid_signature(self, k: KBitcoinScript) -> None:
        """Test OP_CHECKSIG with a real ECDSA signature (DER-encoded)."""
        msg_hash = hashlib.sha256(b"test message").digest()
        sig = _sign_der(PRIVKEY, msg_hash)

        # scriptSig: <sig> <pubkey>, scriptPubKey: OP_CHECKSIG
        result = k.verify_script(
            script_sig=script(push(sig.hex()), push(PUBKEY_HEX)),
            script_pubkey=script("OP_CHECKSIG"),
            sighash=msg_hash,
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01"]

    def test_checksig_wrong_pubkey_pushes_0(self, k: KBitcoinScript) -> None:
        """OP_CHECKSIG with wrong pubkey should push 0."""
        msg_hash = hashlib.sha256(b"test message").digest()
        sig = _sign_der(PRIVKEY, msg_hash)
        wrong_pubkey = "04" + "ff" * 64

        result = k.verify_script(
            script_sig=script(push(sig.hex()), push(wrong_pubkey)),
            script_pubkey=script("OP_CHECKSIG"),
            sighash=msg_hash,
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b""]

    def test_checksig_insufficient_stack_stuck(self, k: KBitcoinScript) -> None:
        result = k.verify_script(
            script_sig=script(push(HEX_65)),
            script_pubkey=script("OP_CHECKSIG"),
        )
        assert k.is_stuck(result)


class TestP2PKH:
    """Integration test: a full P2PKH script execution."""

    def test_p2pkh_success(self, k: KBitcoinScript) -> None:
        """scriptSig: <sig> <pubkey>, scriptPubKey: OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG"""
        msg_hash = hashlib.sha256(b"p2pkh test tx").digest()
        sig = _sign_der(PRIVKEY, msg_hash)

        result = k.verify_script(
            script_sig=script(push(sig.hex()), push(PUBKEY_HEX)),
            script_pubkey=script(
                "OP_DUP",
                "OP_HASH160",
                push(PUBKEY_HASH_HEX),
                "OP_EQUALVERIFY",
                "OP_CHECKSIG",
            ),
            sighash=msg_hash,
        )
        assert not k.is_stuck(result)
        assert k.success(result)
        assert k.stack(result) == [b"\x01"]

    def test_p2pkh_wrong_pubkey(self, k: KBitcoinScript) -> None:
        """P2PKH with wrong pubkey: EQUALVERIFY should get stuck."""
        msg_hash = hashlib.sha256(b"p2pkh test tx").digest()
        sig = _sign_der(PRIVKEY, msg_hash)
        wrong_pubkey = "04" + "aa" * 64

        result = k.verify_script(
            script_sig=script(push(sig.hex()), push(wrong_pubkey)),
            script_pubkey=script(
                "OP_DUP",
                "OP_HASH160",
                push(PUBKEY_HASH_HEX),
                "OP_EQUALVERIFY",
                "OP_CHECKSIG",
            ),
            sighash=msg_hash,
        )
        assert k.is_stuck(result)
        assert not k.success(result)
