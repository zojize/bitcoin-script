"""Tests for Bitcoin Script crypto opcodes implemented in K Framework."""

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


def _push_sig(sig: bytes) -> str:
    """Return the appropriate OP_PUSHBYTES_N for a DER sig."""
    return f"OP_PUSHBYTES_{len(sig)} {sig.hex()}"


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

# 65 bytes of "ab" for simple tests
HEX_65 = "04" + "ab" * 64  # 130 hex chars = 65 bytes
HEX_33 = "02" + "cd" * 32  # 66 hex chars = 33 bytes
HEX_20 = "ef" * 20  # 40 hex chars = 20 bytes


class TestOpPushBytes20:
    def test_push_valid_20_bytes(self, k: KBitcoinScript) -> None:
        result = k.run(k.pattern(f"OP_PUSHBYTES_20 {HEX_20}"))
        assert not k.is_stuck(result)
        stack = k.stack(result)
        assert len(stack) == 1
        assert stack[0] == bytes.fromhex(HEX_20)

    def test_push_wrong_length_stuck(self, k: KBitcoinScript) -> None:
        hex_10 = "ab" * 10  # 20 hex chars, not 40
        result = k.run(k.pattern(f"OP_PUSHBYTES_20 {hex_10}"))
        assert k.is_stuck(result)


class TestOpPushBytes33:
    def test_push_valid_33_bytes(self, k: KBitcoinScript) -> None:
        result = k.run(k.pattern(f"OP_PUSHBYTES_33 {HEX_33}"))
        assert not k.is_stuck(result)
        stack = k.stack(result)
        assert len(stack) == 1
        assert stack[0] == bytes.fromhex(HEX_33)

    def test_push_wrong_length_stuck(self, k: KBitcoinScript) -> None:
        hex_16 = "ab" * 16  # 32 hex chars, not 66
        result = k.run(k.pattern(f"OP_PUSHBYTES_33 {hex_16}"))
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


class TestOpHash160:
    def test_hash160_known_value(self, k: KBitcoinScript) -> None:
        """OP_HASH160 of the secp256k1 generator point pubkey."""
        result = k.run(k.pattern(f"OP_PUSHBYTES_65 {PUBKEY_HEX} OP_HASH160"))
        assert not k.is_stuck(result)
        stack = k.stack(result)
        assert len(stack) == 1
        # Compare with Python's hashlib computation
        assert stack[0] == PUBKEY_HASH

    def test_hash160_empty_stack_stuck(self, k: KBitcoinScript) -> None:
        result = k.run(k.pattern("OP_HASH160"))
        assert k.is_stuck(result)


class TestOpEqualVerify:
    def test_equal_bytes(self, k: KBitcoinScript) -> None:
        """Two identical byte pushes should pass EQUALVERIFY."""
        result = k.run(
            k.pattern(
                f"OP_PUSHBYTES_20 {HEX_20} OP_PUSHBYTES_20 {HEX_20} OP_EQUALVERIFY"
            )
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == []  # both consumed

    def test_equal_integers(self, k: KBitcoinScript) -> None:
        result = k.run(k.pattern("OP_PUSH 42 OP_PUSH 42 OP_EQUALVERIFY"))
        assert not k.is_stuck(result)
        assert k.stack(result) == []

    def test_unequal_stuck(self, k: KBitcoinScript) -> None:
        """Different values should cause EQUALVERIFY to get stuck."""
        hex_a = "aa" * 20
        hex_b = "bb" * 20
        result = k.run(
            k.pattern(
                f"OP_PUSHBYTES_20 {hex_a} OP_PUSHBYTES_20 {hex_b} OP_EQUALVERIFY"
            )
        )
        assert k.is_stuck(result)

    def test_insufficient_stack_stuck(self, k: KBitcoinScript) -> None:
        result = k.run(k.pattern(f"OP_PUSHBYTES_20 {HEX_20} OP_EQUALVERIFY"))
        assert k.is_stuck(result)


class TestOpCheckSig:
    def test_checksig_valid_signature(self, k: KBitcoinScript) -> None:
        """Test OP_CHECKSIG with a real ECDSA signature (DER-encoded)."""
        msg_hash = hashlib.sha256(b"test message").digest()
        sig = _sign_der(PRIVKEY, msg_hash)

        # Stack: <sighash> <sig> <pubkey> OP_CHECKSIG
        script = (
            f"OP_PUSHBYTES_32 {msg_hash.hex()} "
            f"{_push_sig(sig)} "
            f"OP_PUSHBYTES_65 {PUBKEY_HEX} "
            f"OP_CHECKSIG"
        )
        result = k.run(k.pattern(script))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01"]

    def test_checksig_wrong_pubkey_pushes_0(self, k: KBitcoinScript) -> None:
        """OP_CHECKSIG with wrong pubkey should push 0."""
        msg_hash = hashlib.sha256(b"test message").digest()
        sig = _sign_der(PRIVKEY, msg_hash)

        wrong_pubkey = "04" + "ff" * 64
        script = (
            f"OP_PUSHBYTES_32 {msg_hash.hex()} "
            f"{_push_sig(sig)} "
            f"OP_PUSHBYTES_65 {wrong_pubkey} "
            f"OP_CHECKSIG"
        )
        result = k.run(k.pattern(script))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b""]

    def test_checksig_insufficient_stack_stuck(self, k: KBitcoinScript) -> None:
        result = k.run(k.pattern(f"OP_PUSHBYTES_65 {HEX_65} OP_CHECKSIG"))
        assert k.is_stuck(result)


class TestP2PKH:
    """Integration test: a full P2PKH script execution."""

    def test_p2pkh_success(self, k: KBitcoinScript) -> None:
        """<sighash> <sig> <pubkey> OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG"""
        msg_hash = hashlib.sha256(b"p2pkh test tx").digest()
        sig = _sign_der(PRIVKEY, msg_hash)

        script = (
            f"OP_PUSHBYTES_32 {msg_hash.hex()} "  # push sighash
            f"{_push_sig(sig)} "  # push DER sig
            f"OP_PUSHBYTES_65 {PUBKEY_HEX} "  # push pubkey
            f"OP_DUP "  # duplicate pubkey
            f"OP_HASH160 "  # hash the duplicate
            f"OP_PUSHBYTES_20 {PUBKEY_HASH_HEX} "  # push expected hash
            f"OP_EQUALVERIFY "  # verify hashes match
            f"OP_CHECKSIG"  # verify signature
        )
        result = k.run(k.pattern(script))
        assert not k.is_stuck(result)
        assert k.success(result)
        assert k.stack(result) == [b"\x01"]

    def test_p2pkh_wrong_pubkey(self, k: KBitcoinScript) -> None:
        """P2PKH with wrong pubkey: EQUALVERIFY should get stuck."""
        msg_hash = hashlib.sha256(b"p2pkh test tx").digest()
        sig = _sign_der(PRIVKEY, msg_hash)

        # Use a pubkey whose hash doesn't match PUBKEY_HASH_HEX
        wrong_pubkey = "04" + "aa" * 64
        script = (
            f"OP_PUSHBYTES_32 {msg_hash.hex()} "
            f"{_push_sig(sig)} "
            f"OP_PUSHBYTES_65 {wrong_pubkey} "
            f"OP_DUP "
            f"OP_HASH160 "
            f"OP_PUSHBYTES_20 {PUBKEY_HASH_HEX} "
            f"OP_EQUALVERIFY "
            f"OP_CHECKSIG"
        )
        result = k.run(k.pattern(script))
        # EQUALVERIFY will get stuck because hashes don't match
        assert k.is_stuck(result)
        assert not k.success(result)
