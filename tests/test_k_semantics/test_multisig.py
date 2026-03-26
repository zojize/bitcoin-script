"""Tests for OP_0..OP_16 and OP_CHECKMULTISIG in K Framework semantics."""

from __future__ import annotations

import hashlib

import pytest
from ecdsa import SECP256k1, SigningKey
from ecdsa.util import sigencode_der

from bitcoin_script.k_semantics import KBitcoinScript
from .script_helpers import script, push

pytestmark = pytest.mark.k


# --- Key material ---

PRIVKEY_1 = (1).to_bytes(32, "big")
PRIVKEY_2 = (2).to_bytes(32, "big")
PRIVKEY_3 = (3).to_bytes(32, "big")


def _pubkey_uncompressed(privkey: bytes) -> bytes:
    sk = SigningKey.from_string(privkey, curve=SECP256k1)
    vk = sk.verifying_key
    assert vk is not None
    return b"\x04" + vk.to_string()


PUBKEY_1 = _pubkey_uncompressed(PRIVKEY_1)
PUBKEY_2 = _pubkey_uncompressed(PRIVKEY_2)
PUBKEY_3 = _pubkey_uncompressed(PRIVKEY_3)


def _sign_der(privkey: bytes, msg_hash: bytes) -> bytes:
    sk = SigningKey.from_string(privkey, curve=SECP256k1)
    sig_der = sk.sign_digest(msg_hash, sigencode=sigencode_der)
    return sig_der + b"\x01"


class TestOpNumberPush:
    """OP_0 through OP_16 push their numeric value as CScriptNum bytes."""

    def test_op_0(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_0"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b""]

    @pytest.mark.parametrize("n", range(1, 17))
    def test_op_n(self, k: KBitcoinScript, n: int) -> None:
        result = k.verify_script(script_pubkey=script(f"OP_{n}"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [n.to_bytes(1, "little")]

    def test_op_numbers_compose(self, k: KBitcoinScript) -> None:
        """OP_3 OP_4 OP_ADD => 7"""
        result = k.verify_script(
            script_pubkey=script("OP_3", "OP_4", "OP_ADD"),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x07"]


class TestOpCheckMultisig:
    """OP_CHECKMULTISIG: M-of-N multi-signature verification."""

    def test_1_of_1(self, k: KBitcoinScript) -> None:
        msg_hash = hashlib.sha256(b"1of1").digest()
        sig1 = _sign_der(PRIVKEY_1, msg_hash)
        result = k.verify_script(
            script_sig=script("OP_0", push(sig1.hex())),
            script_pubkey=script(
                "OP_1", push(PUBKEY_1.hex()), "OP_1", "OP_CHECKMULTISIG",
            ),
            sighash=msg_hash,
        )
        assert not k.is_stuck(result)
        assert k.success(result)
        assert k.stack(result) == [b"\x01"]

    def test_1_of_2_first_key(self, k: KBitcoinScript) -> None:
        msg_hash = hashlib.sha256(b"1of2-first").digest()
        sig1 = _sign_der(PRIVKEY_1, msg_hash)
        result = k.verify_script(
            script_sig=script("OP_0", push(sig1.hex())),
            script_pubkey=script(
                "OP_1",
                push(PUBKEY_1.hex()), push(PUBKEY_2.hex()),
                "OP_2", "OP_CHECKMULTISIG",
            ),
            sighash=msg_hash,
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01"]

    def test_1_of_2_second_key(self, k: KBitcoinScript) -> None:
        msg_hash = hashlib.sha256(b"1of2-second").digest()
        sig2 = _sign_der(PRIVKEY_2, msg_hash)
        result = k.verify_script(
            script_sig=script("OP_0", push(sig2.hex())),
            script_pubkey=script(
                "OP_1",
                push(PUBKEY_1.hex()), push(PUBKEY_2.hex()),
                "OP_2", "OP_CHECKMULTISIG",
            ),
            sighash=msg_hash,
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01"]

    def test_2_of_2(self, k: KBitcoinScript) -> None:
        msg_hash = hashlib.sha256(b"2of2").digest()
        sig1 = _sign_der(PRIVKEY_1, msg_hash)
        sig2 = _sign_der(PRIVKEY_2, msg_hash)
        result = k.verify_script(
            script_sig=script("OP_0", push(sig1.hex()), push(sig2.hex())),
            script_pubkey=script(
                "OP_2",
                push(PUBKEY_1.hex()), push(PUBKEY_2.hex()),
                "OP_2", "OP_CHECKMULTISIG",
            ),
            sighash=msg_hash,
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01"]

    def test_2_of_3(self, k: KBitcoinScript) -> None:
        """Sign with keys 1 and 3 (skipping key 2)."""
        msg_hash = hashlib.sha256(b"2of3").digest()
        sig1 = _sign_der(PRIVKEY_1, msg_hash)
        sig3 = _sign_der(PRIVKEY_3, msg_hash)
        result = k.verify_script(
            script_sig=script("OP_0", push(sig1.hex()), push(sig3.hex())),
            script_pubkey=script(
                "OP_2",
                push(PUBKEY_1.hex()), push(PUBKEY_2.hex()), push(PUBKEY_3.hex()),
                "OP_3", "OP_CHECKMULTISIG",
            ),
            sighash=msg_hash,
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01"]

    def test_2_of_3_keys_2_and_3(self, k: KBitcoinScript) -> None:
        msg_hash = hashlib.sha256(b"2of3-23").digest()
        sig2 = _sign_der(PRIVKEY_2, msg_hash)
        sig3 = _sign_der(PRIVKEY_3, msg_hash)
        result = k.verify_script(
            script_sig=script("OP_0", push(sig2.hex()), push(sig3.hex())),
            script_pubkey=script(
                "OP_2",
                push(PUBKEY_1.hex()), push(PUBKEY_2.hex()), push(PUBKEY_3.hex()),
                "OP_3", "OP_CHECKMULTISIG",
            ),
            sighash=msg_hash,
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01"]

    def test_wrong_signature_pushes_0(self, k: KBitcoinScript) -> None:
        """1-of-1 with a signature from the wrong key."""
        msg_hash = hashlib.sha256(b"wrong-sig").digest()
        wrong_sig = _sign_der(PRIVKEY_2, msg_hash)
        result = k.verify_script(
            script_sig=script("OP_0", push(wrong_sig.hex())),
            script_pubkey=script(
                "OP_1", push(PUBKEY_1.hex()), "OP_1", "OP_CHECKMULTISIG",
            ),
            sighash=msg_hash,
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b""]

    def test_wrong_order_pushes_0(self, k: KBitcoinScript) -> None:
        """2-of-2 with signatures in wrong order.

        Bitcoin requires sigs to match pubkeys in order. sig2 matches pk2
        first, then sig1 has no remaining pubkeys to match.
        """
        msg_hash = hashlib.sha256(b"wrong-order").digest()
        sig1 = _sign_der(PRIVKEY_1, msg_hash)
        sig2 = _sign_der(PRIVKEY_2, msg_hash)
        result = k.verify_script(
            script_sig=script("OP_0", push(sig2.hex()), push(sig1.hex())),
            script_pubkey=script(
                "OP_2",
                push(PUBKEY_1.hex()), push(PUBKEY_2.hex()),
                "OP_2", "OP_CHECKMULTISIG",
            ),
            sighash=msg_hash,
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b""]

    def test_insufficient_matching_sigs_pushes_0(self, k: KBitcoinScript) -> None:
        """2-of-3 with only one valid signature (needs two)."""
        msg_hash = hashlib.sha256(b"insufficient").digest()
        sig1 = _sign_der(PRIVKEY_1, msg_hash)
        bad_privkey = (99).to_bytes(32, "big")
        bad_sig = _sign_der(bad_privkey, msg_hash)
        result = k.verify_script(
            script_sig=script("OP_0", push(sig1.hex()), push(bad_sig.hex())),
            script_pubkey=script(
                "OP_2",
                push(PUBKEY_1.hex()), push(PUBKEY_2.hex()), push(PUBKEY_3.hex()),
                "OP_3", "OP_CHECKMULTISIG",
            ),
            sighash=msg_hash,
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b""]

    def test_empty_stack_stuck(self, k: KBitcoinScript) -> None:
        result = k.verify_script(
            script_pubkey=script("OP_CHECKMULTISIG"),
        )
        assert k.is_stuck(result)
