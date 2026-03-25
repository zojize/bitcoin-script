"""Tests for OP_0..OP_16 and OP_CHECKMULTISIG in K Framework semantics."""

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


def _push_sig(sig: bytes) -> str:
    return f"OP_PUSHBYTES_{len(sig)} {sig.hex()}"


def _multisig_script(
    sighash: bytes,
    sigs: list[bytes],
    pubkeys: list[bytes],
    m: int,
    n: int,
) -> str:
    """Build a complete multisig script string.

    Stack layout: sighash dummy sig1..sigM OP_M pk1..pkN OP_N OP_CHECKMULTISIG
    """
    parts = [f"OP_PUSHBYTES_32 {sighash.hex()}", "OP_0"]  # sighash + dummy
    for sig in sigs:
        parts.append(_push_sig(sig))
    parts.append(f"OP_{m}")
    for pk in pubkeys:
        parts.append(f"OP_PUSHBYTES_65 {pk.hex()}")
    parts.append(f"OP_{n}")
    parts.append("OP_CHECKMULTISIG")
    return " ".join(parts)


class TestOpNumberPush:
    """OP_0 through OP_16 push their numeric value as CScriptNum bytes."""

    def test_op_0(self, k: KBitcoinScript) -> None:
        result = k.run(k.pattern("OP_0"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b""]

    @pytest.mark.parametrize("n", range(1, 17))
    def test_op_n(self, k: KBitcoinScript, n: int) -> None:
        result = k.run(k.pattern(f"OP_{n}"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [n.to_bytes(1, "little")]

    def test_op_numbers_compose(self, k: KBitcoinScript) -> None:
        """OP_3 OP_4 OP_ADD => 7"""
        result = k.run(k.pattern("OP_3 OP_4 OP_ADD"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x07"]


class TestOpCheckMultisig:
    """OP_CHECKMULTISIG: M-of-N multi-signature verification."""

    def test_1_of_1(self, k: KBitcoinScript) -> None:
        msg_hash = hashlib.sha256(b"1of1").digest()
        sig1 = _sign_der(PRIVKEY_1, msg_hash)
        script = _multisig_script(msg_hash, [sig1], [PUBKEY_1], m=1, n=1)
        result = k.run(k.pattern(script))
        assert not k.is_stuck(result)
        assert k.success(result)
        assert k.stack(result) == [b"\x01"]

    def test_1_of_2_first_key(self, k: KBitcoinScript) -> None:
        msg_hash = hashlib.sha256(b"1of2-first").digest()
        sig1 = _sign_der(PRIVKEY_1, msg_hash)
        script = _multisig_script(msg_hash, [sig1], [PUBKEY_1, PUBKEY_2], m=1, n=2)
        result = k.run(k.pattern(script))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01"]

    def test_1_of_2_second_key(self, k: KBitcoinScript) -> None:
        msg_hash = hashlib.sha256(b"1of2-second").digest()
        sig2 = _sign_der(PRIVKEY_2, msg_hash)
        script = _multisig_script(msg_hash, [sig2], [PUBKEY_1, PUBKEY_2], m=1, n=2)
        result = k.run(k.pattern(script))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01"]

    def test_2_of_2(self, k: KBitcoinScript) -> None:
        msg_hash = hashlib.sha256(b"2of2").digest()
        sig1 = _sign_der(PRIVKEY_1, msg_hash)
        sig2 = _sign_der(PRIVKEY_2, msg_hash)
        script = _multisig_script(
            msg_hash, [sig1, sig2], [PUBKEY_1, PUBKEY_2], m=2, n=2
        )
        result = k.run(k.pattern(script))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01"]

    def test_2_of_3(self, k: KBitcoinScript) -> None:
        """Sign with keys 1 and 3 (skipping key 2)."""
        msg_hash = hashlib.sha256(b"2of3").digest()
        sig1 = _sign_der(PRIVKEY_1, msg_hash)
        sig3 = _sign_der(PRIVKEY_3, msg_hash)
        script = _multisig_script(
            msg_hash, [sig1, sig3], [PUBKEY_1, PUBKEY_2, PUBKEY_3], m=2, n=3
        )
        result = k.run(k.pattern(script))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01"]

    def test_2_of_3_keys_2_and_3(self, k: KBitcoinScript) -> None:
        msg_hash = hashlib.sha256(b"2of3-23").digest()
        sig2 = _sign_der(PRIVKEY_2, msg_hash)
        sig3 = _sign_der(PRIVKEY_3, msg_hash)
        script = _multisig_script(
            msg_hash, [sig2, sig3], [PUBKEY_1, PUBKEY_2, PUBKEY_3], m=2, n=3
        )
        result = k.run(k.pattern(script))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01"]

    def test_wrong_signature_pushes_0(self, k: KBitcoinScript) -> None:
        """1-of-1 with a signature from the wrong key."""
        msg_hash = hashlib.sha256(b"wrong-sig").digest()
        wrong_sig = _sign_der(PRIVKEY_2, msg_hash)
        script = _multisig_script(msg_hash, [wrong_sig], [PUBKEY_1], m=1, n=1)
        result = k.run(k.pattern(script))
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
        script = _multisig_script(
            msg_hash, [sig2, sig1], [PUBKEY_1, PUBKEY_2], m=2, n=2
        )
        result = k.run(k.pattern(script))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b""]

    def test_insufficient_matching_sigs_pushes_0(self, k: KBitcoinScript) -> None:
        """2-of-3 with only one valid signature (needs two)."""
        msg_hash = hashlib.sha256(b"insufficient").digest()
        sig1 = _sign_der(PRIVKEY_1, msg_hash)
        bad_privkey = (99).to_bytes(32, "big")
        bad_sig = _sign_der(bad_privkey, msg_hash)
        script = _multisig_script(
            msg_hash, [sig1, bad_sig], [PUBKEY_1, PUBKEY_2, PUBKEY_3], m=2, n=3
        )
        result = k.run(k.pattern(script))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b""]

    def test_empty_stack_stuck(self, k: KBitcoinScript) -> None:
        result = k.run(k.pattern("OP_CHECKMULTISIG"))
        assert k.is_stuck(result)
