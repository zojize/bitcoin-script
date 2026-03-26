"""Tests for P2SH (BIP-16) execution.

P2SH scriptPubKey pattern: OP_HASH160 <20-byte-hash> OP_EQUAL
P2SH scriptSig: <data...> <serialized-redeem-script>

Execution phases:
  1. Execute scriptSig (pushes data + redeem script onto stack)
  2. Execute scriptPubKey (checks HASH160 of top matches embedded hash)
  3. Pop redeem script from saved stack, decode and execute it
"""

from __future__ import annotations

import hashlib

import pytest

from bitcoin_script.k_semantics import KBitcoinScript
from .script_helpers import script, push

pytestmark = pytest.mark.k

# BIP-16 activation timestamp (April 1, 2012 00:00:00 UTC)
BIP16_TIMESTAMP = 1333238400


def hash160(data: bytes) -> bytes:
    """RIPEMD160(SHA256(data))."""
    sha = hashlib.sha256(data).digest()
    return hashlib.new("ripemd160", sha).digest()


def p2sh_script_pubkey(redeem_script: bytes) -> bytes:
    """Build a P2SH scriptPubKey: OP_HASH160 <hash> OP_EQUAL."""
    h = hash160(redeem_script)
    return script("OP_HASH160", push(h.hex()), "OP_EQUAL")


def push_script(redeem: bytes) -> bytes:
    """Push serialized redeem script bytes (as raw script bytes)."""
    return bytes.fromhex(push(redeem.hex()))


class TestP2SHBasic:
    def test_p2sh_simple_true(self, k: KBitcoinScript) -> None:
        """P2SH where redeem script is just OP_1 (always succeeds)."""
        redeem = script("OP_1")
        result = k.verify_script(
            script_sig=push_script(redeem),
            script_pubkey=p2sh_script_pubkey(redeem),
            timestamp=BIP16_TIMESTAMP,
        )
        assert not k.is_stuck(result)
        assert k.success(result)

    def test_p2sh_simple_false(self, k: KBitcoinScript) -> None:
        """P2SH where redeem script is just OP_0 (always fails)."""
        redeem = script("OP_0")
        result = k.verify_script(
            script_sig=push_script(redeem),
            script_pubkey=p2sh_script_pubkey(redeem),
            timestamp=BIP16_TIMESTAMP,
        )
        assert not k.is_stuck(result)
        assert not k.success(result)

    def test_p2sh_with_data(self, k: KBitcoinScript) -> None:
        """P2SH with data provided by scriptSig to the redeem script.

        Redeem script: OP_ADD OP_5 OP_EQUAL
        scriptSig: OP_2 OP_3 <redeem>
        Expected: 2 + 3 = 5, EQUAL pushes 1 -> success
        """
        redeem = script("OP_ADD", "OP_5", "OP_EQUAL")
        sig = script("OP_2", "OP_3") + push_script(redeem)
        result = k.verify_script(
            script_sig=sig,
            script_pubkey=p2sh_script_pubkey(redeem),
            timestamp=BIP16_TIMESTAMP,
        )
        assert not k.is_stuck(result)
        assert k.success(result)

    def test_p2sh_wrong_hash(self, k: KBitcoinScript) -> None:
        """P2SH fails if redeem script hash doesn't match scriptPubKey."""
        real_redeem = script("OP_1")
        fake_redeem = script("OP_2")
        result = k.verify_script(
            script_sig=push_script(fake_redeem),
            script_pubkey=p2sh_script_pubkey(real_redeem),
            timestamp=BIP16_TIMESTAMP,
        )
        # The HASH160 won't match, so OP_EQUAL pushes 0
        assert not k.is_stuck(result)
        assert not k.success(result)


class TestP2SHTimestampGating:
    def test_pre_bip16_no_p2sh(self, k: KBitcoinScript) -> None:
        """Before BIP-16 activation, P2SH pattern is treated as plain script.

        With correct redeem script on stack, HASH160 matches -> OP_EQUAL -> 1.
        No redeem script execution phase occurs, so OP_0 redeem succeeds.
        """
        redeem = script("OP_0")  # Would fail if executed as redeem script
        result = k.verify_script(
            script_sig=push_script(redeem),
            script_pubkey=p2sh_script_pubkey(redeem),
            timestamp=BIP16_TIMESTAMP - 1,  # Just before activation
        )
        # Pre-BIP16: only checks hash match, doesn't execute redeem script
        assert not k.is_stuck(result)
        assert k.success(result)

    def test_post_bip16_executes_redeem(self, k: KBitcoinScript) -> None:
        """After BIP-16, redeem script IS executed. OP_0 redeem -> failure."""
        redeem = script("OP_0")
        result = k.verify_script(
            script_sig=push_script(redeem),
            script_pubkey=p2sh_script_pubkey(redeem),
            timestamp=BIP16_TIMESTAMP,
        )
        assert not k.is_stuck(result)
        assert not k.success(result)

    def test_timestamp_zero_no_p2sh(self, k: KBitcoinScript) -> None:
        """Default timestamp (0) means no P2SH execution."""
        redeem = script("OP_0")  # Would fail if executed
        result = k.verify_script(
            script_sig=push_script(redeem),
            script_pubkey=p2sh_script_pubkey(redeem),
            timestamp=0,
        )
        assert not k.is_stuck(result)
        assert k.success(result)


class TestP2SHRedeemScripts:
    def test_p2sh_equality_check(self, k: KBitcoinScript) -> None:
        """P2SH with redeem: OP_2 OP_EQUAL (expects 2 from scriptSig)."""
        redeem = script("OP_2", "OP_EQUAL")
        sig = script("OP_2") + push_script(redeem)
        result = k.verify_script(
            script_sig=sig,
            script_pubkey=p2sh_script_pubkey(redeem),
            timestamp=BIP16_TIMESTAMP,
        )
        assert not k.is_stuck(result)
        assert k.success(result)

    def test_p2sh_conditional_redeem(self, k: KBitcoinScript) -> None:
        """P2SH with conditional redeem script.

        Redeem: OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF
        scriptSig: OP_1 <redeem>  (true branch -> 2)
        """
        redeem = script("OP_IF", "OP_2", "OP_ELSE", "OP_3", "OP_ENDIF")
        sig = script("OP_1") + push_script(redeem)
        result = k.verify_script(
            script_sig=sig,
            script_pubkey=p2sh_script_pubkey(redeem),
            timestamp=BIP16_TIMESTAMP,
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x02"]

    def test_p2sh_hash_redeem(self, k: KBitcoinScript) -> None:
        """P2SH wrapping a HASH160-based check.

        Redeem: OP_HASH160 <expected_hash> OP_EQUAL
        scriptSig: <preimage> <redeem>
        """
        preimage = b"hello world"
        expected_hash = hash160(preimage)
        redeem = script("OP_HASH160", push(expected_hash.hex()), "OP_EQUAL")
        sig = bytes.fromhex(push(preimage.hex())) + push_script(redeem)
        result = k.verify_script(
            script_sig=sig,
            script_pubkey=p2sh_script_pubkey(redeem),
            timestamp=BIP16_TIMESTAMP,
        )
        assert not k.is_stuck(result)
        assert k.success(result)


class TestP2SHStackHandling:
    def test_p2sh_stack_restored(self, k: KBitcoinScript) -> None:
        """Verify saved stack from scriptSig is restored for redeem execution.

        scriptSig: OP_2 OP_3 <redeem>
        Redeem: OP_ADD OP_5 OP_EQUAL
        """
        redeem = script("OP_ADD", "OP_5", "OP_EQUAL")
        sig = script("OP_2", "OP_3") + push_script(redeem)
        result = k.verify_script(
            script_sig=sig,
            script_pubkey=p2sh_script_pubkey(redeem),
            timestamp=BIP16_TIMESTAMP,
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01"]

    def test_p2sh_empty_scriptsig_data(self, k: KBitcoinScript) -> None:
        """P2SH where scriptSig only contains the redeem script (no extra data).

        Redeem: OP_1 (unconditionally pushes 1)
        """
        redeem = script("OP_1")
        result = k.verify_script(
            script_sig=push_script(redeem),
            script_pubkey=p2sh_script_pubkey(redeem),
            timestamp=BIP16_TIMESTAMP,
        )
        assert not k.is_stuck(result)
        assert k.success(result)
