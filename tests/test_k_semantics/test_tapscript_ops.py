"""Tests for BIP 342 tapscript opcodes: CHECKSIGADD, CHECKMULTISIG disabling, OP_SUCCESS."""

from __future__ import annotations

import pytest

from .conftest import (
    encode_witness_blob,
    expand_taproot_witness,
    flags_to_bitmask,
)

pytestmark = pytest.mark.k

# Standard taproot flags (all consensus flags active)
TAPROOT_FLAGS = flags_to_bitmask(
    {
        "P2SH",
        "STRICTENC",
        "DERSIG",
        "LOW_S",
        "NULLDUMMY",
        "SIGPUSHONLY",
        "MINIMALDATA",
        "DISCOURAGE_UPGRADABLE_NOPS",
        "CLEANSTACK",
        "CHECKLOCKTIMEVERIFY",
        "CHECKSEQUENCEVERIFY",
        "WITNESS",
        "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM",
        "MINIMALIF",
        "NULLFAIL",
        "WITNESS_PUBKEYTYPE",
        "CONST_SCRIPTCODE",
        "TAPROOT",
    }
)

# Standard non-taproot flags (for testing OP_SUCCESS in non-tapscript context)
SEGWIT_FLAGS = flags_to_bitmask(
    {
        "P2SH",
        "STRICTENC",
        "DERSIG",
        "LOW_S",
        "NULLDUMMY",
        "SIGPUSHONLY",
        "MINIMALDATA",
        "DISCOURAGE_UPGRADABLE_NOPS",
        "CLEANSTACK",
        "CHECKLOCKTIMEVERIFY",
        "CHECKSEQUENCEVERIFY",
        "WITNESS",
        "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM",
        "MINIMALIF",
        "NULLFAIL",
        "WITNESS_PUBKEYTYPE",
        "CONST_SCRIPTCODE",
    }
)


def _build_tapscript_spend(
    script_asm: str,
    witness_stack_hex: list[str] | None = None,
) -> tuple[bytes, bytes, bytes]:
    """Build a tapscript witness-v1 spend.

    Args:
        script_asm: Bitcoin Core ASM for the tapscript.
        witness_stack_hex: Hex-encoded witness items to place before the script.
            If None, no extra items are pushed.

    Returns:
        (script_sig, script_pubkey, witness_blob)
    """
    # Build witness hex list: [stack items..., #SCRIPT# asm, #CONTROLBLOCK#]
    wit_hex: list[str] = []
    if witness_stack_hex:
        wit_hex.extend(witness_stack_hex)
    wit_hex.append(f"#SCRIPT#{script_asm}")
    wit_hex.append("#CONTROLBLOCK#")

    pubkey_asm = "1 0x20 0x#TAPROOTOUTPUT#"

    witness_items, expanded_pubkey_asm = expand_taproot_witness(wit_hex, pubkey_asm)
    witness_blob = encode_witness_blob(witness_items)

    from .bitcoin_core_vectors import parse_bitcoin_core_asm

    pubkey_bytes = parse_bitcoin_core_asm(expanded_pubkey_asm)

    return b"", pubkey_bytes, witness_blob


# =========================================================================
# OP_CHECKSIGADD tests
# =========================================================================


class TestChecksigadd:
    """OP_CHECKSIGADD (0xba) in tapscript."""

    def test_empty_sig_counter_unchanged(self, k):
        """Empty signature: push N unchanged (no error)."""
        # Script: OP_CHECKSIGADD
        # Stack (bottom to top): empty_sig, num(5), pubkey(32 bytes)
        pubkey_hex = "ab" * 32  # 32-byte pubkey (valid x-only format)
        sig_hex = ""  # empty signature
        num_hex = "05"  # CScriptNum 5

        # Witness stack: sig, num, pubkey (pushed bottom-to-top, so sig first)
        # The tapscript is just OP_CHECKSIGADD
        script_sig, script_pubkey, witness_blob = _build_tapscript_spend(
            "CHECKSIGADD",
            witness_stack_hex=[sig_hex, num_hex, pubkey_hex],
        )

        result = k.verify_script(
            script_sig=script_sig,
            script_pubkey=script_pubkey,
            witness=witness_blob,
            flags=TAPROOT_FLAGS,
        )
        # Stack should have N=5 (truthy), script succeeds
        assert k.success(result), "Empty sig should leave N unchanged"
        stack = k.stack(result)
        assert stack == [b"\x05"], f"Expected [0x05] on stack, got {stack}"

    def test_empty_pubkey_fails(self, k):
        """Empty pubkey (0 bytes) must fail with TAPSCRIPT_EMPTY_PUBKEY."""
        pubkey_hex = ""  # empty pubkey
        sig_hex = "aa" * 64  # some 64-byte sig
        num_hex = "05"

        script_sig, script_pubkey, witness_blob = _build_tapscript_spend(
            "CHECKSIGADD",
            witness_stack_hex=[sig_hex, num_hex, pubkey_hex],
        )

        result = k.verify_script(
            script_sig=script_sig,
            script_pubkey=script_pubkey,
            witness=witness_blob,
            flags=TAPROOT_FLAGS,
        )
        assert not k.success(result)
        assert k.error(result) == "TAPSCRIPT_EMPTY_PUBKEY"

    def test_unknown_pubkey_type_increments(self, k):
        """Non-32-byte non-empty pubkey: unknown key type, push N+1 (future compat)."""
        pubkey_hex = "ab" * 33  # 33-byte pubkey (not x-only, unknown type)
        sig_hex = "cc" * 64  # some 64-byte sig (length is valid)
        num_hex = "03"  # CScriptNum 3

        script_sig, script_pubkey, witness_blob = _build_tapscript_spend(
            "CHECKSIGADD",
            witness_stack_hex=[sig_hex, num_hex, pubkey_hex],
        )

        result = k.verify_script(
            script_sig=script_sig,
            script_pubkey=script_pubkey,
            witness=witness_blob,
            flags=TAPROOT_FLAGS,
        )
        # Should succeed with N+1 = 4 on stack
        assert k.success(result), "Unknown pubkey type should push N+1"
        stack = k.stack(result)
        assert stack == [b"\x04"], f"Expected [0x04] (N+1=4) on stack, got {stack}"


# =========================================================================
# CHECKMULTISIG / CHECKMULTISIGVERIFY disabled in tapscript
# =========================================================================


class TestCheckmultisigDisabled:
    """CHECKMULTISIG and CHECKMULTISIGVERIFY must fail in tapscript."""

    def test_checkmultisig_fails_in_tapscript(self, k):
        """OP_CHECKMULTISIG in tapscript must fail with TAPSCRIPT_CHECKMULTISIG."""
        # Script: OP_0 OP_0 OP_0 OP_CHECKMULTISIG
        # (0-of-0 multisig with dummy element -- simplest possible invocation)
        script_sig, script_pubkey, witness_blob = _build_tapscript_spend(
            "0 0 0 CHECKMULTISIG",
        )

        result = k.verify_script(
            script_sig=script_sig,
            script_pubkey=script_pubkey,
            witness=witness_blob,
            flags=TAPROOT_FLAGS,
        )
        assert not k.success(result)
        assert k.error(result) == "TAPSCRIPT_CHECKMULTISIG"

    def test_checkmultisigverify_fails_in_tapscript(self, k):
        """OP_CHECKMULTISIGVERIFY in tapscript must fail with TAPSCRIPT_CHECKMULTISIG."""
        script_sig, script_pubkey, witness_blob = _build_tapscript_spend(
            "0 0 0 CHECKMULTISIGVERIFY",
        )

        result = k.verify_script(
            script_sig=script_sig,
            script_pubkey=script_pubkey,
            witness=witness_blob,
            flags=TAPROOT_FLAGS,
        )
        assert not k.success(result)
        assert k.error(result) == "TAPSCRIPT_CHECKMULTISIG"


# =========================================================================
# OP_SUCCESS opcodes
# =========================================================================


class TestOpSuccess:
    """OP_SUCCESS opcodes cause unconditional success in tapscript (BIP 342)."""

    def test_op_success_0xbb_in_tapscript(self, k):
        """Opcode 0xbb (undefined) causes OP_SUCCESS in tapscript."""
        # Build a tapscript that contains raw byte 0xbb followed by OP_RETURN
        # (OP_RETURN would normally fail, but OP_SUCCESS preempts everything)
        # Script bytes: 0xbb 0x6a (OP_RETURN)
        # We pass raw hex as witness item for the script
        script_hex = "bb6a"  # 0xbb then OP_RETURN
        script_bytes = bytes.fromhex(script_hex)

        # Build the tapscript spend manually with raw script bytes
        from .conftest import (
            _tagged_hash,
            _compact_size,
            _taproot_tweak_pubkey,
            _INTERNAL_KEY,
            _TAPSCRIPT_LEAF_VERSION,
        )

        leaf_hash = _tagged_hash(
            "TapLeaf",
            bytes([_TAPSCRIPT_LEAF_VERSION])
            + _compact_size(len(script_bytes))
            + script_bytes,
        )
        tweak = _tagged_hash("TapTweak", _INTERNAL_KEY + leaf_hash)
        output_key, parity = _taproot_tweak_pubkey(_INTERNAL_KEY, tweak)

        cb_first_byte = _TAPSCRIPT_LEAF_VERSION | parity
        control_block = bytes([cb_first_byte]) + _INTERNAL_KEY

        witness_items = [script_bytes, control_block]
        witness_blob = encode_witness_blob(witness_items)

        # scriptPubKey: OP_1 PUSH32 <output_key>
        script_pubkey = bytes([0x51, 0x20]) + output_key

        result = k.verify_script(
            script_sig=b"",
            script_pubkey=script_pubkey,
            witness=witness_blob,
            flags=TAPROOT_FLAGS,
        )
        assert k.success(result), "0xbb should cause OP_SUCCESS in tapscript"

    def test_op_success_disabled_opcode_in_tapscript(self, k):
        """Disabled opcode 0x7e (OP_CAT) causes OP_SUCCESS in tapscript."""
        script_hex = "7e"  # OP_CAT — disabled normally, OP_SUCCESS in tapscript
        script_bytes = bytes.fromhex(script_hex)

        from .conftest import (
            _tagged_hash,
            _compact_size,
            _taproot_tweak_pubkey,
            _INTERNAL_KEY,
            _TAPSCRIPT_LEAF_VERSION,
        )

        leaf_hash = _tagged_hash(
            "TapLeaf",
            bytes([_TAPSCRIPT_LEAF_VERSION])
            + _compact_size(len(script_bytes))
            + script_bytes,
        )
        tweak = _tagged_hash("TapTweak", _INTERNAL_KEY + leaf_hash)
        output_key, parity = _taproot_tweak_pubkey(_INTERNAL_KEY, tweak)

        cb_first_byte = _TAPSCRIPT_LEAF_VERSION | parity
        control_block = bytes([cb_first_byte]) + _INTERNAL_KEY

        witness_items = [script_bytes, control_block]
        witness_blob = encode_witness_blob(witness_items)

        script_pubkey = bytes([0x51, 0x20]) + output_key

        result = k.verify_script(
            script_sig=b"",
            script_pubkey=script_pubkey,
            witness=witness_blob,
            flags=TAPROOT_FLAGS,
        )
        assert k.success(result), "0x7e (OP_CAT) should cause OP_SUCCESS in tapscript"

    def test_op_success_reserved_opcode_in_tapscript(self, k):
        """Reserved opcode 0x50 (OP_RESERVED) causes OP_SUCCESS in tapscript."""
        script_hex = "50"  # OP_RESERVED — normally fails, OP_SUCCESS in tapscript
        script_bytes = bytes.fromhex(script_hex)

        from .conftest import (
            _tagged_hash,
            _compact_size,
            _taproot_tweak_pubkey,
            _INTERNAL_KEY,
            _TAPSCRIPT_LEAF_VERSION,
        )

        leaf_hash = _tagged_hash(
            "TapLeaf",
            bytes([_TAPSCRIPT_LEAF_VERSION])
            + _compact_size(len(script_bytes))
            + script_bytes,
        )
        tweak = _tagged_hash("TapTweak", _INTERNAL_KEY + leaf_hash)
        output_key, parity = _taproot_tweak_pubkey(_INTERNAL_KEY, tweak)

        cb_first_byte = _TAPSCRIPT_LEAF_VERSION | parity
        control_block = bytes([cb_first_byte]) + _INTERNAL_KEY

        witness_items = [script_bytes, control_block]
        witness_blob = encode_witness_blob(witness_items)

        script_pubkey = bytes([0x51, 0x20]) + output_key

        result = k.verify_script(
            script_sig=b"",
            script_pubkey=script_pubkey,
            witness=witness_blob,
            flags=TAPROOT_FLAGS,
        )
        assert k.success(result), (
            "0x50 (OP_RESERVED) should cause OP_SUCCESS in tapscript"
        )

    def test_same_opcode_fails_in_non_tapscript(self, k):
        """Opcode 0xbb fails in non-tapscript (witness-v0) context.

        In a P2WSH script, undefined opcodes act as OP_RESERVED_OP
        (fail when executed, but OK in dead IF branches -- however we execute it).
        """
        import hashlib

        # Build a P2WSH script that contains 0xbb followed by OP_1
        # 0xbb is a reserved opcode outside tapscript, so it fails on execution
        witness_script = bytes.fromhex("bb51")  # 0xbb then OP_1

        # P2WSH: scriptPubKey = OP_0 PUSH32 SHA256(witness_script)
        script_hash = hashlib.sha256(witness_script).digest()
        script_pubkey = bytes([0x00, 0x20]) + script_hash

        # Witness: [witness_script]
        witness_items = [witness_script]
        witness_blob = encode_witness_blob(witness_items)

        result = k.verify_script(
            script_sig=b"",
            script_pubkey=script_pubkey,
            witness=witness_blob,
            flags=SEGWIT_FLAGS,
        )
        assert not k.success(result), "0xbb should fail in non-tapscript context"
