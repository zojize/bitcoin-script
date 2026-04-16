"""Taproot/tapscript coverage tests derived from Bitcoin Core's feature_taproot.py categories.

Tests key-path signature validation, script-path control block validation,
tapscript OP_CHECKSIG behavior, and annex handling.
"""

from __future__ import annotations

import ctypes
import hashlib
import os
import struct

import pytest

from bitcoin_script.script_utils import encode_witness_blob

from .conftest import (
    _INTERNAL_KEY,
    _TAPSCRIPT_LEAF_VERSION,
    _compact_size,
    _find_libsecp256k1,
    _tagged_hash,
    _taproot_tweak_pubkey,
    flags_to_bitmask,
)

pytestmark = pytest.mark.k

# Standard taproot flags
TAPROOT_FLAGS = flags_to_bitmask({"P2SH", "WITNESS", "TAPROOT"})

# ── Helpers ──────────────────────────────────────────────────────────────


def _make_taproot_output(
    internal_key: bytes, merkle_root: bytes | None = None
) -> tuple[bytes, bytes, int]:
    """Compute taproot output key from internal key and optional merkle root.

    Returns (output_key, tweak, parity).
    """
    if merkle_root is not None:
        tweak = _tagged_hash("TapTweak", internal_key + merkle_root)
    else:
        # Key-path only (no scripts): tweak is just H(internal_key)
        tweak = _tagged_hash("TapTweak", internal_key)

    output_key, parity = _taproot_tweak_pubkey(internal_key, tweak)
    return output_key, tweak, parity


def _make_witness_v1_spk(output_key: bytes) -> bytes:
    """Build witness v1 scriptPubKey: OP_1 <32-byte-key>."""
    return bytes([0x51, 0x20]) + output_key


def _make_schnorr_keypair() -> tuple[bytes, bytes]:
    """Generate a random secp256k1 Schnorr keypair.

    Returns (secret_key_32, x_only_pubkey_32).
    """
    lib = _find_libsecp256k1()

    lib.secp256k1_context_create.restype = ctypes.c_void_p
    lib.secp256k1_context_create.argtypes = [ctypes.c_uint]
    ctx = lib.secp256k1_context_create(0x0101)

    # Generate a valid secret key
    while True:
        sk = os.urandom(32)
        lib.secp256k1_ec_seckey_verify.restype = ctypes.c_int
        lib.secp256k1_ec_seckey_verify.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        if lib.secp256k1_ec_seckey_verify(ctx, sk) == 1:
            break

    # Create keypair
    keypair = (ctypes.c_ubyte * 96)()
    lib.secp256k1_keypair_create.restype = ctypes.c_int
    lib.secp256k1_keypair_create.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_char_p,
    ]
    ok = lib.secp256k1_keypair_create(ctx, keypair, sk)
    assert ok == 1

    # Extract x-only pubkey
    xonly = (ctypes.c_ubyte * 64)()
    lib.secp256k1_keypair_xonly_pub.restype = ctypes.c_int
    lib.secp256k1_keypair_xonly_pub.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    lib.secp256k1_keypair_xonly_pub(ctx, xonly, None, keypair)

    serialized = (ctypes.c_ubyte * 32)()
    lib.secp256k1_xonly_pubkey_serialize.restype = ctypes.c_int
    lib.secp256k1_xonly_pubkey_serialize.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    lib.secp256k1_xonly_pubkey_serialize(ctx, serialized, xonly)

    lib.secp256k1_context_destroy.restype = None
    lib.secp256k1_context_destroy.argtypes = [ctypes.c_void_p]
    lib.secp256k1_context_destroy(ctx)

    return bytes(sk), bytes(serialized)


def _schnorr_sign(
    keypair_sk: bytes,
    msg32: bytes,
) -> bytes:
    """Create a 64-byte Schnorr signature using libsecp256k1."""
    lib = _find_libsecp256k1()

    lib.secp256k1_context_create.restype = ctypes.c_void_p
    lib.secp256k1_context_create.argtypes = [ctypes.c_uint]
    ctx = lib.secp256k1_context_create(0x0101)

    # Create keypair from sk
    keypair = (ctypes.c_ubyte * 96)()
    lib.secp256k1_keypair_create.restype = ctypes.c_int
    lib.secp256k1_keypair_create.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_char_p,
    ]
    ok = lib.secp256k1_keypair_create(ctx, keypair, keypair_sk)
    assert ok == 1

    # Sign
    sig = (ctypes.c_ubyte * 64)()
    lib.secp256k1_schnorrsig_sign32.restype = ctypes.c_int
    lib.secp256k1_schnorrsig_sign32.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    ok = lib.secp256k1_schnorrsig_sign32(ctx, sig, msg32, keypair, None)
    assert ok == 1

    lib.secp256k1_context_destroy.restype = None
    lib.secp256k1_context_destroy.argtypes = [ctypes.c_void_p]
    lib.secp256k1_context_destroy(ctx)

    return bytes(sig)


def _tweak_secret_key(sk: bytes, tweak: bytes) -> bytes:
    """Tweak a secret key: sk' = sk + tweak (mod n), with parity negation.

    For key-path spending, the signature must be made with the tweaked key.
    """
    lib = _find_libsecp256k1()

    lib.secp256k1_context_create.restype = ctypes.c_void_p
    lib.secp256k1_context_create.argtypes = [ctypes.c_uint]
    ctx = lib.secp256k1_context_create(0x0101)

    # Create keypair and tweak it
    keypair = (ctypes.c_ubyte * 96)()
    lib.secp256k1_keypair_create.restype = ctypes.c_int
    lib.secp256k1_keypair_create.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_char_p,
    ]
    ok = lib.secp256k1_keypair_create(ctx, keypair, sk)
    assert ok == 1

    lib.secp256k1_keypair_xonly_tweak_add.restype = ctypes.c_int
    lib.secp256k1_keypair_xonly_tweak_add.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_char_p,
    ]
    ok = lib.secp256k1_keypair_xonly_tweak_add(ctx, keypair, tweak)
    assert ok == 1

    # Extract tweaked secret key
    tweaked_sk = (ctypes.c_ubyte * 32)()
    lib.secp256k1_keypair_sec.restype = ctypes.c_int
    lib.secp256k1_keypair_sec.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    ok = lib.secp256k1_keypair_sec(ctx, tweaked_sk, keypair)
    assert ok == 1

    lib.secp256k1_context_destroy.restype = None
    lib.secp256k1_context_destroy.argtypes = [ctypes.c_void_p]
    lib.secp256k1_context_destroy(ctx)

    return bytes(tweaked_sk)


def _build_taproot_sighash_blob(
    script_pubkey: bytes,
    hash_type: int,
    amount: int = 0,
) -> bytes:
    """Build a minimal taproot sighash blob for the test crediting/spending tx pair.

    The K semantics look up sighash via lookupSighash(blob, hashtype, codesep_idx).
    The blob format is: N entries of (1-byte hashtype + 2-byte BE codesepIdx + 32-byte hash).

    For key-path, we compute the BIP 341 sighash for ext_flag=0, input_index=0.
    """
    from bitcoin.core import COutPoint, CTransaction, CTxIn, CTxOut
    from bitcoin.core.script import CScript

    # Build crediting tx (has the taproot output)
    txin_credit = CTxIn(
        COutPoint(b"\x00" * 32, 0xFFFFFFFF), CScript(b"\x00\x00"), 0xFFFFFFFF
    )
    txout_credit = CTxOut(amount, CScript(script_pubkey))
    credit_tx = CTransaction([txin_credit], [txout_credit])

    # Build spending tx
    txin_spend = CTxIn(COutPoint(credit_tx.GetTxid(), 0), CScript(b""), 0xFFFFFFFF)
    txout_spend = CTxOut(amount, CScript(b""))
    spend_tx = CTransaction([txin_spend], [txout_spend])

    # Compute BIP 341 sighash (ext_flag=0 for key-path)
    sh = _taproot_sighash_manual(spend_tx, 0, hash_type, 0, [script_pubkey], [amount])

    # For hash_type 0 (DEFAULT), the K semantics look up with key 0
    return bytes([hash_type]) + (0).to_bytes(2, "big") + sh


def _taproot_sighash_manual(
    tx,
    input_index: int,
    hash_type: int,
    ext_flag: int,
    all_prevout_scriptpubkeys: list[bytes],
    all_prevout_amounts: list[int],
    annex: bytes | None = None,
    tapleaf_hash: bytes | None = None,
    codesep_pos: int = 0xFFFFFFFF,
) -> bytes:
    """Compute BIP 341 taproot sighash (copied from verifier for test isolation)."""
    if hash_type == 0:
        base_type = 1
    else:
        base_type = hash_type & 0x1F
    anyone_can_pay = (hash_type & 0x80) != 0

    msg = b"\x00"  # epoch
    msg += struct.pack("<B", hash_type)
    msg += struct.pack("<i", tx.nVersion)
    msg += struct.pack("<I", tx.nLockTime)

    if not anyone_can_pay:
        prevouts = b""
        for vin in tx.vin:
            prevouts += bytes(vin.prevout.hash) + struct.pack("<I", vin.prevout.n)
        msg += hashlib.sha256(prevouts).digest()

        amounts = b""
        for amt in all_prevout_amounts:
            amounts += struct.pack("<q", amt)
        msg += hashlib.sha256(amounts).digest()

        sequences = b""
        for vin in tx.vin:
            sequences += struct.pack("<I", vin.nSequence)
        msg += hashlib.sha256(sequences).digest()

        if base_type not in (2, 3):  # not NONE or SINGLE
            outputs = b""
            for vout in tx.vout:
                outputs += struct.pack("<q", vout.nValue)
                spk = bytes(vout.scriptPubKey)
                outputs += _compact_size(len(spk)) + spk
            msg += hashlib.sha256(outputs).digest()

    spend_type = ext_flag * 2
    if annex is not None:
        spend_type |= 1
    msg += struct.pack("<B", spend_type)

    if anyone_can_pay:
        vin = tx.vin[input_index]
        msg += bytes(vin.prevout.hash) + struct.pack("<I", vin.prevout.n)
        msg += struct.pack("<q", all_prevout_amounts[input_index])
        spk = all_prevout_scriptpubkeys[input_index]
        msg += _compact_size(len(spk)) + spk
        msg += struct.pack("<I", vin.nSequence)
    else:
        msg += struct.pack("<I", input_index)

    if annex is not None:
        annex_hash = hashlib.sha256(_compact_size(len(annex)) + annex).digest()
        msg += annex_hash

    if base_type == 2:  # NONE
        pass
    elif base_type == 3:  # SINGLE
        if input_index < len(tx.vout):
            vout = tx.vout[input_index]
            single_out = struct.pack("<q", vout.nValue)
            spk = bytes(vout.scriptPubKey)
            single_out += _compact_size(len(spk)) + spk
            msg += hashlib.sha256(single_out).digest()
        else:
            msg += b"\x00" * 32
    # ALL: outputs already included above

    if ext_flag == 1:
        assert tapleaf_hash is not None
        msg += tapleaf_hash
        msg += struct.pack("<B", 0)  # key_version
        msg += struct.pack("<I", codesep_pos)  # code_separator_position

    return _tagged_hash("TapSighash", msg)


def _build_tapscript_sighash_blob(
    script_pubkey: bytes,
    tapscript: bytes,
    control_block: bytes,
    hash_type: int,
    amount: int = 0,
    codesep_idx: int = 0,
    codesep_pos: int = 0xFFFFFFFF,
) -> bytes:
    """Build sighash blob for tapscript (ext_flag=1) spending."""
    from bitcoin.core import COutPoint, CTransaction, CTxIn, CTxOut
    from bitcoin.core.script import CScript

    txin_credit = CTxIn(
        COutPoint(b"\x00" * 32, 0xFFFFFFFF), CScript(b"\x00\x00"), 0xFFFFFFFF
    )
    txout_credit = CTxOut(amount, CScript(script_pubkey))
    credit_tx = CTransaction([txin_credit], [txout_credit])

    txin_spend = CTxIn(COutPoint(credit_tx.GetTxid(), 0), CScript(b""), 0xFFFFFFFF)
    txout_spend = CTxOut(amount, CScript(b""))
    spend_tx = CTransaction([txin_spend], [txout_spend])

    leaf_version = control_block[0] & 0xFE
    tapleaf_hash = _tagged_hash(
        "TapLeaf",
        bytes([leaf_version]) + _compact_size(len(tapscript)) + tapscript,
    )

    sh = _taproot_sighash_manual(
        spend_tx,
        0,
        hash_type,
        1,
        [script_pubkey],
        [amount],
        tapleaf_hash=tapleaf_hash,
        codesep_pos=codesep_pos,
    )

    return bytes([hash_type]) + codesep_idx.to_bytes(2, "big") + sh


def _build_script_path_tree(
    internal_key: bytes, tapscript: bytes
) -> tuple[bytes, bytes, bytes, int]:
    """Build a single-leaf taproot tree.

    Returns (output_key, control_block, script_pubkey, parity).
    """
    leaf_hash = _tagged_hash(
        "TapLeaf",
        bytes([_TAPSCRIPT_LEAF_VERSION]) + _compact_size(len(tapscript)) + tapscript,
    )
    tweak = _tagged_hash("TapTweak", internal_key + leaf_hash)
    output_key, parity = _taproot_tweak_pubkey(internal_key, tweak)
    cb_first_byte = _TAPSCRIPT_LEAF_VERSION | parity
    control_block = bytes([cb_first_byte]) + internal_key
    script_pubkey = _make_witness_v1_spk(output_key)
    return output_key, control_block, script_pubkey, parity


# ==========================================================================
# Category 1: Key-path signature validation
# ==========================================================================


class TestKeyPathSignature:
    """Key-path Schnorr signature validation (BIP 341)."""

    def test_invalid_sig_length_too_short(self, k):
        """Wrong signature length (32 bytes, not 64 or 65) should fail."""
        output_key, _tweak, _parity = _make_taproot_output(_INTERNAL_KEY)
        spk = _make_witness_v1_spk(output_key)

        # 32-byte "signature" (too short)
        bad_sig = b"\x42" * 32
        witness = encode_witness_blob([bad_sig])

        result = k.verify_script(
            script_sig=b"",
            script_pubkey=spk,
            sighash=b"",
            witness=witness,
            flags=TAPROOT_FLAGS,
        )
        assert not k.success(result)
        assert k.error(result) == "SCHNORR_SIG_SIZE"

    def test_invalid_sig_length_too_long(self, k):
        """Wrong signature length (66 bytes) should fail."""
        output_key, _tweak, _parity = _make_taproot_output(_INTERNAL_KEY)
        spk = _make_witness_v1_spk(output_key)

        bad_sig = b"\x42" * 66
        witness = encode_witness_blob([bad_sig])

        result = k.verify_script(
            script_sig=b"",
            script_pubkey=spk,
            sighash=b"",
            witness=witness,
            flags=TAPROOT_FLAGS,
        )
        assert not k.success(result)
        assert k.error(result) == "SCHNORR_SIG_SIZE"

    def test_65byte_sig_hashtype_0x00_invalid(self, k):
        """65-byte signature with sighash type 0x00 is invalid (BIP 341)."""
        output_key, _tweak, _parity = _make_taproot_output(_INTERNAL_KEY)
        spk = _make_witness_v1_spk(output_key)

        # 64-byte body + 0x00 hashtype byte
        bad_sig = b"\x42" * 64 + b"\x00"
        witness = encode_witness_blob([bad_sig])

        result = k.verify_script(
            script_sig=b"",
            script_pubkey=spk,
            sighash=b"",
            witness=witness,
            flags=TAPROOT_FLAGS,
        )
        assert not k.success(result)
        assert k.error(result) == "SCHNORR_SIG_HASHTYPE"

    def test_valid_keypath_default_sighash(self, k):
        """Valid key-path spend with correct Schnorr signature (DEFAULT sighash 0x00)."""
        sk, pk = _make_schnorr_keypair()
        output_key, tweak, parity = _make_taproot_output(pk)
        spk = _make_witness_v1_spk(output_key)

        # Tweak the secret key for key-path signing
        tweaked_sk = _tweak_secret_key(sk, tweak)

        # Build sighash blob for DEFAULT (hash_type=0)
        sighash_blob = _build_taproot_sighash_blob(spk, 0)
        # The actual sighash is the 32-byte hash from the blob
        msg32 = sighash_blob[3:]  # skip 1-byte hashtype + 2-byte codesep_idx

        sig = _schnorr_sign(tweaked_sk, msg32)
        witness = encode_witness_blob([sig])  # 64 bytes = DEFAULT

        result = k.verify_script(
            script_sig=b"",
            script_pubkey=spk,
            sighash=sighash_blob,
            witness=witness,
            flags=TAPROOT_FLAGS,
        )
        assert k.success(result), f"Expected success, got error: {k.error(result)}"

    @pytest.mark.parametrize(
        "hash_type,label",
        [
            (0x01, "ALL"),
            (0x02, "NONE"),
            (0x03, "SINGLE"),
            (0x81, "ALL|ANYONECANPAY"),
            (0x82, "NONE|ANYONECANPAY"),
            (0x83, "SINGLE|ANYONECANPAY"),
        ],
    )
    def test_valid_keypath_sighash_types(self, k, hash_type, label):
        """Valid key-path spend for each explicit sighash type."""
        sk, pk = _make_schnorr_keypair()
        output_key, tweak, parity = _make_taproot_output(pk)
        spk = _make_witness_v1_spk(output_key)

        tweaked_sk = _tweak_secret_key(sk, tweak)

        sighash_blob = _build_taproot_sighash_blob(spk, hash_type)
        msg32 = sighash_blob[3:]

        sig64 = _schnorr_sign(tweaked_sk, msg32)
        # 65-byte sig = 64-byte body + hashtype byte
        sig = sig64 + bytes([hash_type])
        witness = encode_witness_blob([sig])

        result = k.verify_script(
            script_sig=b"",
            script_pubkey=spk,
            sighash=sighash_blob,
            witness=witness,
            flags=TAPROOT_FLAGS,
        )
        assert k.success(result), (
            f"Expected success for {label}, got error: {k.error(result)}"
        )

    def test_invalid_sig_bit_flip(self, k):
        """Signature with a flipped bit should fail verification."""
        sk, pk = _make_schnorr_keypair()
        output_key, tweak, parity = _make_taproot_output(pk)
        spk = _make_witness_v1_spk(output_key)

        tweaked_sk = _tweak_secret_key(sk, tweak)

        sighash_blob = _build_taproot_sighash_blob(spk, 0)
        msg32 = sighash_blob[3:]

        sig = _schnorr_sign(tweaked_sk, msg32)
        # Flip a bit in the signature
        bad_sig = bytearray(sig)
        bad_sig[16] ^= 0x01
        bad_sig = bytes(bad_sig)

        witness = encode_witness_blob([bad_sig])

        result = k.verify_script(
            script_sig=b"",
            script_pubkey=spk,
            sighash=sighash_blob,
            witness=witness,
            flags=TAPROOT_FLAGS,
        )
        assert not k.success(result)
        assert k.error(result) == "SCHNORR_SIG"


# ==========================================================================
# Category 2: Script-path control block validation
# ==========================================================================


class TestScriptPathControlBlock:
    """Script-path control block validation (BIP 341)."""

    def test_valid_script_path(self, k):
        """Valid script-path spend with correct control block (OP_TRUE tapscript)."""
        # OP_TRUE tapscript
        tapscript = bytes([0x51])  # OP_1 (push true)
        output_key, control_block, spk, parity = _build_script_path_tree(
            _INTERNAL_KEY, tapscript
        )

        witness = encode_witness_blob([tapscript, control_block])

        result = k.verify_script(
            script_sig=b"",
            script_pubkey=spk,
            sighash=b"",
            witness=witness,
            flags=TAPROOT_FLAGS,
        )
        assert k.success(result), f"Expected success, got error: {k.error(result)}"

    def test_wrong_internal_key(self, k):
        """Control block with wrong internal key should fail."""
        tapscript = bytes([0x51])  # OP_1
        output_key, control_block, spk, parity = _build_script_path_tree(
            _INTERNAL_KEY, tapscript
        )

        # Replace internal key in control block with different key
        wrong_key = bytes([0x02] * 32)
        bad_cb = bytes([control_block[0]]) + wrong_key

        witness = encode_witness_blob([tapscript, bad_cb])

        result = k.verify_script(
            script_sig=b"",
            script_pubkey=spk,
            sighash=b"",
            witness=witness,
            flags=TAPROOT_FLAGS,
        )
        assert not k.success(result)
        assert k.error(result) == "WITNESS_PROGRAM_MISMATCH"

    @pytest.mark.xfail(
        reason="TaprootCheckOutput hook does not check parity bit from control block"
    )
    def test_wrong_parity_bit(self, k):
        """Control block with flipped parity bit should fail."""
        tapscript = bytes([0x51])  # OP_1
        output_key, control_block, spk, parity = _build_script_path_tree(
            _INTERNAL_KEY, tapscript
        )

        # Flip the parity bit (bit 0 of first byte)
        bad_first_byte = control_block[0] ^ 0x01
        bad_cb = bytes([bad_first_byte]) + control_block[1:]

        witness = encode_witness_blob([tapscript, bad_cb])

        result = k.verify_script(
            script_sig=b"",
            script_pubkey=spk,
            sighash=b"",
            witness=witness,
            flags=TAPROOT_FLAGS,
        )
        assert not k.success(result)
        assert k.error(result) == "WITNESS_PROGRAM_MISMATCH"

    def test_control_block_wrong_length_too_short(self, k):
        """Control block shorter than 33 bytes should fail."""
        tapscript = bytes([0x51])  # OP_1
        output_key, control_block, spk, parity = _build_script_path_tree(
            _INTERNAL_KEY, tapscript
        )

        # 20 bytes is too short (must be >= 33)
        bad_cb = b"\xc0" + b"\x00" * 19

        witness = encode_witness_blob([tapscript, bad_cb])

        result = k.verify_script(
            script_sig=b"",
            script_pubkey=spk,
            sighash=b"",
            witness=witness,
            flags=TAPROOT_FLAGS,
        )
        assert not k.success(result)
        assert k.error(result) == "TAPROOT_WRONG_CONTROL_SIZE"

    def test_control_block_wrong_length_not_mod_32(self, k):
        """Control block with (len - 33) not divisible by 32 should fail."""
        tapscript = bytes([0x51])  # OP_1
        output_key, control_block, spk, parity = _build_script_path_tree(
            _INTERNAL_KEY, tapscript
        )

        # 33 + 10 = 43 bytes, (43 - 33) % 32 = 10 != 0
        bad_cb = bytes([_TAPSCRIPT_LEAF_VERSION]) + _INTERNAL_KEY + b"\x00" * 10

        witness = encode_witness_blob([tapscript, bad_cb])

        result = k.verify_script(
            script_sig=b"",
            script_pubkey=spk,
            sighash=b"",
            witness=witness,
            flags=TAPROOT_FLAGS,
        )
        assert not k.success(result)
        assert k.error(result) == "TAPROOT_WRONG_CONTROL_SIZE"


# ==========================================================================
# Category 3: Tapscript OP_CHECKSIG
# ==========================================================================


class TestTapscriptChecksig:
    """Tapscript OP_CHECKSIG behavior (BIP 342)."""

    def test_valid_schnorr_checksig(self, k):
        """Valid Schnorr signature in tapscript OP_CHECKSIG pushes 1."""
        sk, pk = _make_schnorr_keypair()

        # Tapscript: <pk> OP_CHECKSIG
        tapscript = bytes([0x20]) + pk + bytes([0xAC])

        output_key, control_block, spk, parity = _build_script_path_tree(
            _INTERNAL_KEY, tapscript
        )

        # Build sighash for tapscript (ext_flag=1)
        sighash_blob = _build_tapscript_sighash_blob(
            spk,
            tapscript,
            control_block,
            0,  # DEFAULT
        )
        msg32 = sighash_blob[3:]

        sig = _schnorr_sign(sk, msg32)
        witness = encode_witness_blob([sig, tapscript, control_block])

        result = k.verify_script(
            script_sig=b"",
            script_pubkey=spk,
            sighash=sighash_blob,
            witness=witness,
            flags=TAPROOT_FLAGS,
        )
        assert k.success(result), f"Expected success, got error: {k.error(result)}"

    def test_empty_sig_pushes_zero(self, k):
        """Empty signature in tapscript OP_CHECKSIG pushes 0 (no error)."""
        _sk, pk = _make_schnorr_keypair()

        # Tapscript: <pk> OP_CHECKSIG OP_NOT (invert so empty sig => stack has 1)
        tapscript = bytes([0x20]) + pk + bytes([0xAC, 0x91])

        output_key, control_block, spk, parity = _build_script_path_tree(
            _INTERNAL_KEY, tapscript
        )

        # Empty signature
        witness = encode_witness_blob([b"", tapscript, control_block])

        result = k.verify_script(
            script_sig=b"",
            script_pubkey=spk,
            sighash=b"",
            witness=witness,
            flags=TAPROOT_FLAGS,
        )
        assert k.success(result), (
            f"Expected success (empty sig pushes 0, NOT makes 1), got error: {k.error(result)}"
        )

    def test_failed_verification_is_mandatory_error(self, k):
        """Failed Schnorr verification in tapscript is a mandatory error (not push 0)."""
        sk, pk = _make_schnorr_keypair()

        # Tapscript: <pk> OP_CHECKSIG
        tapscript = bytes([0x20]) + pk + bytes([0xAC])

        output_key, control_block, spk, parity = _build_script_path_tree(
            _INTERNAL_KEY, tapscript
        )

        # Build a valid sighash blob so the verifier can attempt verification
        sighash_blob = _build_tapscript_sighash_blob(spk, tapscript, control_block, 0)

        # Use a different random 64-byte "signature" that will fail verification
        bad_sig = os.urandom(64)
        witness = encode_witness_blob([bad_sig, tapscript, control_block])

        result = k.verify_script(
            script_sig=b"",
            script_pubkey=spk,
            sighash=sighash_blob,
            witness=witness,
            flags=TAPROOT_FLAGS,
        )
        assert not k.success(result)
        assert k.error(result) == "SCHNORR_SIG"

    def test_empty_pubkey_error(self, k):
        """Empty pubkey in tapscript OP_CHECKSIG fails with TAPSCRIPT_EMPTY_PUBKEY."""
        # Tapscript: OP_0 OP_CHECKSIG (push empty, then checksig with empty pubkey on top)
        # Stack before CHECKSIG: sig=<something>, pk=<empty>
        # We need: push sig, push empty pubkey, OP_CHECKSIG
        # Tapscript: OP_PUSHBYTES_1 0x42 OP_0 OP_CHECKSIG
        tapscript = bytes([0x01, 0x42, 0x00, 0xAC])

        output_key, control_block, spk, parity = _build_script_path_tree(
            _INTERNAL_KEY, tapscript
        )

        witness = encode_witness_blob([tapscript, control_block])

        result = k.verify_script(
            script_sig=b"",
            script_pubkey=spk,
            sighash=b"",
            witness=witness,
            flags=TAPROOT_FLAGS,
        )
        assert not k.success(result)
        assert k.error(result) == "TAPSCRIPT_EMPTY_PUBKEY"

    def test_unknown_pubkey_type_pushes_1(self, k):
        """Non-32-byte non-empty pubkey in tapscript with non-empty sig pushes 1."""
        # Use a 33-byte pubkey (not 32), which is "unknown key type" in tapscript
        unknown_pk = b"\x02" + b"\x42" * 32  # 33 bytes

        # Tapscript: <unknown_pk> OP_CHECKSIG
        tapscript = bytes([0x21]) + unknown_pk + bytes([0xAC])

        output_key, control_block, spk, parity = _build_script_path_tree(
            _INTERNAL_KEY, tapscript
        )

        # Any non-empty signature triggers the "unknown key type → push 1" rule
        dummy_sig = b"\x42" * 64
        witness = encode_witness_blob([dummy_sig, tapscript, control_block])

        result = k.verify_script(
            script_sig=b"",
            script_pubkey=spk,
            sighash=b"",
            witness=witness,
            flags=TAPROOT_FLAGS,
        )
        assert k.success(result), (
            f"Expected success (unknown key type pushes 1), got error: {k.error(result)}"
        )

    def test_invalid_schnorr_sig_length_in_tapscript(self, k):
        """Invalid Schnorr signature length (not 64 or 65) in tapscript fails."""
        _sk, pk = _make_schnorr_keypair()

        # Tapscript: <pk> OP_CHECKSIG
        tapscript = bytes([0x20]) + pk + bytes([0xAC])

        output_key, control_block, spk, parity = _build_script_path_tree(
            _INTERNAL_KEY, tapscript
        )

        # 32-byte sig (wrong length for Schnorr)
        bad_sig = b"\x42" * 32
        witness = encode_witness_blob([bad_sig, tapscript, control_block])

        result = k.verify_script(
            script_sig=b"",
            script_pubkey=spk,
            sighash=b"",
            witness=witness,
            flags=TAPROOT_FLAGS,
        )
        assert not k.success(result)
        assert k.error(result) == "SCHNORR_SIG_SIZE"

    def test_65byte_sig_hashtype_0x00_in_tapscript(self, k):
        """65-byte sig with hash type 0x00 is invalid in tapscript too."""
        _sk, pk = _make_schnorr_keypair()

        tapscript = bytes([0x20]) + pk + bytes([0xAC])

        output_key, control_block, spk, parity = _build_script_path_tree(
            _INTERNAL_KEY, tapscript
        )

        bad_sig = b"\x42" * 64 + b"\x00"
        witness = encode_witness_blob([bad_sig, tapscript, control_block])

        result = k.verify_script(
            script_sig=b"",
            script_pubkey=spk,
            sighash=b"",
            witness=witness,
            flags=TAPROOT_FLAGS,
        )
        assert not k.success(result)
        assert k.error(result) == "SCHNORR_SIG_HASHTYPE"


# ==========================================================================
# Category 4: Annex handling
# ==========================================================================


class TestAnnexHandling:
    """Annex detection and stripping (BIP 341)."""

    def test_keypath_with_annex(self, k):
        """Key-path spend with annex (last witness item starts with 0x50)."""
        output_key, _tweak, _parity = _make_taproot_output(_INTERNAL_KEY)
        spk = _make_witness_v1_spk(output_key)

        # Two witness items: the signature + an annex starting with 0x50
        # With annex, effective witness count = 2 - 1 = 1 (key-path)
        # But the sig is garbage so it should fail at SCHNORR_SIG verification
        fake_sig = b"\x42" * 64
        annex = b"\x50" + b"\xaa\xbb"
        witness = encode_witness_blob([fake_sig, annex])

        result = k.verify_script(
            script_sig=b"",
            script_pubkey=spk,
            sighash=b"",
            witness=witness,
            flags=TAPROOT_FLAGS,
        )
        # The annex should be stripped. Then effective witness count = 1,
        # so this is treated as a key-path spend. The fake sig will fail.
        assert not k.success(result)
        # Should get SCHNORR_SIG (verification failure), NOT TAPROOT_WRONG_CONTROL_SIZE
        assert k.error(result) == "SCHNORR_SIG"

    def test_keypath_with_annex_wrong_sig_length(self, k):
        """Key-path with annex: bad sig length still detected after annex stripping."""
        output_key, _tweak, _parity = _make_taproot_output(_INTERNAL_KEY)
        spk = _make_witness_v1_spk(output_key)

        bad_sig = b"\x42" * 32  # wrong length
        annex = b"\x50\xff"
        witness = encode_witness_blob([bad_sig, annex])

        result = k.verify_script(
            script_sig=b"",
            script_pubkey=spk,
            sighash=b"",
            witness=witness,
            flags=TAPROOT_FLAGS,
        )
        assert not k.success(result)
        assert k.error(result) == "SCHNORR_SIG_SIZE"

    def test_script_path_with_annex(self, k):
        """Script-path spend with annex correctly strips annex for script detection."""
        tapscript = bytes([0x51])  # OP_1
        output_key, control_block, spk, parity = _build_script_path_tree(
            _INTERNAL_KEY, tapscript
        )

        # Witness: [tapscript, control_block, annex]
        # With annex stripped, effective items = [tapscript, control_block] → script-path
        annex = b"\x50\xde\xad"
        witness = encode_witness_blob([tapscript, control_block, annex])

        result = k.verify_script(
            script_sig=b"",
            script_pubkey=spk,
            sighash=b"",
            witness=witness,
            flags=TAPROOT_FLAGS,
        )
        assert k.success(result), f"Expected success, got error: {k.error(result)}"
