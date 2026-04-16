from __future__ import annotations

import ctypes
import hashlib
import json
import urllib.request
from pathlib import Path

import pytest
from bitcoin.core import CTransaction, CTxIn, CTxOut, COutPoint
from bitcoin.core.script import (
    CScript,
    SIGHASH_ALL,
    SIGHASH_ANYONECANPAY,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
    SIGVERSION_WITNESS_V0,
    SignatureHash,
)

from bitcoin_script.k_semantics import KBitcoinScript, ScriptDist
from bitcoin_script.script_utils import (
    encode_witness_blob,  # noqa: F401 (re-exported for test modules)
    extract_last_push,
    extract_sig_hashtypes,
    find_codesep_positions,
    is_p2sh,
    is_witness_program,
    remove_codeseparators,
)

DATA_DIR = Path(__file__).parent / "data"
_VECTOR_BASE = "https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/test/data"
VECTOR_URLS = {
    "script_tests.json": f"{_VECTOR_BASE}/script_tests.json",
    "tx_valid.json": f"{_VECTOR_BASE}/tx_valid.json",
    "tx_invalid.json": f"{_VECTOR_BASE}/tx_invalid.json",
}

# Bitcoin Core SCRIPT_VERIFY_* flags (bitmask values)
SCRIPT_FLAGS: dict[str, int] = {
    "P2SH": 1 << 0,
    "STRICTENC": 1 << 1,
    "DERSIG": 1 << 2,
    "LOW_S": 1 << 3,
    "NULLDUMMY": 1 << 4,
    "SIGPUSHONLY": 1 << 5,
    "MINIMALDATA": 1 << 6,
    "DISCOURAGE_UPGRADABLE_NOPS": 1 << 7,
    "CLEANSTACK": 1 << 8,
    "CHECKLOCKTIMEVERIFY": 1 << 9,
    "CHECKSEQUENCEVERIFY": 1 << 10,
    "WITNESS": 1 << 11,
    "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM": 1 << 12,
    "MINIMALIF": 1 << 13,
    "NULLFAIL": 1 << 14,
    "WITNESS_PUBKEYTYPE": 1 << 15,
    "COMPRESSED_PUBKEYTYPE": 1 << 15,
    "CONST_SCRIPTCODE": 1 << 16,
    "TAPROOT": 1 << 17,
}


def flags_to_bitmask(flags: set[str]) -> int:
    """Convert a set of flag name strings to a bitmask integer."""
    mask = 0
    for f in flags:
        mask |= SCRIPT_FLAGS.get(f, 0)
    return mask


# All standard hashtype values
_STANDARD_HASHTYPES = [
    SIGHASH_ALL,  # 0x01
    SIGHASH_NONE,  # 0x02
    SIGHASH_SINGLE,  # 0x03
    SIGHASH_ALL | SIGHASH_ANYONECANPAY,  # 0x81
    SIGHASH_NONE | SIGHASH_ANYONECANPAY,  # 0x82
    SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,  # 0x83
]


def load_vector(name: str) -> list:
    """Download a Bitcoin Core test vector file (cached locally)."""
    DATA_DIR.mkdir(exist_ok=True)
    path = DATA_DIR / name
    if not path.exists():
        urllib.request.urlretrieve(VECTOR_URLS[name], path)
    return json.loads(path.read_text())


# ── Sighash computation (matching Bitcoin Core's test harness) ──────────


def build_crediting_transaction(script_pubkey: bytes, n_value: int = 0) -> CTransaction:
    """Build the deterministic crediting tx (matches Bitcoin Core's BuildCreditingTransaction)."""
    txin = CTxIn(COutPoint(b"\x00" * 32, 0xFFFFFFFF), CScript(b"\x00\x00"), 0xFFFFFFFF)
    txout = CTxOut(n_value, CScript(script_pubkey))
    return CTransaction([txin], [txout])


def build_spending_transaction(
    script_sig: bytes, credit_tx: CTransaction
) -> CTransaction:
    """Build the deterministic spending tx (matches Bitcoin Core's BuildSpendingTransaction)."""
    txin = CTxIn(COutPoint(credit_tx.GetTxid(), 0), CScript(script_sig), 0xFFFFFFFF)
    txout = CTxOut(credit_tx.vout[0].nValue, CScript())
    return CTransaction([txin], [txout])


def compute_sighash_blob(
    script_pubkey: bytes,
    script_sig: bytes,
    hashtypes: set[int] | None = None,
) -> bytes:
    """Compute sighash for each hashtype and return as a concatenated blob.

    Format: N entries of (1-byte hashtype + 2-byte BE codesepIdx + 32-byte sighash).
    For P2SH, computes against the redeem script (last push in scriptSig).
    Automatically includes hashtypes found in signatures within the scripts.
    Computes sighashes for each CODESEPARATOR position in the subscript.
    """
    if hashtypes is None:
        hashtypes = set(_STANDARD_HASHTYPES)
    # Also include any non-standard hashtypes found in the actual signatures
    hashtypes |= extract_sig_hashtypes(script_sig)
    hashtypes |= extract_sig_hashtypes(script_pubkey)
    hashtypes.discard(0)  # hashtype 0 is not valid

    # For P2SH, the sighash is computed against the redeem script
    subscript = script_pubkey
    if is_p2sh(script_pubkey):
        redeem = extract_last_push(script_sig)
        if redeem is not None:
            subscript = redeem

    credit_tx = build_crediting_transaction(script_pubkey)
    spend_tx = build_spending_transaction(script_sig, credit_tx)

    # Find CODESEPARATOR positions in the subscript
    codesep_positions = find_codesep_positions(subscript)

    # Build list of (codesep_index, subscript_from_position) pairs
    # Index 0 = full subscript (no CODESEPARATOR seen yet), with CODESEPs removed
    subscripts: list[tuple[int, bytes]] = [(0, remove_codeseparators(subscript))]
    for idx, byte_pos in enumerate(codesep_positions):
        subscripts.append((idx + 1, remove_codeseparators(subscript[byte_pos:])))

    parts = []
    for csi, sub in subscripts:
        for ht in sorted(hashtypes):
            try:
                sh = SignatureHash(CScript(sub), spend_tx, 0, ht)
            except AssertionError, ValueError:
                # Witness scriptPubKeys use BIP-143 sighash (not legacy SignatureHash)
                continue
            parts.append(bytes([ht]) + csi.to_bytes(2, "big") + bytes(sh))
    return b"".join(parts)


def compute_witness_sighash_blob(
    script_pubkey: bytes,
    script_sig: bytes,
    witness_items: list[bytes],
    amount_satoshis: int,
    hashtypes: set[int] | None = None,
) -> bytes:
    """Compute BIP-143 sighash for witness scripts.

    Determines the correct subscript based on the witness program type:
    - P2WPKH (20-byte program): OP_DUP OP_HASH160 <program> OP_EQUALVERIFY OP_CHECKSIG
    - P2WSH (32-byte program): the witness script (last witness item)
    - P2SH-wrapped: extract witness program from redeem script
    """
    if hashtypes is None:
        hashtypes = set(_STANDARD_HASHTYPES)
    # Include hashtypes from witness items (signatures)
    for item in witness_items:
        if len(item) >= 9 and item[0] == 0x30:
            hashtypes.add(item[-1])
    hashtypes.discard(0)

    # Determine witness program
    wp = is_witness_program(script_pubkey)
    if wp is None and is_p2sh(script_pubkey):
        redeem = extract_last_push(script_sig)
        if redeem is not None:
            wp = is_witness_program(redeem)

    if wp is None:
        # Not a witness program — fall back to legacy sighash
        return compute_sighash_blob(script_pubkey, script_sig, hashtypes)

    version, program = wp
    if version == 0 and len(program) == 20:
        # P2WPKH: subscript is synthetic P2PKH
        subscript = CScript(bytes([0x76, 0xA9, 0x14]) + program + bytes([0x88, 0xAC]))
    elif version == 0 and len(program) == 32 and witness_items:
        # P2WSH: subscript is the witness script (last witness item)
        subscript = CScript(witness_items[-1])
    else:
        return b""

    credit_tx = build_crediting_transaction(script_pubkey, amount_satoshis)
    spend_tx = build_spending_transaction(script_sig, credit_tx)

    # For witness v0, CODESEPARATOR positions in the witness script
    # BIP-143: scriptCode does NOT strip OP_CODESEPARATOR bytes (unlike legacy)
    # It just starts from after the last executed CODESEP
    if version == 0 and len(program) == 32 and witness_items:
        witness_script = witness_items[-1]
        codesep_positions = find_codesep_positions(witness_script)
    else:
        codesep_positions = []

    # Build subscripts for each CODESEPARATOR index
    subscripts_list: list[tuple[int, CScript]] = [(0, subscript)]
    if version == 0 and len(program) == 32 and witness_items:
        for idx, byte_pos in enumerate(codesep_positions):
            subscripts_list.append((idx + 1, CScript(witness_items[-1][byte_pos:])))

    parts = []
    for csi, sub in subscripts_list:
        for ht in sorted(hashtypes):
            try:
                sh = SignatureHash(
                    sub,
                    spend_tx,
                    0,
                    ht,
                    amount=amount_satoshis,
                    sigversion=SIGVERSION_WITNESS_V0,
                )
            except AssertionError, ValueError:
                continue
            parts.append(bytes([ht]) + csi.to_bytes(2, "big") + bytes(sh))

    # Also include legacy sighashes (some P2SH-wrapped tests may need both)
    legacy_parts = compute_sighash_blob(script_pubkey, script_sig, hashtypes)
    # Merge: BIP-143 sighashes take precedence (come first in blob)
    return b"".join(parts) + legacy_parts


# ── Taproot placeholder expansion ─────────────────────────────────────


def _tagged_hash(tag: str, msg: bytes) -> bytes:
    """BIP 340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg)."""
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()


def _compact_size(n: int) -> bytes:
    """Bitcoin compact size encoding."""
    if n <= 252:
        return n.to_bytes(1, "little")
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def _find_libsecp256k1() -> ctypes.CDLL:
    """Find and load libsecp256k1 from nix store or system."""
    import ctypes.util
    import glob

    # Nix store (macOS .dylib and Linux .so)
    for pattern in [
        "/nix/store/*-secp256k1-*/lib/libsecp256k1.dylib",
        "/nix/store/*-secp256k1-*/lib/libsecp256k1.so",
    ]:
        for p in sorted(glob.glob(pattern), reverse=True):
            try:
                return ctypes.CDLL(p)
            except OSError:
                continue
    # Common system paths
    for p in [
        "/opt/homebrew/lib/libsecp256k1.dylib",
        "/usr/local/lib/libsecp256k1.so",
        "/usr/lib/libsecp256k1.so",
        "/usr/lib/x86_64-linux-gnu/libsecp256k1.so",
        "/usr/lib/aarch64-linux-gnu/libsecp256k1.so",
    ]:
        try:
            return ctypes.CDLL(p)
        except OSError:
            continue
    # ctypes.util.find_library as last resort
    path = ctypes.util.find_library("secp256k1")
    if path:
        try:
            return ctypes.CDLL(path)
        except OSError:
            pass
    raise RuntimeError("libsecp256k1 not found")


def _taproot_tweak_pubkey(internal_key: bytes, tweak: bytes) -> tuple[bytes, int]:
    """Compute taproot tweaked pubkey: Q = P + t*G.

    Returns (x_only_output_key, parity).
    """
    lib = _find_libsecp256k1()

    # secp256k1_context_create
    lib.secp256k1_context_create.restype = ctypes.c_void_p
    lib.secp256k1_context_create.argtypes = [ctypes.c_uint]
    ctx = lib.secp256k1_context_create(0x0101)  # VERIFY | SIGN

    # Parse x-only pubkey
    xonly_buf = (ctypes.c_ubyte * 64)()  # secp256k1_xonly_pubkey is 64 bytes
    lib.secp256k1_xonly_pubkey_parse.restype = ctypes.c_int
    lib.secp256k1_xonly_pubkey_parse.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_char_p,
    ]
    ok = lib.secp256k1_xonly_pubkey_parse(ctx, xonly_buf, internal_key)
    assert ok == 1, "Failed to parse internal key"

    # Tweak add
    pubkey_buf = (ctypes.c_ubyte * 64)()  # secp256k1_pubkey is 64 bytes
    lib.secp256k1_xonly_pubkey_tweak_add.restype = ctypes.c_int
    lib.secp256k1_xonly_pubkey_tweak_add.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_char_p,
    ]
    ok = lib.secp256k1_xonly_pubkey_tweak_add(ctx, pubkey_buf, xonly_buf, tweak)
    assert ok == 1, "Failed to tweak pubkey"

    # Extract x-only from tweaked pubkey
    tweaked_xonly = (ctypes.c_ubyte * 64)()
    parity_out = ctypes.c_int(0)
    lib.secp256k1_xonly_pubkey_from_pubkey.restype = ctypes.c_int
    lib.secp256k1_xonly_pubkey_from_pubkey.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_int),
        ctypes.c_void_p,
    ]
    ok = lib.secp256k1_xonly_pubkey_from_pubkey(
        ctx, tweaked_xonly, ctypes.byref(parity_out), pubkey_buf
    )
    assert ok == 1, "Failed to extract x-only from tweaked pubkey"

    # Serialize x-only
    output = (ctypes.c_ubyte * 32)()
    lib.secp256k1_xonly_pubkey_serialize.restype = ctypes.c_int
    lib.secp256k1_xonly_pubkey_serialize.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    lib.secp256k1_xonly_pubkey_serialize(ctx, output, tweaked_xonly)

    lib.secp256k1_context_destroy.restype = None
    lib.secp256k1_context_destroy.argtypes = [ctypes.c_void_p]
    lib.secp256k1_context_destroy(ctx)

    return bytes(output), parity_out.value


# Deterministic internal key for test vectors (a valid x-only pubkey).
# This is the x-coordinate of the generator point G on secp256k1.
_INTERNAL_KEY = bytes.fromhex(
    "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
)

# Default tapscript leaf version (0xc0 per BIP 342)
_TAPSCRIPT_LEAF_VERSION = 0xC0


def expand_taproot_witness(
    witness_hex_list: list[str],
    pubkey_asm: str,
) -> tuple[list[bytes], str]:
    """Expand #SCRIPT#, #CONTROLBLOCK#, #TAPROOTOUTPUT# in taproot test vectors.

    Returns (expanded_witness_items, expanded_pubkey_asm).
    """
    from .bitcoin_core_vectors import parse_bitcoin_core_asm

    # Find the script item (contains "#SCRIPT#") and control block placeholder
    script_idx = -1
    for i, item in enumerate(witness_hex_list):
        if "#SCRIPT#" in item:
            script_idx = i
            break

    if script_idx == -1:
        # No taproot placeholders — return as-is
        return [bytes.fromhex(h) for h in witness_hex_list], pubkey_asm

    # Parse the tapscript ASM (everything after "#SCRIPT#")
    script_asm = witness_hex_list[script_idx].replace("#SCRIPT#", "").strip()
    tapscript = parse_bitcoin_core_asm(script_asm)

    # Compute leaf hash: TaggedHash("TapLeaf", leaf_version || compact_size(len) || script)
    leaf_hash = _tagged_hash(
        "TapLeaf",
        bytes([_TAPSCRIPT_LEAF_VERSION]) + _compact_size(len(tapscript)) + tapscript,
    )

    # Merkle root = leaf hash (single leaf, no sibling nodes)
    merkle_root = leaf_hash

    # Compute tweak: TaggedHash("TapTweak", internal_key || merkle_root)
    tweak = _tagged_hash("TapTweak", _INTERNAL_KEY + merkle_root)

    # Compute tweaked output key via libsecp256k1 ctypes
    output_key, parity = _taproot_tweak_pubkey(_INTERNAL_KEY, tweak)

    # Build control block: leaf_version | parity (1 byte) + internal_key (32 bytes)
    # No merkle path nodes (single leaf)
    cb_first_byte = _TAPSCRIPT_LEAF_VERSION | parity
    control_block = bytes([cb_first_byte]) + _INTERNAL_KEY

    # Expand witness items
    expanded: list[bytes] = []
    for item in witness_hex_list:
        if "#SCRIPT#" in item:
            expanded.append(tapscript)
        elif item == "#CONTROLBLOCK#":
            expanded.append(control_block)
        else:
            expanded.append(bytes.fromhex(item))

    # Expand scriptPubKey: replace #TAPROOTOUTPUT# with hex of output key
    expanded_pubkey_asm = pubkey_asm.replace("#TAPROOTOUTPUT#", output_key.hex())

    return expanded, expanded_pubkey_asm


@pytest.fixture(scope="session")
def _dist() -> ScriptDist:
    return ScriptDist.load()


@pytest.fixture(scope="session")
def k(_dist: ScriptDist) -> KBitcoinScript:
    """Shared KBitcoinScript instance (auto-detects hex vs ASM from input)."""
    return KBitcoinScript(_dist)


@pytest.fixture(scope="session")
def k_hex(_dist: ScriptDist) -> KBitcoinScript:
    """Alias for k — kept for test readability."""
    return KBitcoinScript(_dist)
