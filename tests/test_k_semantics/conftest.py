from __future__ import annotations

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


def _is_p2sh(script_pubkey: bytes) -> bool:
    """Check if scriptPubKey is P2SH: OP_HASH160 <20 bytes> OP_EQUAL."""
    return (
        len(script_pubkey) == 23
        and script_pubkey[0] == 0xA9
        and script_pubkey[1] == 0x14
        and script_pubkey[22] == 0x87
    )


def _extract_redeem_script(script_sig: bytes) -> bytes | None:
    """Extract the last push from scriptSig (the P2SH redeem script).

    Walks the script byte-by-byte following push opcodes to find the final push.
    """
    pos = 0
    last_push: bytes | None = None
    while pos < len(script_sig):
        op = script_sig[pos]
        pos += 1
        if 1 <= op <= 75:
            last_push = script_sig[pos : pos + op]
            pos += op
        elif op == 0x4C and pos < len(script_sig):  # PUSHDATA1
            n = script_sig[pos]
            pos += 1
            last_push = script_sig[pos : pos + n]
            pos += n
        elif op == 0x4D and pos + 1 < len(script_sig):  # PUSHDATA2
            n = int.from_bytes(script_sig[pos : pos + 2], "little")
            pos += 2
            last_push = script_sig[pos : pos + n]
            pos += n
        elif op == 0x4E and pos + 3 < len(script_sig):  # PUSHDATA4
            n = int.from_bytes(script_sig[pos : pos + 4], "little")
            pos += 4
            last_push = script_sig[pos : pos + n]
            pos += n
        # else: opcode without data, skip
    return last_push


def _extract_hashtypes_from_script(script: bytes) -> set[int]:
    """Extract hashtype bytes from DER signatures embedded in script push data."""
    hashtypes: set[int] = set()
    pos = 0
    while pos < len(script):
        op = script[pos]
        pos += 1
        data: bytes | None = None
        if 1 <= op <= 75:
            data = script[pos : pos + op]
            pos += op
        elif op == 0x4C and pos < len(script):  # PUSHDATA1
            n = script[pos]
            pos += 1
            data = script[pos : pos + n]
            pos += n
        elif op == 0x4D and pos + 1 < len(script):  # PUSHDATA2
            n = int.from_bytes(script[pos : pos + 2], "little")
            pos += 2
            data = script[pos : pos + n]
            pos += n
        elif op == 0x4E and pos + 3 < len(script):  # PUSHDATA4
            n = int.from_bytes(script[pos : pos + 4], "little")
            pos += 4
            data = script[pos : pos + n]
            pos += n
        # Check if push data looks like a DER signature (starts with 0x30, length >= 9)
        if data is not None and len(data) >= 9 and data[0] == 0x30:
            hashtypes.add(data[-1])
    return hashtypes


def compute_sighash_blob(
    script_pubkey: bytes,
    script_sig: bytes,
    hashtypes: set[int] | None = None,
) -> bytes:
    """Compute sighash for each hashtype and return as a concatenated blob.

    Format: N entries of (1-byte hashtype + 32-byte sighash).
    For P2SH, computes against the redeem script (last push in scriptSig).
    Automatically includes hashtypes found in signatures within the scripts.
    """
    if hashtypes is None:
        hashtypes = set(_STANDARD_HASHTYPES)
    # Also include any non-standard hashtypes found in the actual signatures
    hashtypes |= _extract_hashtypes_from_script(script_sig)
    hashtypes |= _extract_hashtypes_from_script(script_pubkey)
    hashtypes.discard(0)  # hashtype 0 is not valid

    # For P2SH, the sighash is computed against the redeem script
    subscript = script_pubkey
    if _is_p2sh(script_pubkey):
        redeem = _extract_redeem_script(script_sig)
        if redeem is not None:
            subscript = redeem

    credit_tx = build_crediting_transaction(script_pubkey)
    spend_tx = build_spending_transaction(script_sig, credit_tx)

    parts = []
    for ht in sorted(hashtypes):
        try:
            sh = SignatureHash(CScript(subscript), spend_tx, 0, ht)
        except AssertionError, ValueError:
            # Witness scriptPubKeys use BIP-143 sighash (not legacy SignatureHash)
            continue
        parts.append(bytes([ht]) + bytes(sh))
    return b"".join(parts)


def _is_witness_program(script: bytes) -> tuple[int, bytes] | None:
    """Detect witness program: <version_byte> <push_2_to_40_bytes>."""
    if len(script) < 4 or len(script) > 42:
        return None
    version_byte = script[0]
    if version_byte == 0x00:
        version = 0
    elif 0x51 <= version_byte <= 0x60:
        version = version_byte - 0x50
    else:
        return None
    if script[1] + 2 != len(script):
        return None
    return (version, script[2:])


def encode_witness_blob(items: list[bytes]) -> bytes:
    """Encode witness stack as: <2B BE count> (<2B BE length> <data>)*"""
    result = len(items).to_bytes(2, "big")
    for item in items:
        result += len(item).to_bytes(2, "big") + item
    return result


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
    wp = _is_witness_program(script_pubkey)
    if wp is None and _is_p2sh(script_pubkey):
        redeem = _extract_redeem_script(script_sig)
        if redeem is not None:
            wp = _is_witness_program(redeem)

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

    parts = []
    for ht in sorted(hashtypes):
        try:
            sh = SignatureHash(
                subscript,
                spend_tx,
                0,
                ht,
                amount=amount_satoshis,
                sigversion=SIGVERSION_WITNESS_V0,
            )
        except AssertionError, ValueError:
            continue
        parts.append(bytes([ht]) + bytes(sh))

    # Also include legacy sighashes (some P2SH-wrapped tests may need both)
    legacy_parts = compute_sighash_blob(script_pubkey, script_sig, hashtypes)
    # Merge: BIP-143 sighashes take precedence (come first in blob)
    return b"".join(parts) + legacy_parts


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
