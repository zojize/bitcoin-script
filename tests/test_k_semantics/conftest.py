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

# All standard hashtype values
_STANDARD_HASHTYPES = [
    SIGHASH_ALL,                            # 0x01
    SIGHASH_NONE,                           # 0x02
    SIGHASH_SINGLE,                         # 0x03
    SIGHASH_ALL | SIGHASH_ANYONECANPAY,     # 0x81
    SIGHASH_NONE | SIGHASH_ANYONECANPAY,    # 0x82
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


def build_crediting_transaction(script_pubkey: bytes) -> CTransaction:
    """Build the deterministic crediting tx (matches Bitcoin Core's BuildCreditingTransaction)."""
    txin = CTxIn(COutPoint(b"\x00" * 32, 0xFFFFFFFF), CScript(b"\x00\x00"), 0xFFFFFFFF)
    txout = CTxOut(0, CScript(script_pubkey))
    return CTransaction([txin], [txout])


def build_spending_transaction(script_sig: bytes, credit_tx: CTransaction) -> CTransaction:
    """Build the deterministic spending tx (matches Bitcoin Core's BuildSpendingTransaction)."""
    txin = CTxIn(COutPoint(credit_tx.GetTxid(), 0), CScript(script_sig), 0xFFFFFFFF)
    txout = CTxOut(0, CScript())
    return CTransaction([txin], [txout])


def _is_p2sh(script_pubkey: bytes) -> bool:
    """Check if scriptPubKey is P2SH: OP_HASH160 <20 bytes> OP_EQUAL."""
    return len(script_pubkey) == 23 and script_pubkey[0] == 0xA9 and script_pubkey[1] == 0x14 and script_pubkey[22] == 0x87


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
        sh = SignatureHash(CScript(subscript), spend_tx, 0, ht)
        parts.append(bytes([ht]) + bytes(sh))
    return b"".join(parts)


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
