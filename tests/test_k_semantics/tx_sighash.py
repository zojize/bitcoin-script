"""Compute sighash blobs for real Bitcoin transactions.

Unlike conftest.py's compute_sighash_blob (which uses synthetic crediting/spending
transactions for script_tests.json vectors), this module computes sighash against
actual CTransaction objects — needed for tx_valid.json / tx_invalid.json vectors
and eventually for mainnet block verification.
"""

from __future__ import annotations

from bitcoin.core import CTransaction
from bitcoin.core.script import (
    CScript,
    CScriptTruncatedPushDataError,
    SIGHASH_ALL,
    SIGHASH_ANYONECANPAY,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
    SIGVERSION_WITNESS_V0,
    SignatureHash,
)

from .conftest import _find_codesep_positions, _remove_codeseparators

# All standard hashtype values
_STANDARD_HASHTYPES = [
    SIGHASH_ALL,  # 0x01
    SIGHASH_NONE,  # 0x02
    SIGHASH_SINGLE,  # 0x03
    SIGHASH_ALL | SIGHASH_ANYONECANPAY,  # 0x81
    SIGHASH_NONE | SIGHASH_ANYONECANPAY,  # 0x82
    SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,  # 0x83
]


def _is_p2sh(script_pubkey: bytes) -> bool:
    """Check if scriptPubKey is P2SH: OP_HASH160 <20 bytes> OP_EQUAL."""
    return (
        len(script_pubkey) == 23
        and script_pubkey[0] == 0xA9
        and script_pubkey[1] == 0x14
        and script_pubkey[22] == 0x87
    )


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


def _extract_last_push(script: bytes) -> bytes | None:
    """Extract the last push from a script (for P2SH redeem script extraction)."""
    pos = 0
    last_push: bytes | None = None
    while pos < len(script):
        op = script[pos]
        pos += 1
        if 1 <= op <= 75:
            last_push = script[pos : pos + op]
            pos += op
        elif op == 0x4C and pos < len(script):  # PUSHDATA1
            n = script[pos]
            pos += 1
            last_push = script[pos : pos + n]
            pos += n
        elif op == 0x4D and pos + 1 < len(script):  # PUSHDATA2
            n = int.from_bytes(script[pos : pos + 2], "little")
            pos += 2
            last_push = script[pos : pos + n]
            pos += n
        elif op == 0x4E and pos + 3 < len(script):  # PUSHDATA4
            n = int.from_bytes(script[pos : pos + 4], "little")
            pos += 4
            last_push = script[pos : pos + n]
            pos += n
    return last_push


def _extract_hashtypes_from_data(data_items: list[bytes]) -> set[int]:
    """Extract hashtype bytes from data items that look like DER signatures."""
    hashtypes: set[int] = set()
    for item in data_items:
        if len(item) >= 9 and item[0] == 0x30:
            hashtypes.add(item[-1])
    return hashtypes


def _extract_push_data(script: bytes) -> list[bytes]:
    """Walk script and extract all push data items."""
    items: list[bytes] = []
    pos = 0
    while pos < len(script):
        op = script[pos]
        pos += 1
        if 1 <= op <= 75:
            items.append(script[pos : pos + op])
            pos += op
        elif op == 0x4C and pos < len(script):
            n = script[pos]
            pos += 1
            items.append(script[pos : pos + n])
            pos += n
        elif op == 0x4D and pos + 1 < len(script):
            n = int.from_bytes(script[pos : pos + 2], "little")
            pos += 2
            items.append(script[pos : pos + n])
            pos += n
        elif op == 0x4E and pos + 3 < len(script):
            n = int.from_bytes(script[pos : pos + 4], "little")
            pos += 4
            items.append(script[pos : pos + n])
            pos += n
    return items


def compute_tx_sighash_blob(
    tx: CTransaction,
    input_index: int,
    script_pubkey: bytes,
    amount: int,
    script_sig: bytes,
    witness_items: list[bytes] | None = None,
) -> bytes:
    """Compute sighash blob for a real transaction input.

    Returns concatenated (1-byte hashtype + 2-byte BE codesepIdx + 32-byte sighash)
    entries for all standard hashtypes plus any found in signatures.
    Computes sighashes for each CODESEPARATOR position in the subscript.

    Detects witness vs legacy based on script type and computes accordingly.
    """
    if witness_items is None:
        witness_items = []

    # Gather hashtypes from signatures in scriptSig and witness
    hashtypes: set[int] = set(_STANDARD_HASHTYPES)
    sig_data = _extract_push_data(script_sig) + witness_items
    hashtypes |= _extract_hashtypes_from_data(sig_data)
    # Don't discard hashtype 0 — some early Bitcoin transactions use it

    # Determine if this is a witness spend
    wp = _is_witness_program(script_pubkey)
    if wp is None and _is_p2sh(script_pubkey):
        redeem = _extract_last_push(script_sig)
        if redeem is not None:
            wp = _is_witness_program(redeem)

    parts: list[bytes] = []

    if wp is not None and wp[0] == 0:
        _version, program = wp
        # BIP-143 witness v0 sighash
        if len(program) == 20:
            # P2WPKH: no CODESEPARATOR possible in synthetic P2PKH
            subscript = CScript(
                bytes([0x76, 0xA9, 0x14]) + program + bytes([0x88, 0xAC])
            )
            witness_subscripts: list[tuple[int, CScript]] = [(0, subscript)]
        elif len(program) == 32 and witness_items:
            # P2WSH: witness script may contain CODESEPARATOR
            # BIP-143: scriptCode does NOT strip CODESEP bytes (unlike legacy)
            ws = witness_items[-1]
            codesep_pos = _find_codesep_positions(ws)
            witness_subscripts = [(0, CScript(ws))]
            for idx, bp in enumerate(codesep_pos):
                witness_subscripts.append((idx + 1, CScript(ws[bp:])))
        else:
            witness_subscripts = []

        for csi, sub in witness_subscripts:
            for ht in sorted(hashtypes):
                try:
                    sh = SignatureHash(
                        sub,
                        tx,
                        input_index,
                        ht,
                        amount=amount,
                        sigversion=SIGVERSION_WITNESS_V0,
                    )
                    parts.append(bytes([ht]) + csi.to_bytes(2, "big") + bytes(sh))
                except AssertionError, ValueError, CScriptTruncatedPushDataError:
                    continue

    # Legacy sighash (always compute — some P2SH-wrapped cases need both)
    legacy_subscript = script_pubkey
    if _is_p2sh(script_pubkey):
        redeem = _extract_last_push(script_sig)
        if redeem is not None:
            legacy_subscript = redeem

    # Find CODESEPARATOR positions in legacy subscript
    codesep_positions = _find_codesep_positions(legacy_subscript)
    legacy_subscripts: list[tuple[int, bytes]] = [
        (0, _remove_codeseparators(legacy_subscript))
    ]
    for idx, bp in enumerate(codesep_positions):
        legacy_subscripts.append(
            (idx + 1, _remove_codeseparators(legacy_subscript[bp:]))
        )

    for csi, sub in legacy_subscripts:
        for ht in sorted(hashtypes):
            try:
                sh = SignatureHash(CScript(sub), tx, input_index, ht)
                parts.append(bytes([ht]) + csi.to_bytes(2, "big") + bytes(sh))
            except ValueError, CScriptTruncatedPushDataError:
                # SIGHASH_SINGLE bug
                if (ht & 0x1F) == SIGHASH_SINGLE and input_index >= len(tx.vout):
                    sighash_single_bug = b"\x01" + b"\x00" * 31
                    parts.append(
                        bytes([ht]) + csi.to_bytes(2, "big") + sighash_single_bug
                    )
                continue
            except AssertionError:
                continue

    return b"".join(parts)
