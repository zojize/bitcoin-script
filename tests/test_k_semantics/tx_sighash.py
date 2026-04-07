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

from bitcoin_script.script_utils import (
    extract_last_push,
    extract_push_data,
    find_codesep_positions,
    is_p2sh,
    is_witness_program,
    remove_codeseparators,
)

# All standard hashtype values
_STANDARD_HASHTYPES = [
    SIGHASH_ALL,  # 0x01
    SIGHASH_NONE,  # 0x02
    SIGHASH_SINGLE,  # 0x03
    SIGHASH_ALL | SIGHASH_ANYONECANPAY,  # 0x81
    SIGHASH_NONE | SIGHASH_ANYONECANPAY,  # 0x82
    SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,  # 0x83
]


def _extract_hashtypes_from_data(data_items: list[bytes]) -> set[int]:
    """Extract hashtype bytes from data items that look like DER signatures."""
    hashtypes: set[int] = set()
    for item in data_items:
        if len(item) >= 9 and item[0] == 0x30:
            hashtypes.add(item[-1])
    return hashtypes


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
    sig_data = extract_push_data(script_sig) + witness_items
    hashtypes |= _extract_hashtypes_from_data(sig_data)
    # Don't discard hashtype 0 — some early Bitcoin transactions use it

    # Determine if this is a witness spend
    wp = is_witness_program(script_pubkey)
    if wp is None and is_p2sh(script_pubkey):
        redeem = extract_last_push(script_sig)
        if redeem is not None:
            wp = is_witness_program(redeem)

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
            codesep_pos = find_codesep_positions(ws)
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
    if is_p2sh(script_pubkey):
        redeem = extract_last_push(script_sig)
        if redeem is not None:
            legacy_subscript = redeem

    # Find CODESEPARATOR positions in legacy subscript
    codesep_positions = find_codesep_positions(legacy_subscript)
    legacy_subscripts: list[tuple[int, bytes]] = [
        (0, remove_codeseparators(legacy_subscript))
    ]
    for idx, bp in enumerate(codesep_positions):
        legacy_subscripts.append(
            (idx + 1, remove_codeseparators(legacy_subscript[bp:]))
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
