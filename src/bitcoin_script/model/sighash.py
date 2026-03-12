"""Signature hash computation for transaction signing/verification."""

from __future__ import annotations

from enum import IntFlag

from bitcoin_script.model.transaction import Transaction
from bitcoin_script.types import ScriptBytes


class SigHashType(IntFlag):
    """Signature hash type flags."""

    ALL = 0x01
    NONE = 0x02
    SINGLE = 0x03
    ANYONECANPAY = 0x80


def sighash_legacy(
    tx: Transaction,
    input_index: int,
    script_code: ScriptBytes,
    hash_type: SigHashType,
) -> bytes:
    """Compute the legacy (pre-segwit) signature hash.

    Serializes the transaction with the appropriate modifications
    based on hash_type, then returns the double SHA-256 (32 bytes).

    Note: Must reproduce the SIGHASH_SINGLE bug (returns 0x01 + 31 zero bytes
    when input_index >= len(outputs)).
    """
    ...


def sighash_segwit_v0(
    tx: Transaction,
    input_index: int,
    script_code: ScriptBytes,
    value: int,
    hash_type: SigHashType,
) -> bytes:
    """Compute the BIP143 segwit v0 signature hash.

    Args:
        tx: The transaction being signed.
        input_index: Index of the input being signed.
        script_code: The script code for the input.
        value: The value of the output being spent (in satoshis).
        hash_type: The signature hash type.

    Returns:
        32-byte signature hash.
    """
    ...
