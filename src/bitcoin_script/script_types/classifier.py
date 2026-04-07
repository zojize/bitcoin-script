"""Script type classification by template matching."""

from __future__ import annotations

from enum import Enum, auto

from bitcoin.core.script import CScript


class ScriptType(Enum):
    """Standard Bitcoin script template types."""

    P2PKH = auto()
    P2SH = auto()
    P2WPKH = auto()
    P2WSH = auto()
    P2PK = auto()
    MULTISIG = auto()
    NULL_DATA = auto()
    NONSTANDARD = auto()


def classify(script: CScript) -> ScriptType:
    """Identify the standard script template type."""
    if is_p2pkh(script):
        return ScriptType.P2PKH
    if is_p2sh(script):
        return ScriptType.P2SH
    if is_p2wpkh(script):
        return ScriptType.P2WPKH
    if is_p2wsh(script):
        return ScriptType.P2WSH
    if is_p2pk(script):
        return ScriptType.P2PK
    if is_multisig(script):
        return ScriptType.MULTISIG
    if is_null_data(script):
        return ScriptType.NULL_DATA
    return ScriptType.NONSTANDARD


def is_p2pkh(script: CScript) -> bool:
    """OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG (25 bytes)"""
    r = bytes(script)
    return (
        len(r) == 25
        and r[0] == 0x76  # OP_DUP
        and r[1] == 0xA9  # OP_HASH160
        and r[2] == 0x14  # PUSH 20
        and r[23] == 0x88  # OP_EQUALVERIFY
        and r[24] == 0xAC  # OP_CHECKSIG
    )


def is_p2sh(script: CScript) -> bool:
    """OP_HASH160 <20 bytes> OP_EQUAL (23 bytes)"""
    r = bytes(script)
    return (
        len(r) == 23
        and r[0] == 0xA9  # OP_HASH160
        and r[1] == 0x14  # PUSH 20
        and r[22] == 0x87  # OP_EQUAL
    )


def is_p2wpkh(script: CScript) -> bool:
    """OP_0 <20 bytes> (22 bytes)"""
    r = bytes(script)
    return len(r) == 22 and r[0] == 0x00 and r[1] == 0x14


def is_p2wsh(script: CScript) -> bool:
    """OP_0 <32 bytes> (34 bytes)"""
    r = bytes(script)
    return len(r) == 34 and r[0] == 0x00 and r[1] == 0x20


def is_p2pk(script: CScript) -> bool:
    """<33 or 65 bytes pubkey> OP_CHECKSIG"""
    r = bytes(script)
    if len(r) == 35 and r[0] == 0x21 and r[34] == 0xAC:
        return True
    if len(r) == 67 and r[0] == 0x41 and r[66] == 0xAC:
        return True
    return False


def is_multisig(script: CScript) -> bool:
    """OP_m <pubkeys> OP_n OP_CHECKMULTISIG"""
    r = bytes(script)
    if len(r) < 3:
        return False
    if r[-1] != 0xAE:  # OP_CHECKMULTISIG
        return False
    if not (0x51 <= r[-2] <= 0x60):  # OP_1..OP_16 for n
        return False
    if not (0x51 <= r[0] <= 0x60):  # OP_1..OP_16 for m
        return False
    return True


def is_null_data(script: CScript) -> bool:
    """OP_RETURN <data>"""
    r = bytes(script)
    return len(r) >= 1 and r[0] == 0x6A  # OP_RETURN
