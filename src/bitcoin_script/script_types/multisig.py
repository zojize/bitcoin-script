"""Bare multisig (OP_m <pubkeys> OP_n OP_CHECKMULTISIG) script handling."""

from __future__ import annotations

from bitcoin.core.script import CScript


def extract_pubkeys(script_pubkey: CScript) -> tuple[int, list[bytes]]:
    """Extract m and the public keys from a bare multisig scriptPubKey.

    Returns:
        (m, pubkeys) where m is the required signature count.

    Raises:
        ValueError: If the script is not a valid multisig template.
    """
    r = bytes(script_pubkey)
    if len(r) < 3 or r[-1] != 0xAE:  # OP_CHECKMULTISIG
        raise ValueError("Not a multisig scriptPubKey")
    if not (0x51 <= r[0] <= 0x60):
        raise ValueError("Not a multisig scriptPubKey")
    if not (0x51 <= r[-2] <= 0x60):
        raise ValueError("Not a multisig scriptPubKey")

    m = r[0] - 0x50
    n = r[-2] - 0x50

    pubkeys: list[bytes] = []
    pos = 1
    for _ in range(n):
        if pos >= len(r) - 2:
            raise ValueError("Not a multisig scriptPubKey")
        key_len = r[pos]
        if key_len not in (33, 65):
            raise ValueError("Not a multisig scriptPubKey")
        pos += 1
        pubkeys.append(r[pos : pos + key_len])
        pos += key_len

    if pos != len(r) - 2:
        raise ValueError("Not a multisig scriptPubKey")

    return m, pubkeys


def create_script_pubkey(m: int, pubkeys: list[bytes]) -> CScript:
    """Create a bare multisig scriptPubKey: OP_m <pubkeys> OP_n OP_CHECKMULTISIG

    Args:
        m: Required number of signatures (1–16).
        pubkeys: List of 1–16 compressed (33-byte) or uncompressed (65-byte) public keys.

    Raises:
        ValueError: If m/n are out of range or pubkeys are invalid lengths.
    """
    n = len(pubkeys)
    if not (1 <= m <= 16):
        raise ValueError("m must be between 1 and 16")
    if not (1 <= n <= 16):
        raise ValueError("number of pubkeys must be between 1 and 16")
    if m > n:
        raise ValueError("m cannot exceed number of pubkeys")
    for pk in pubkeys:
        if len(pk) not in (33, 65):
            raise ValueError("each pubkey must be 33 or 65 bytes")

    script = bytes([0x50 + m])
    for pk in pubkeys:
        script += bytes([len(pk)]) + pk
    script += bytes([0x50 + n, 0xAE])  # OP_n OP_CHECKMULTISIG
    return CScript(script)


def create_script_sig(signatures: list[bytes]) -> CScript:
    """Create a bare multisig scriptSig: OP_0 <signatures>

    The leading OP_0 is required due to the off-by-one bug in OP_CHECKMULTISIG.
    """
    script = b"\x00"  # OP_0 (CHECKMULTISIG dummy)
    for sig in signatures:
        script += bytes([len(sig)]) + sig
    return CScript(script)
