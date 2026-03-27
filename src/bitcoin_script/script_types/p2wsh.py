"""Pay-to-Witness-Script-Hash (P2WSH) script handling."""

from __future__ import annotations

from bitcoin.core.script import CScript


def extract_script_hash(script_pubkey: CScript) -> bytes:
    """Extract the 32-byte script hash from a P2WSH scriptPubKey.

    Raises:
        ValueError: If the script is not a valid P2WSH template.
    """
    r = bytes(script_pubkey)
    if len(r) != 34 or r[0] != 0x00 or r[1] != 0x20:
        raise ValueError("Not a P2WSH scriptPubKey")
    return r[2:]


def create_script_pubkey(script_hash: bytes) -> CScript:
    """Create a P2WSH scriptPubKey: OP_0 <script_hash>"""
    if len(script_hash) != 32:
        raise ValueError("script_hash must be 32 bytes")
    return CScript(b"\x00\x20" + script_hash)


def extract_witness_script(witness: list[bytes]) -> CScript:
    """Extract the witness script (last item) from a P2WSH witness stack.

    Raises:
        ValueError: If the witness stack is empty.
    """
    if not witness:
        raise ValueError("Witness stack is empty")
    return CScript(witness[-1])