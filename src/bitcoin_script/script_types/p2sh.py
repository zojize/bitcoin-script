"""Pay-to-Script-Hash (P2SH) script handling."""

from __future__ import annotations

from bitcoin.core.script import CScript, OP_EQUAL, OP_HASH160


def extract_script_hash(script_pubkey: CScript) -> bytes:
    """Extract the 20-byte script hash from a P2SH scriptPubKey.

    Raises:
        ValueError: If the script is not a valid P2SH template.
    """
    r = bytes(script_pubkey)
    if (
        len(r) != 23
        or r[0] != 0xA9  # OP_HASH160
        or r[1] != 0x14  # PUSH 20
        or r[22] != 0x87  # OP_EQUAL
    ):
        raise ValueError("Not a P2SH scriptPubKey")
    return r[2:22]


def create_script_pubkey(script_hash: bytes) -> CScript:
    """Create a P2SH scriptPubKey from a 20-byte script hash.

    Returns: OP_HASH160 <script_hash> OP_EQUAL
    """
    if len(script_hash) != 20:
        raise ValueError("script_hash must be 20 bytes")
    return CScript([OP_HASH160, script_hash, OP_EQUAL])


def deserialize_redeem_script(script_sig: CScript) -> CScript:
    """Extract the serialized redeem script from a P2SH scriptSig.

    The redeem script is the last push in the scriptSig.

    Raises:
        ValueError: If the scriptSig doesn't contain a redeem script.
    """
    pushes = list(script_sig)
    if not pushes:
        raise ValueError("scriptSig is empty")
    last = pushes[-1]
    if not isinstance(last, bytes):
        raise ValueError("Last element of scriptSig is not a data push")
    return CScript(last)