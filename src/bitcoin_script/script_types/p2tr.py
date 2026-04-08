"""Pay-to-Taproot (P2TR) script handling."""

from __future__ import annotations

from bitcoin.core.script import CScript


def extract_pubkey(script_pubkey: CScript) -> bytes:
    """Extract the 32-byte x-only tweaked public key from a P2TR scriptPubKey.

    Raises:
        ValueError: If the script is not a valid P2TR template.
    """
    r = bytes(script_pubkey)
    if len(r) != 34 or r[0] != 0x51 or r[1] != 0x20:
        raise ValueError("Not a P2TR scriptPubKey")
    return r[2:]


def create_script_pubkey(tweaked_pubkey: bytes) -> CScript:
    """Create a P2TR scriptPubKey: OP_1 <tweaked_pubkey>

    Args:
        tweaked_pubkey: 32-byte x-only tweaked public key.

    Raises:
        ValueError: If tweaked_pubkey is not 32 bytes.
    """
    if len(tweaked_pubkey) != 32:
        raise ValueError("tweaked_pubkey must be 32 bytes")
    return CScript(b"\x51\x20" + tweaked_pubkey)
