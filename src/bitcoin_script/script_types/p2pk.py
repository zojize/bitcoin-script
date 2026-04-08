"""Pay-to-Public-Key (P2PK) script handling."""

from __future__ import annotations

from bitcoin.core.script import CScript


def extract_pubkey(script_pubkey: CScript) -> bytes:
    """Extract the public key from a P2PK scriptPubKey.

    Raises:
        ValueError: If the script is not a valid P2PK template.
    """
    r = bytes(script_pubkey)
    if len(r) == 35 and r[0] == 0x21 and r[34] == 0xAC:
        return r[1:34]
    if len(r) == 67 and r[0] == 0x41 and r[66] == 0xAC:
        return r[1:66]
    raise ValueError("Not a P2PK scriptPubKey")


def create_script_pubkey(pubkey: bytes) -> CScript:
    """Create a P2PK scriptPubKey: <pubkey> OP_CHECKSIG

    Args:
        pubkey: 33-byte compressed or 65-byte uncompressed public key.

    Raises:
        ValueError: If pubkey length is not 33 or 65 bytes.
    """
    if len(pubkey) not in (33, 65):
        raise ValueError("pubkey must be 33 (compressed) or 65 (uncompressed) bytes")
    return CScript(bytes([len(pubkey)]) + pubkey + b"\xac")


def create_script_sig(signature: bytes) -> CScript:
    """Create a P2PK scriptSig: <signature>

    Returns: A script containing only the signature push.
    """
    return CScript(bytes([len(signature)]) + signature)
