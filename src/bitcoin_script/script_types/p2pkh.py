"""Pay-to-Public-Key-Hash (P2PKH) script handling."""

from __future__ import annotations

from bitcoin.core.script import CScript, OP_CHECKSIG, OP_DUP, OP_EQUALVERIFY, OP_HASH160


def extract_pubkey_hash(script_pubkey: CScript) -> bytes:
    """Extract the 20-byte public key hash from a P2PKH scriptPubKey.

    Raises:
        ValueError: If the script is not a valid P2PKH template.
    """
    r = bytes(script_pubkey)
    if (
        len(r) != 25
        or r[0] != 0x76  # OP_DUP
        or r[1] != 0xA9  # OP_HASH160
        or r[2] != 0x14  # PUSH 20
        or r[23] != 0x88  # OP_EQUALVERIFY
        or r[24] != 0xAC  # OP_CHECKSIG
    ):
        raise ValueError("Not a P2PKH scriptPubKey")
    return r[3:23]


def create_script_pubkey(pubkey_hash: bytes) -> CScript:
    """Create a P2PKH scriptPubKey from a 20-byte public key hash.

    Returns: OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
    """
    if len(pubkey_hash) != 20:
        raise ValueError("pubkey_hash must be 20 bytes")
    return CScript([OP_DUP, OP_HASH160, pubkey_hash, OP_EQUALVERIFY, OP_CHECKSIG])


def create_script_sig(signature: bytes, pubkey: bytes) -> CScript:
    """Create a P2PKH scriptSig from a signature and public key.

    Returns: <signature> <pubkey>
    """
    return CScript([signature, pubkey])