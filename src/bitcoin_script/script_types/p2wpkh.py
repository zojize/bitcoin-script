"""Pay-to-Witness-Public-Key-Hash (P2WPKH) script handling."""

from __future__ import annotations

from bitcoin.core.script import CScript


def extract_pubkey_hash(script_pubkey: CScript) -> bytes:
    """Extract the 20-byte public key hash from a P2WPKH scriptPubKey.

    Raises:
        ValueError: If the script is not a valid P2WPKH template.
    """
    r = bytes(script_pubkey)
    if len(r) != 22 or r[0] != 0x00 or r[1] != 0x14:
        raise ValueError("Not a P2WPKH scriptPubKey")
    return r[2:]


def create_script_pubkey(pubkey_hash: bytes) -> CScript:
    """Create a P2WPKH scriptPubKey: OP_0 <pubkey_hash>"""
    if len(pubkey_hash) != 20:
        raise ValueError("pubkey_hash must be 20 bytes")
    return CScript(b"\x00\x14" + pubkey_hash)


def witness_to_script_code(pubkey_hash: bytes) -> bytes:
    """Create the BIP143 script code for P2WPKH sighash computation.

    Returns: OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
    (identical to a P2PKH scriptPubKey)
    """
    if len(pubkey_hash) != 20:
        raise ValueError("pubkey_hash must be 20 bytes")
    return b"\x76\xa9\x14" + pubkey_hash + b"\x88\xac"
