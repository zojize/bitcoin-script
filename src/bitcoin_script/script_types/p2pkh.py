"""Pay-to-Public-Key-Hash (P2PKH) script handling."""

from __future__ import annotations

from bitcoin.core.script import CScript


def extract_pubkey_hash(script_pubkey: CScript) -> bytes:
    """Extract the 20-byte public key hash from a P2PKH scriptPubKey.

    Raises:
        ValueError: If the script is not a valid P2PKH template.
    """
    ...


def create_script_pubkey(pubkey_hash: bytes) -> CScript:
    """Create a P2PKH scriptPubKey from a 20-byte public key hash.

    Returns: OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
    """
    ...


def create_script_sig(signature: bytes, pubkey: bytes) -> CScript:
    """Create a P2PKH scriptSig from a signature and public key.

    Returns: <signature> <pubkey>
    """
    ...
