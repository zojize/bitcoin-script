"""Pay-to-Witness-Public-Key-Hash (P2WPKH) script handling."""

from __future__ import annotations

from bitcoin.core.script import CScript


def extract_pubkey_hash(script_pubkey: CScript) -> bytes:
    """Extract the 20-byte public key hash from a P2WPKH scriptPubKey.

    Raises:
        ValueError: If the script is not a valid P2WPKH template.
    """
    ...


def create_script_pubkey(pubkey_hash: bytes) -> CScript:
    """Create a P2WPKH scriptPubKey from a 20-byte public key hash.

    Returns: OP_0 <pubkey_hash>
    """
    ...


def witness_to_script_code(pubkey_hash: bytes) -> bytes:
    """Create the script code used in BIP143 sighash for P2WPKH.

    Returns: OP_DUP OP_HASH160 <pubkey_hash> OP_EQUALVERIFY OP_CHECKSIG
    (Same as P2PKH scriptPubKey)
    """
    ...
