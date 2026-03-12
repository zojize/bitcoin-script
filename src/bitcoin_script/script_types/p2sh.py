"""Pay-to-Script-Hash (P2SH) script handling."""

from __future__ import annotations

from bitcoin_script.model.script import Script


def extract_script_hash(script_pubkey: Script) -> bytes:
    """Extract the 20-byte script hash from a P2SH scriptPubKey.

    Raises:
        ValueError: If the script is not a valid P2SH template.
    """
    ...


def create_script_pubkey(script_hash: bytes) -> Script:
    """Create a P2SH scriptPubKey from a 20-byte script hash.

    Returns: OP_HASH160 <script_hash> OP_EQUAL
    """
    ...


def deserialize_redeem_script(script_sig: Script) -> Script:
    """Extract the serialized redeem script from a P2SH scriptSig.

    The redeem script is the last push in the scriptSig.

    Raises:
        ValueError: If the scriptSig doesn't contain a redeem script.
    """
    ...
