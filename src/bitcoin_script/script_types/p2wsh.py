"""Pay-to-Witness-Script-Hash (P2WSH) script handling."""

from __future__ import annotations

from bitcoin.core.script import CScript


def extract_script_hash(script_pubkey: CScript) -> bytes:
    """Extract the 32-byte script hash from a P2WSH scriptPubKey.

    Raises:
        ValueError: If the script is not a valid P2WSH template.
    """
    ...


def create_script_pubkey(script_hash: bytes) -> CScript:
    """Create a P2WSH scriptPubKey from a 32-byte SHA-256 script hash.

    Returns: OP_0 <script_hash>
    """
    ...


def extract_witness_script(witness: list[bytes]) -> CScript:
    """Extract the witness script from a P2WSH witness stack.

    The witness script is the last item in the witness stack.

    Raises:
        ValueError: If the witness stack is empty.
    """
    ...
