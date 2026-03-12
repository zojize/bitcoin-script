"""ECDSA signature verification on the secp256k1 curve."""

from __future__ import annotations

from bitcoin_script.types import PubKeyBytes, SignatureBytes


def verify_ecdsa(
    public_key: PubKeyBytes,
    signature: SignatureBytes,
    message_hash: bytes,
) -> bool:
    """Verify an ECDSA signature on the secp256k1 curve.

    Args:
        public_key: Compressed (33 bytes) or uncompressed (65 bytes) public key.
        signature: DER-encoded ECDSA signature (without sighash byte).
        message_hash: 32-byte message hash to verify against.

    Returns:
        True if the signature is valid, False otherwise.
    """
    ...


def verify_schnorr(
    public_key: PubKeyBytes,
    signature: SignatureBytes,
    message_hash: bytes,
) -> bool:
    """Verify a Schnorr signature (BIP340) on the secp256k1 curve.

    Placeholder for future Taproot support.

    Args:
        public_key: 32-byte x-only public key.
        signature: 64-byte Schnorr signature.
        message_hash: 32-byte message hash to verify against.

    Returns:
        True if the signature is valid, False otherwise.
    """
    ...
