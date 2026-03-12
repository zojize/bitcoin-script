"""DER signature parsing and validation utilities."""

from __future__ import annotations

from bitcoin_script.model.sighash import SigHashType
from bitcoin_script.types import SignatureBytes


def parse_der_signature(sig_bytes: bytes) -> tuple[int, int]:
    """Parse a DER-encoded ECDSA signature into (r, s) integers.

    Args:
        sig_bytes: DER-encoded signature bytes (without trailing sighash byte).

    Returns:
        Tuple of (r, s) as Python integers.

    Raises:
        InvalidSignatureError: If the encoding is malformed.
    """
    ...


def is_valid_der_encoding(sig_bytes: bytes) -> bool:
    """Check if bytes are valid strict DER encoding per BIP66.

    Args:
        sig_bytes: Signature bytes to validate (without trailing sighash byte).

    Returns:
        True if the encoding is valid strict DER.
    """
    ...


def is_low_s(s: int) -> bool:
    """Check that the S value is in the lower half of the curve order (BIP62).

    Args:
        s: The S component of the ECDSA signature.

    Returns:
        True if S <= order/2.
    """
    ...


def extract_hash_type(sig_with_hashtype: bytes) -> tuple[SignatureBytes, SigHashType]:
    """Split the trailing sighash type byte from a signature.

    Args:
        sig_with_hashtype: DER signature concatenated with 1-byte sighash flag.

    Returns:
        Tuple of (signature_bytes, sighash_type).
    """
    ...
