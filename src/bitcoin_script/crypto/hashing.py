"""Cryptographic hash function wrappers."""


def sha256(data: bytes) -> bytes:
    """Single SHA-256 hash. Returns 32 bytes."""
    ...


def hash256(data: bytes) -> bytes:
    """Double SHA-256 (SHA256d). Returns 32 bytes."""
    ...


def ripemd160(data: bytes) -> bytes:
    """RIPEMD-160 hash. Returns 20 bytes."""
    ...


def hash160(data: bytes) -> bytes:
    """HASH160 = RIPEMD160(SHA256(data)). Returns 20 bytes."""
    ...


def sha1(data: bytes) -> bytes:
    """SHA-1 hash. Returns 20 bytes."""
    ...
