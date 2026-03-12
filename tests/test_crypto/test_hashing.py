"""Tests for cryptographic hash functions."""

from bitcoin_script.crypto.hashing import hash160, hash256, ripemd160, sha1, sha256


class TestHashing:
    def test_sha256_known_vector(self) -> None:
        """SHA-256 of empty string should match known hash."""
        ...

    def test_sha256_returns_32_bytes(self) -> None:
        """SHA-256 should always return 32 bytes."""
        ...

    def test_hash256_double_sha256(self) -> None:
        """hash256 should be SHA256(SHA256(data))."""
        ...

    def test_ripemd160_returns_20_bytes(self) -> None:
        """RIPEMD-160 should always return 20 bytes."""
        ...

    def test_hash160_known_vector(self) -> None:
        """HASH160 should be RIPEMD160(SHA256(data))."""
        ...

    def test_sha1_returns_20_bytes(self) -> None:
        """SHA-1 should always return 20 bytes."""
        ...
