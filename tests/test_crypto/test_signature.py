"""Tests for DER signature parsing and validation."""

from bitcoin_script.crypto.signature import extract_hash_type, is_low_s, is_valid_der_encoding, parse_der_signature


class TestDERParsing:
    def test_parse_valid_der(self) -> None:
        """Should parse a valid DER signature into (r, s)."""
        ...

    def test_parse_invalid_der_raises(self) -> None:
        """Should raise on malformed DER encoding."""
        ...

    def test_is_valid_der_strict(self) -> None:
        """Should validate strict DER encoding per BIP66."""
        ...

    def test_is_valid_der_rejects_non_strict(self) -> None:
        """Should reject non-canonical DER encoding."""
        ...


class TestLowS:
    def test_low_s_value(self) -> None:
        """S in lower half of curve order should return True."""
        ...

    def test_high_s_value(self) -> None:
        """S in upper half of curve order should return False."""
        ...


class TestExtractHashType:
    def test_extract_sighash_all(self) -> None:
        """Should extract SIGHASH_ALL (0x01) from trailing byte."""
        ...

    def test_extract_sighash_anyonecanpay(self) -> None:
        """Should extract ANYONECANPAY flag combinations."""
        ...
