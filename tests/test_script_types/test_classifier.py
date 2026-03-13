"""Tests for script type classification."""



class TestClassifier:
    def test_classify_p2pkh(self) -> None:
        """Should identify P2PKH scripts."""
        ...

    def test_classify_p2sh(self) -> None:
        """Should identify P2SH scripts."""
        ...

    def test_classify_p2wpkh(self) -> None:
        """Should identify P2WPKH scripts."""
        ...

    def test_classify_p2wsh(self) -> None:
        """Should identify P2WSH scripts."""
        ...

    def test_classify_null_data(self) -> None:
        """Should identify OP_RETURN scripts."""
        ...

    def test_classify_nonstandard(self) -> None:
        """Unrecognized scripts should be NONSTANDARD."""
        ...
