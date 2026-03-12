"""End-to-end script execution tests."""

from bitcoin_script.engine.engine import ScriptEngine


class TestP2PKHExecution:
    def test_valid_p2pkh_succeeds(self) -> None:
        """Valid P2PKH scriptSig + scriptPubKey should evaluate to True."""
        ...

    def test_wrong_pubkey_fails(self) -> None:
        """P2PKH with wrong public key should fail at EQUALVERIFY."""
        ...

    def test_wrong_signature_fails(self) -> None:
        """P2PKH with wrong signature should fail at CHECKSIG."""
        ...


class TestSimpleScripts:
    def test_op_1_op_1_op_add_op_2_op_equal(self) -> None:
        """1 + 1 == 2 should succeed."""
        ...

    def test_op_1_op_2_op_equal_fails(self) -> None:
        """1 == 2 should fail."""
        ...

    def test_hash_preimage_script(self) -> None:
        """Hash preimage reveal script should work."""
        ...
