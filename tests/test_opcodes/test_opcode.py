"""Tests for the Opcode enum."""

from bitcoin_script.opcodes.opcode import Opcode


class TestOpcodeEnum:
    def test_op_0_value(self) -> None:
        """OP_0 should have byte value 0x00."""
        ...

    def test_op_checksig_value(self) -> None:
        """OP_CHECKSIG should have byte value 0xAC."""
        ...

    def test_op_dup_value(self) -> None:
        """OP_DUP should have byte value 0x76."""
        ...

    def test_all_opcodes_have_unique_values(self) -> None:
        """All opcodes should have distinct byte values (except aliases)."""
        ...

    def test_is_disabled_for_disabled_opcode(self) -> None:
        """Disabled opcodes (e.g. OP_CAT) should return True."""
        ...

    def test_is_disabled_for_active_opcode(self) -> None:
        """Active opcodes (e.g. OP_ADD) should return False."""
        ...

    def test_is_push_data(self) -> None:
        """Push data opcodes should return True for is_push_data."""
        ...

    def test_opcode_from_int(self) -> None:
        """Should construct an Opcode from a raw integer value."""
        ...
