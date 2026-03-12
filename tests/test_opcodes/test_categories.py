"""Tests for opcode category groupings."""

from bitcoin_script.opcodes.categories import (
    ARITHMETIC_OPS,
    CONSTANT_OPS,
    CRYPTO_OPS,
    DISABLED_OPS,
    FLOW_CONTROL_OPS,
    LOCKTIME_OPS,
    STACK_OPS,
)
from bitcoin_script.opcodes.opcode import Opcode


class TestOpcodeCategories:
    def test_op_add_in_arithmetic(self) -> None:
        """OP_ADD should be in ARITHMETIC_OPS."""
        ...

    def test_op_dup_in_stack(self) -> None:
        """OP_DUP should be in STACK_OPS."""
        ...

    def test_op_hash160_in_crypto(self) -> None:
        """OP_HASH160 should be in CRYPTO_OPS."""
        ...

    def test_op_if_in_flow_control(self) -> None:
        """OP_IF should be in FLOW_CONTROL_OPS."""
        ...

    def test_op_cat_in_disabled(self) -> None:
        """OP_CAT should be in DISABLED_OPS."""
        ...

    def test_categories_are_disjoint(self) -> None:
        """No opcode should appear in multiple primary categories."""
        ...
