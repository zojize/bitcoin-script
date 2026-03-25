"""Tests for individual opcode handlers."""

import pytest


class TestStackOps:
    def test_op_dup(self) -> None:
        """OP_DUP should duplicate the top element."""
        ...

    def test_op_drop(self) -> None:
        """OP_DROP should remove the top element."""
        ...

    def test_op_swap(self) -> None:
        """OP_SWAP should swap the top two elements."""
        ...


class TestArithmeticOps:
    @pytest.mark.parametrize("a,b,expected", [(1, 2, 3), (-1, 1, 0), (0, 0, 0)])
    def test_op_add(self, a: int, b: int, expected: int) -> None:
        """OP_ADD should push the sum of the top two elements."""
        ...

    @pytest.mark.parametrize("a,b,expected", [(5, 3, 2), (0, 1, -1)])
    def test_op_sub(self, a: int, b: int, expected: int) -> None:
        """OP_SUB should push (second - top)."""
        ...


class TestEqualityOps:
    def test_op_equal_same(self) -> None:
        """OP_EQUAL should push 1 for identical elements."""
        ...

    def test_op_equal_different(self) -> None:
        """OP_EQUAL should push 0 for different elements."""
        ...

    def test_op_equalverify_pass(self) -> None:
        """OP_EQUALVERIFY should pass for identical elements."""
        ...

    def test_op_equalverify_fail(self) -> None:
        """OP_EQUALVERIFY should raise for different elements."""
        ...


class TestCryptoOps:
    def test_op_hash160_known_vector(self) -> None:
        """OP_HASH160 should produce RIPEMD160(SHA256(input))."""
        ...
