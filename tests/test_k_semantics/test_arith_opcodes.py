"""Tests for Bitcoin Script arithmetic, boolean, and comparison opcodes."""

from __future__ import annotations

import pytest

from bitcoin_script.k_semantics import KBitcoinScript
from .script_helpers import script

pytestmark = pytest.mark.k


class TestOp1Add:
    def test_1add(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_5", "OP_1ADD"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x06"]

    def test_1add_zero(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_0", "OP_1ADD"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01"]


class TestOp1Sub:
    def test_1sub(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_5", "OP_1SUB"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x04"]

    def test_1sub_to_zero(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_1", "OP_1SUB"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b""]  # 0 = empty bytes


class TestOpNegate:
    def test_negate_positive(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_5", "OP_NEGATE"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x85"]  # -5 in CScriptNum

    def test_negate_zero(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_0", "OP_NEGATE"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b""]


class TestOpAbs:
    def test_abs_positive(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_5", "OP_ABS"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x05"]

    def test_abs_negative(self, k: KBitcoinScript) -> None:
        # Push -5 (0x85) then ABS -> 5
        result = k.verify_script(
            script_pubkey=script("OP_5", "OP_NEGATE", "OP_ABS"),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x05"]


class TestOpNot:
    def test_not_zero(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_0", "OP_NOT"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01"]

    def test_not_one(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_1", "OP_NOT"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b""]

    def test_not_nonzero(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_5", "OP_NOT"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b""]


class TestOp0NotEqual:
    def test_0notequal_zero(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_0", "OP_0NOTEQUAL"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b""]

    def test_0notequal_nonzero(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_5", "OP_0NOTEQUAL"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01"]


class TestOpSub:
    def test_sub(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_5", "OP_3", "OP_SUB"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x02"]

    def test_sub_negative_result(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_3", "OP_5", "OP_SUB"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x82"]  # -2 in CScriptNum


class TestOpBoolAnd:
    def test_both_nonzero(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_1", "OP_2", "OP_BOOLAND"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01"]

    def test_one_zero(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_1", "OP_0", "OP_BOOLAND"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b""]

    def test_both_zero(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_0", "OP_0", "OP_BOOLAND"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b""]


class TestOpBoolOr:
    def test_both_nonzero(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_1", "OP_2", "OP_BOOLOR"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01"]

    def test_one_zero(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_0", "OP_2", "OP_BOOLOR"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01"]

    def test_both_zero(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_0", "OP_0", "OP_BOOLOR"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b""]


class TestOpNumEqual:
    def test_equal(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_3", "OP_3", "OP_NUMEQUAL"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01"]

    def test_not_equal(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_3", "OP_4", "OP_NUMEQUAL"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b""]


class TestOpNumNotEqual:
    def test_not_equal(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_3", "OP_4", "OP_NUMNOTEQUAL"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01"]

    def test_equal(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_3", "OP_3", "OP_NUMNOTEQUAL"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b""]


class TestOpLessThan:
    def test_less(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_3", "OP_5", "OP_LESSTHAN"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01"]

    def test_not_less(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_5", "OP_3", "OP_LESSTHAN"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b""]

    def test_equal_not_less(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_3", "OP_3", "OP_LESSTHAN"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b""]


class TestOpGreaterThan:
    def test_greater(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_5", "OP_3", "OP_GREATERTHAN"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01"]

    def test_not_greater(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_3", "OP_5", "OP_GREATERTHAN"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b""]


class TestOpLessThanOrEqual:
    def test_less(self, k: KBitcoinScript) -> None:
        result = k.verify_script(
            script_pubkey=script("OP_3", "OP_5", "OP_LESSTHANOREQUAL"),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01"]

    def test_equal(self, k: KBitcoinScript) -> None:
        result = k.verify_script(
            script_pubkey=script("OP_3", "OP_3", "OP_LESSTHANOREQUAL"),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01"]

    def test_greater(self, k: KBitcoinScript) -> None:
        result = k.verify_script(
            script_pubkey=script("OP_5", "OP_3", "OP_LESSTHANOREQUAL"),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b""]


class TestOpGreaterThanOrEqual:
    def test_greater(self, k: KBitcoinScript) -> None:
        result = k.verify_script(
            script_pubkey=script("OP_5", "OP_3", "OP_GREATERTHANOREQUAL"),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01"]

    def test_equal(self, k: KBitcoinScript) -> None:
        result = k.verify_script(
            script_pubkey=script("OP_3", "OP_3", "OP_GREATERTHANOREQUAL"),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01"]

    def test_less(self, k: KBitcoinScript) -> None:
        result = k.verify_script(
            script_pubkey=script("OP_3", "OP_5", "OP_GREATERTHANOREQUAL"),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b""]


class TestOpMin:
    def test_min(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_3", "OP_5", "OP_MIN"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x03"]


class TestOpMax:
    def test_max(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_3", "OP_5", "OP_MAX"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x05"]


class TestOpWithin:
    def test_within_true(self, k: KBitcoinScript) -> None:
        # 3 is within [2, 5)
        result = k.verify_script(
            script_pubkey=script("OP_3", "OP_2", "OP_5", "OP_WITHIN"),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01"]

    def test_within_false_above(self, k: KBitcoinScript) -> None:
        # 5 is NOT within [2, 5)
        result = k.verify_script(
            script_pubkey=script("OP_5", "OP_2", "OP_5", "OP_WITHIN"),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b""]

    def test_within_false_below(self, k: KBitcoinScript) -> None:
        # 1 is NOT within [2, 5)
        result = k.verify_script(
            script_pubkey=script("OP_1", "OP_2", "OP_5", "OP_WITHIN"),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b""]

    def test_within_at_min(self, k: KBitcoinScript) -> None:
        # 2 is within [2, 5)
        result = k.verify_script(
            script_pubkey=script("OP_2", "OP_2", "OP_5", "OP_WITHIN"),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01"]


class TestOpNumEqualVerify:
    def test_equal_continues(self, k: KBitcoinScript) -> None:
        result = k.verify_script(
            script_pubkey=script("OP_3", "OP_3", "OP_NUMEQUALVERIFY", "OP_1"),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01"]

    def test_not_equal_fails(self, k: KBitcoinScript) -> None:
        result = k.verify_script(
            script_pubkey=script("OP_3", "OP_4", "OP_NUMEQUALVERIFY"),
        )
        assert not k.success(result)
        assert k.error(result) == "NUMEQUALVERIFY"


class TestOp1Negate:
    def test_1negate(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_1NEGATE"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x81"]  # -1 in CScriptNum

    def test_1negate_add(self, k: KBitcoinScript) -> None:
        """OP_1NEGATE + OP_1 + OP_ADD = 0."""
        result = k.verify_script(
            script_pubkey=script("OP_1NEGATE", "OP_1", "OP_ADD"),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b""]


class TestOpNop:
    def test_nop(self, k: KBitcoinScript) -> None:
        result = k.verify_script(
            script_pubkey=script("OP_1", "OP_NOP", "OP_NOP"),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01"]


class TestOpVerify:
    def test_verify_truthy(self, k: KBitcoinScript) -> None:
        result = k.verify_script(
            script_pubkey=script("OP_1", "OP_VERIFY", "OP_2"),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x02"]

    def test_verify_falsy_fails(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_0", "OP_VERIFY"))
        assert not k.success(result)
        assert k.error(result) == "VERIFY"


class TestOpReturn:
    def test_return_fails(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_1", "OP_RETURN"))
        assert not k.success(result)
        assert k.error(result) == "OP_RETURN"
