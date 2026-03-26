"""Tests for Bitcoin Script conditional execution (IF/ELSE/ENDIF/NOTIF)."""

from __future__ import annotations

import pytest

from bitcoin_script.k_semantics import KBitcoinScript
from .script_helpers import script, push

pytestmark = pytest.mark.k


class TestOpIf:
    def test_if_true_executes(self, k: KBitcoinScript) -> None:
        """OP_1 OP_IF OP_2 OP_ENDIF -> stack: [2]"""
        result = k.verify_script(
            script_pubkey=script("OP_1", "OP_IF", "OP_2", "OP_ENDIF"),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x02"]

    def test_if_false_skips(self, k: KBitcoinScript) -> None:
        """OP_0 OP_IF OP_2 OP_ENDIF -> stack: []"""
        result = k.verify_script(
            script_pubkey=script("OP_0", "OP_IF", "OP_2", "OP_ENDIF"),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == []

    def test_if_true_else(self, k: KBitcoinScript) -> None:
        """OP_1 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF -> stack: [2]"""
        result = k.verify_script(
            script_pubkey=script(
                "OP_1", "OP_IF", "OP_2", "OP_ELSE", "OP_3", "OP_ENDIF",
            ),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x02"]

    def test_if_false_else(self, k: KBitcoinScript) -> None:
        """OP_0 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF -> stack: [3]"""
        result = k.verify_script(
            script_pubkey=script(
                "OP_0", "OP_IF", "OP_2", "OP_ELSE", "OP_3", "OP_ENDIF",
            ),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x03"]


class TestOpNotIf:
    def test_notif_false_executes(self, k: KBitcoinScript) -> None:
        """OP_0 OP_NOTIF OP_2 OP_ENDIF -> stack: [2]"""
        result = k.verify_script(
            script_pubkey=script("OP_0", "OP_NOTIF", "OP_2", "OP_ENDIF"),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x02"]

    def test_notif_true_skips(self, k: KBitcoinScript) -> None:
        """OP_1 OP_NOTIF OP_2 OP_ENDIF -> stack: []"""
        result = k.verify_script(
            script_pubkey=script("OP_1", "OP_NOTIF", "OP_2", "OP_ENDIF"),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == []

    def test_notif_else(self, k: KBitcoinScript) -> None:
        """OP_1 OP_NOTIF OP_2 OP_ELSE OP_3 OP_ENDIF -> stack: [3]"""
        result = k.verify_script(
            script_pubkey=script(
                "OP_1", "OP_NOTIF", "OP_2", "OP_ELSE", "OP_3", "OP_ENDIF",
            ),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x03"]


class TestNestedConditionals:
    def test_nested_if_both_true(self, k: KBitcoinScript) -> None:
        """Nested IF/ENDIF with both conditions true."""
        result = k.verify_script(
            script_pubkey=script(
                "OP_1", "OP_IF",
                    "OP_1", "OP_IF", "OP_2", "OP_ENDIF",
                "OP_ENDIF",
            ),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x02"]

    def test_nested_if_outer_false(self, k: KBitcoinScript) -> None:
        """Outer IF false: inner IF is skipped entirely."""
        result = k.verify_script(
            script_pubkey=script(
                "OP_0", "OP_IF",
                    "OP_1", "OP_IF", "OP_2", "OP_ENDIF",
                "OP_ENDIF",
            ),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == []

    def test_nested_if_inner_false(self, k: KBitcoinScript) -> None:
        """Outer true, inner false: inner body skipped."""
        result = k.verify_script(
            script_pubkey=script(
                "OP_1", "OP_IF",
                    "OP_0", "OP_IF", "OP_2", "OP_ENDIF",
                    "OP_3",
                "OP_ENDIF",
            ),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x03"]

    def test_nested_if_else(self, k: KBitcoinScript) -> None:
        """Nested IF with ELSE branches."""
        result = k.verify_script(
            script_pubkey=script(
                "OP_1", "OP_IF",
                    "OP_0", "OP_IF", "OP_2", "OP_ELSE", "OP_3", "OP_ENDIF",
                "OP_ELSE",
                    "OP_4",
                "OP_ENDIF",
            ),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x03"]

    def test_outer_false_inner_else_not_toggled(self, k: KBitcoinScript) -> None:
        """When outer is false, inner ELSE must NOT toggle to true."""
        result = k.verify_script(
            script_pubkey=script(
                "OP_0", "OP_IF",
                    "OP_1", "OP_IF", "OP_2", "OP_ELSE", "OP_3", "OP_ENDIF",
                "OP_ELSE",
                    "OP_4",
                "OP_ENDIF",
            ),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x04"]


class TestConditionalPushSkip:
    def test_push_skipped_in_false_branch(self, k: KBitcoinScript) -> None:
        """Push data in a false IF branch should be skipped."""
        result = k.verify_script(
            script_pubkey=script(
                "OP_0", "OP_IF", push("deadbeef"), "OP_ENDIF", "OP_1",
            ),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01"]


class TestConditionalIntegration:
    def test_if_verify_pattern(self, k: KBitcoinScript) -> None:
        """Common pattern: OP_IF <branch1> OP_ELSE <branch2> OP_ENDIF OP_CHECKSIG equivalent."""
        # Simplified: choose which value to leave on stack
        result = k.verify_script(
            script_pubkey=script(
                "OP_1", "OP_IF", "OP_5", "OP_ELSE", "OP_3", "OP_ENDIF",
                "OP_1ADD",
            ),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x06"]  # 5 + 1

    def test_if_from_scriptsig(self, k: KBitcoinScript) -> None:
        """scriptSig provides the condition for OP_IF in scriptPubKey."""
        result = k.verify_script(
            script_sig=script("OP_1"),
            script_pubkey=script(
                "OP_IF", "OP_2", "OP_ELSE", "OP_3", "OP_ENDIF",
            ),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x02"]
