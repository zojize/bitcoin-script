"""Tests for Bitcoin Script stack manipulation opcodes."""

from __future__ import annotations

import pytest

from bitcoin_script.k_semantics import KBitcoinScript
from .script_helpers import script, push

pytestmark = pytest.mark.k


class TestOpDrop:
    def test_drop(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_1", "OP_2", "OP_DROP"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01"]

    def test_drop_empty_stuck(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_DROP"))
        assert k.is_stuck(result)


class TestOp2Drop:
    def test_2drop(self, k: KBitcoinScript) -> None:
        result = k.verify_script(
            script_pubkey=script("OP_1", "OP_2", "OP_3", "OP_2DROP")
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01"]

    def test_2drop_insufficient_stuck(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_1", "OP_2DROP"))
        assert k.is_stuck(result)


class TestOp2Dup:
    def test_2dup(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_1", "OP_2", "OP_2DUP"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x02", b"\x01", b"\x02", b"\x01"]


class TestOp3Dup:
    def test_3dup(self, k: KBitcoinScript) -> None:
        result = k.verify_script(
            script_pubkey=script("OP_1", "OP_2", "OP_3", "OP_3DUP"),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [
            b"\x03",
            b"\x02",
            b"\x01",
            b"\x03",
            b"\x02",
            b"\x01",
        ]


class TestOpNip:
    def test_nip(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_1", "OP_2", "OP_NIP"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x02"]


class TestOpOver:
    def test_over(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_1", "OP_2", "OP_OVER"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01", b"\x02", b"\x01"]


class TestOp2Over:
    def test_2over(self, k: KBitcoinScript) -> None:
        result = k.verify_script(
            script_pubkey=script("OP_1", "OP_2", "OP_3", "OP_4", "OP_2OVER"),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [
            b"\x02",
            b"\x01",
            b"\x04",
            b"\x03",
            b"\x02",
            b"\x01",
        ]


class TestOpSwap:
    def test_swap(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_1", "OP_2", "OP_SWAP"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01", b"\x02"]


class TestOp2Swap:
    def test_2swap(self, k: KBitcoinScript) -> None:
        result = k.verify_script(
            script_pubkey=script("OP_1", "OP_2", "OP_3", "OP_4", "OP_2SWAP"),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x02", b"\x01", b"\x04", b"\x03"]


class TestOpRot:
    def test_rot(self, k: KBitcoinScript) -> None:
        result = k.verify_script(
            script_pubkey=script("OP_1", "OP_2", "OP_3", "OP_ROT"),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01", b"\x03", b"\x02"]


class TestOp2Rot:
    def test_2rot(self, k: KBitcoinScript) -> None:
        result = k.verify_script(
            script_pubkey=script(
                "OP_1",
                "OP_2",
                "OP_3",
                "OP_4",
                "OP_5",
                "OP_6",
                "OP_2ROT",
            ),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [
            b"\x02",
            b"\x01",
            b"\x06",
            b"\x05",
            b"\x04",
            b"\x03",
        ]


class TestOpTuck:
    def test_tuck(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_1", "OP_2", "OP_TUCK"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x02", b"\x01", b"\x02"]


class TestOpIfDup:
    def test_ifdup_truthy(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_1", "OP_IFDUP"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01", b"\x01"]

    def test_ifdup_falsy(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_0", "OP_IFDUP"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b""]


class TestOpDepth:
    def test_depth_empty(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_DEPTH"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b""]  # depth 0 = empty bytes

    def test_depth_two(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_1", "OP_2", "OP_DEPTH"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x02", b"\x02", b"\x01"]


class TestOpSize:
    def test_size_1_byte(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_1", "OP_SIZE"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01", b"\x01"]

    def test_size_20_bytes(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script(push("aa" * 20), "OP_SIZE"))
        assert not k.is_stuck(result)
        stack = k.stack(result)
        assert stack[0] == b"\x14"  # 20 in CScriptNum

    def test_size_empty(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_0", "OP_SIZE"))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"", b""]


class TestOpPick:
    def test_pick_0(self, k: KBitcoinScript) -> None:
        """Pick index 0 = copy top element."""
        result = k.verify_script(
            script_pubkey=script("OP_1", "OP_2", "OP_0", "OP_PICK"),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x02", b"\x02", b"\x01"]

    def test_pick_1(self, k: KBitcoinScript) -> None:
        """Pick index 1 = copy second element (same as OVER)."""
        result = k.verify_script(
            script_pubkey=script("OP_1", "OP_2", "OP_1", "OP_PICK"),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01", b"\x02", b"\x01"]


class TestOpRoll:
    def test_roll_0(self, k: KBitcoinScript) -> None:
        """Roll index 0 = no-op."""
        result = k.verify_script(
            script_pubkey=script("OP_1", "OP_2", "OP_0", "OP_ROLL"),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x02", b"\x01"]

    def test_roll_1(self, k: KBitcoinScript) -> None:
        """Roll index 1 = SWAP."""
        result = k.verify_script(
            script_pubkey=script("OP_1", "OP_2", "OP_1", "OP_ROLL"),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x01", b"\x02"]


class TestOpAltStack:
    def test_toaltstack_fromaltstack(self, k: KBitcoinScript) -> None:
        result = k.verify_script(
            script_pubkey=script(
                "OP_1",
                "OP_2",
                "OP_TOALTSTACK",
                "OP_3",
                "OP_FROMALTSTACK",
            ),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b"\x02", b"\x03", b"\x01"]

    def test_fromaltstack_empty_stuck(self, k: KBitcoinScript) -> None:
        result = k.verify_script(script_pubkey=script("OP_FROMALTSTACK"))
        assert k.is_stuck(result)
