"""Opcode handler dispatch and implementation stubs."""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable

from bitcoin_script.opcodes.opcode import Opcode

if TYPE_CHECKING:
    from bitcoin_script.engine.stack import ScriptStack
    from bitcoin_script.model.transaction import Transaction

# Type alias for simple opcode handlers (stack-only)
OpcodeHandler = Callable[["ScriptStack"], None]


def get_handler(opcode: Opcode) -> OpcodeHandler:
    """Return the handler function for the given opcode.

    Raises:
        OpDisabledError: If the opcode is disabled.
        KeyError: If no handler is registered for the opcode.
    """
    ...


# --- Data push ---


def op_push_data(stack: ScriptStack, data: bytes) -> None:
    """Push raw data bytes onto the stack."""
    ...


def op_push_number(stack: ScriptStack, n: int) -> None:
    """Push a small integer (-1 through 16) onto the stack."""
    ...


# --- Stack manipulation ---


def op_dup(stack: ScriptStack) -> None:
    """OP_DUP: Duplicate the top stack element."""
    ...


def op_drop(stack: ScriptStack) -> None:
    """OP_DROP: Remove the top stack element."""
    ...


def op_swap(stack: ScriptStack) -> None:
    """OP_SWAP: Swap the top two stack elements."""
    ...


def op_over(stack: ScriptStack) -> None:
    """OP_OVER: Copy the second-to-top element to the top."""
    ...


def op_rot(stack: ScriptStack) -> None:
    """OP_ROT: Rotate the top three elements (3rd -> top)."""
    ...


def op_pick(stack: ScriptStack) -> None:
    """OP_PICK: Copy the nth element to the top (n from stack)."""
    ...


def op_roll(stack: ScriptStack) -> None:
    """OP_ROLL: Move the nth element to the top (n from stack)."""
    ...


def op_2dup(stack: ScriptStack) -> None:
    """OP_2DUP: Duplicate the top two stack elements."""
    ...


def op_3dup(stack: ScriptStack) -> None:
    """OP_3DUP: Duplicate the top three stack elements."""
    ...


def op_2drop(stack: ScriptStack) -> None:
    """OP_2DROP: Remove the top two stack elements."""
    ...


def op_2swap(stack: ScriptStack) -> None:
    """OP_2SWAP: Swap the top two pairs of elements."""
    ...


def op_2over(stack: ScriptStack) -> None:
    """OP_2OVER: Copy the 3rd and 4th elements to the top."""
    ...


def op_2rot(stack: ScriptStack) -> None:
    """OP_2ROT: Move the 5th and 6th elements to the top."""
    ...


def op_ifdup(stack: ScriptStack) -> None:
    """OP_IFDUP: Duplicate top if it's nonzero."""
    ...


def op_depth(stack: ScriptStack) -> None:
    """OP_DEPTH: Push the stack size."""
    ...


def op_nip(stack: ScriptStack) -> None:
    """OP_NIP: Remove the second-to-top element."""
    ...


def op_tuck(stack: ScriptStack) -> None:
    """OP_TUCK: Copy top element and insert before second-to-top."""
    ...


def op_size(stack: ScriptStack) -> None:
    """OP_SIZE: Push the byte length of the top element (without removing it)."""
    ...


# --- Arithmetic ---


def op_add(stack: ScriptStack) -> None:
    """OP_ADD: Pop two, push their sum."""
    ...


def op_sub(stack: ScriptStack) -> None:
    """OP_SUB: Pop two, push (second - top)."""
    ...


def op_1add(stack: ScriptStack) -> None:
    """OP_1ADD: Increment top element by 1."""
    ...


def op_1sub(stack: ScriptStack) -> None:
    """OP_1SUB: Decrement top element by 1."""
    ...


def op_negate(stack: ScriptStack) -> None:
    """OP_NEGATE: Negate the top element."""
    ...


def op_abs(stack: ScriptStack) -> None:
    """OP_ABS: Replace top with its absolute value."""
    ...


def op_not(stack: ScriptStack) -> None:
    """OP_NOT: Boolean NOT (0 -> 1, nonzero -> 0)."""
    ...


def op_0notequal(stack: ScriptStack) -> None:
    """OP_0NOTEQUAL: Push 1 if top is nonzero, else 0."""
    ...


def op_booland(stack: ScriptStack) -> None:
    """OP_BOOLAND: Boolean AND of top two elements."""
    ...


def op_boolor(stack: ScriptStack) -> None:
    """OP_BOOLOR: Boolean OR of top two elements."""
    ...


def op_numequal(stack: ScriptStack) -> None:
    """OP_NUMEQUAL: Push 1 if top two are numerically equal."""
    ...


def op_numequalverify(stack: ScriptStack) -> None:
    """OP_NUMEQUALVERIFY: OP_NUMEQUAL then OP_VERIFY."""
    ...


def op_numnotequal(stack: ScriptStack) -> None:
    """OP_NUMNOTEQUAL: Push 1 if top two are not equal."""
    ...


def op_lessthan(stack: ScriptStack) -> None:
    """OP_LESSTHAN: Push 1 if second < top."""
    ...


def op_greaterthan(stack: ScriptStack) -> None:
    """OP_GREATERTHAN: Push 1 if second > top."""
    ...


def op_lessthanorequal(stack: ScriptStack) -> None:
    """OP_LESSTHANOREQUAL: Push 1 if second <= top."""
    ...


def op_greaterthanorequal(stack: ScriptStack) -> None:
    """OP_GREATERTHANOREQUAL: Push 1 if second >= top."""
    ...


def op_min(stack: ScriptStack) -> None:
    """OP_MIN: Push the smaller of the top two elements."""
    ...


def op_max(stack: ScriptStack) -> None:
    """OP_MAX: Push the larger of the top two elements."""
    ...


def op_within(stack: ScriptStack) -> None:
    """OP_WITHIN: Push 1 if x is within [min, max)."""
    ...


# --- Equality ---


def op_equal(stack: ScriptStack) -> None:
    """OP_EQUAL: Push 1 if top two are byte-identical, else 0."""
    ...


def op_equalverify(stack: ScriptStack) -> None:
    """OP_EQUALVERIFY: OP_EQUAL then OP_VERIFY."""
    ...


# --- Crypto ---


def op_ripemd160(stack: ScriptStack) -> None:
    """OP_RIPEMD160: Replace top with RIPEMD-160 hash."""
    ...


def op_sha1(stack: ScriptStack) -> None:
    """OP_SHA1: Replace top with SHA-1 hash."""
    ...


def op_sha256(stack: ScriptStack) -> None:
    """OP_SHA256: Replace top with SHA-256 hash."""
    ...


def op_hash160(stack: ScriptStack) -> None:
    """OP_HASH160: Replace top with RIPEMD160(SHA256(x))."""
    ...


def op_hash256(stack: ScriptStack) -> None:
    """OP_HASH256: Replace top with SHA256(SHA256(x))."""
    ...


def op_checksig(
    stack: ScriptStack,
    tx: Transaction,
    input_index: int,
    input_value: int,
    script_code: bytes,
) -> None:
    """OP_CHECKSIG: Verify ECDSA signature against transaction.

    Pops pubkey and signature from stack, verifies against the
    transaction's signature hash, pushes True/False.
    """
    ...


def op_checksigverify(
    stack: ScriptStack,
    tx: Transaction,
    input_index: int,
    input_value: int,
    script_code: bytes,
) -> None:
    """OP_CHECKSIGVERIFY: OP_CHECKSIG then OP_VERIFY."""
    ...


def op_checkmultisig(
    stack: ScriptStack,
    tx: Transaction,
    input_index: int,
    input_value: int,
    script_code: bytes,
) -> None:
    """OP_CHECKMULTISIG: M-of-N multi-signature verification.

    Pops N pubkeys, M signatures, and a dummy element (off-by-one bug),
    verifies M signatures against N pubkeys, pushes True/False.
    """
    ...


def op_checkmultisigverify(
    stack: ScriptStack,
    tx: Transaction,
    input_index: int,
    input_value: int,
    script_code: bytes,
) -> None:
    """OP_CHECKMULTISIGVERIFY: OP_CHECKMULTISIG then OP_VERIFY."""
    ...


# --- Flow control (simple ones; IF/ELSE/ENDIF handled by engine) ---


def op_verify(stack: ScriptStack) -> None:
    """OP_VERIFY: Fail if top is false, otherwise remove top.

    Raises:
        VerifyFailedError: If top element is false.
    """
    ...
