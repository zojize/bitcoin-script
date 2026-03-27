"""Opcode handler dispatch and implementation."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from bitcoin.core import CTransaction
    from bitcoin_script.engine.stack import ScriptStack

from bitcoin_script.engine.errors import (
    OpDisabledError,
    VerifyFailedError,
)
from bitcoin_script.engine.stack import ScriptStack

# Type alias for simple opcode handlers (stack-only)
OpcodeHandler = Callable[["ScriptStack"], None]

# Disabled opcodes
_DISABLED = {
    0x7E,  # OP_CAT
    0x7F,  # OP_SUBSTR
    0x80,  # OP_LEFT
    0x81,  # OP_RIGHT
    0x83,  # OP_INVERT
    0x84,  # OP_AND
    0x85,  # OP_OR
    0x86,  # OP_XOR
    0x8D,  # OP_2MUL
    0x8E,  # OP_2DIV
    0x95,  # OP_MUL
    0x96,  # OP_DIV
    0x97,  # OP_MOD
    0x98,  # OP_LSHIFT
    0x99,  # OP_RSHIFT
}

_HANDLERS: dict[int, OpcodeHandler] = {}


def get_handler(opcode: int) -> OpcodeHandler:
    """Return the handler function for the given opcode.

    Raises:
        OpDisabledError: If the opcode is disabled.
        KeyError: If no handler is registered for the opcode.
    """
    if opcode in _DISABLED:
        raise OpDisabledError(f"Opcode 0x{opcode:02x} is disabled")
    return _HANDLERS[opcode]


# --- Data push ---


def op_push_data(stack: ScriptStack, data: bytes) -> None:
    """Push raw data bytes onto the stack."""
    stack.push(data)


def op_push_number(stack: ScriptStack, n: int) -> None:
    """Push a small integer (-1 through 16) onto the stack."""
    stack.push(ScriptStack.int_to_element(n))


# --- Stack manipulation ---


def op_dup(stack: ScriptStack) -> None:
    """OP_DUP: Duplicate the top stack element."""
    stack.push(stack.peek())


def op_drop(stack: ScriptStack) -> None:
    """OP_DROP: Remove the top stack element."""
    stack.pop()


def op_swap(stack: ScriptStack) -> None:
    """OP_SWAP: Swap the top two stack elements."""
    a = stack.pop()
    b = stack.pop()
    stack.push(a)
    stack.push(b)


def op_over(stack: ScriptStack) -> None:
    """OP_OVER: Copy the second-to-top element to the top."""
    stack.push(stack.peek(-2))


def op_rot(stack: ScriptStack) -> None:
    """OP_ROT: Rotate the top three elements (3rd -> top)."""
    c = stack.pop()
    b = stack.pop()
    a = stack.pop()
    stack.push(b)
    stack.push(c)
    stack.push(a)


def op_pick(stack: ScriptStack) -> None:
    """OP_PICK: Copy the nth element to the top (n from stack)."""
    n = ScriptStack.element_to_int(stack.pop())
    stack.push(stack.peek(-(n + 1)))


def op_roll(stack: ScriptStack) -> None:
    """OP_ROLL: Move the nth element to the top (n from stack)."""
    n = ScriptStack.element_to_int(stack.pop())
    idx = stack.size() - 1 - n
    element = stack._main.pop(idx)
    stack.push(element)


def op_2dup(stack: ScriptStack) -> None:
    """OP_2DUP: Duplicate the top two stack elements."""
    b = stack.peek(-1)
    a = stack.peek(-2)
    stack.push(a)
    stack.push(b)


def op_3dup(stack: ScriptStack) -> None:
    """OP_3DUP: Duplicate the top three stack elements."""
    c = stack.peek(-1)
    b = stack.peek(-2)
    a = stack.peek(-3)
    stack.push(a)
    stack.push(b)
    stack.push(c)


def op_2drop(stack: ScriptStack) -> None:
    """OP_2DROP: Remove the top two stack elements."""
    stack.pop()
    stack.pop()


def op_2swap(stack: ScriptStack) -> None:
    """OP_2SWAP: Swap the top two pairs of elements."""
    d = stack.pop()
    c = stack.pop()
    b = stack.pop()
    a = stack.pop()
    stack.push(c)
    stack.push(d)
    stack.push(a)
    stack.push(b)


def op_2over(stack: ScriptStack) -> None:
    """OP_2OVER: Copy the 3rd and 4th elements to the top."""
    a = stack.peek(-4)
    b = stack.peek(-3)
    stack.push(a)
    stack.push(b)


def op_2rot(stack: ScriptStack) -> None:
    """OP_2ROT: Move the 5th and 6th elements to the top."""
    f = stack.pop()
    e = stack.pop()
    d = stack.pop()
    c = stack.pop()
    b = stack.pop()
    a = stack.pop()
    stack.push(c)
    stack.push(d)
    stack.push(e)
    stack.push(f)
    stack.push(a)
    stack.push(b)


def op_ifdup(stack: ScriptStack) -> None:
    """OP_IFDUP: Duplicate top if it's nonzero."""
    top = stack.peek()
    if ScriptStack.element_to_bool(top):
        stack.push(top)


def op_depth(stack: ScriptStack) -> None:
    """OP_DEPTH: Push the stack size."""
    stack.push(ScriptStack.int_to_element(stack.size()))


def op_nip(stack: ScriptStack) -> None:
    """OP_NIP: Remove the second-to-top element."""
    top = stack.pop()
    stack.pop()
    stack.push(top)


def op_tuck(stack: ScriptStack) -> None:
    """OP_TUCK: Copy top element and insert before second-to-top."""
    top = stack.pop()
    second = stack.pop()
    stack.push(top)
    stack.push(second)
    stack.push(top)


def op_size(stack: ScriptStack) -> None:
    """OP_SIZE: Push the byte length of the top element (without removing it)."""
    stack.push(ScriptStack.int_to_element(len(stack.peek())))


# --- Arithmetic ---


def op_add(stack: ScriptStack) -> None:
    """OP_ADD: Pop two, push their sum."""
    b = ScriptStack.element_to_int(stack.pop())
    a = ScriptStack.element_to_int(stack.pop())
    stack.push(ScriptStack.int_to_element(a + b))


def op_sub(stack: ScriptStack) -> None:
    """OP_SUB: Pop two, push (second - top)."""
    b = ScriptStack.element_to_int(stack.pop())
    a = ScriptStack.element_to_int(stack.pop())
    stack.push(ScriptStack.int_to_element(a - b))


def op_1add(stack: ScriptStack) -> None:
    """OP_1ADD: Increment top element by 1."""
    a = ScriptStack.element_to_int(stack.pop())
    stack.push(ScriptStack.int_to_element(a + 1))


def op_1sub(stack: ScriptStack) -> None:
    """OP_1SUB: Decrement top element by 1."""
    a = ScriptStack.element_to_int(stack.pop())
    stack.push(ScriptStack.int_to_element(a - 1))


def op_negate(stack: ScriptStack) -> None:
    """OP_NEGATE: Negate the top element."""
    a = ScriptStack.element_to_int(stack.pop())
    stack.push(ScriptStack.int_to_element(-a))


def op_abs(stack: ScriptStack) -> None:
    """OP_ABS: Replace top with its absolute value."""
    a = ScriptStack.element_to_int(stack.pop())
    stack.push(ScriptStack.int_to_element(abs(a)))


def op_not(stack: ScriptStack) -> None:
    """OP_NOT: Boolean NOT (0 -> 1, nonzero -> 0)."""
    a = ScriptStack.element_to_int(stack.pop())
    stack.push(ScriptStack.bool_to_element(a == 0))


def op_0notequal(stack: ScriptStack) -> None:
    """OP_0NOTEQUAL: Push 1 if top is nonzero, else 0."""
    a = ScriptStack.element_to_int(stack.pop())
    stack.push(ScriptStack.bool_to_element(a != 0))


def op_booland(stack: ScriptStack) -> None:
    """OP_BOOLAND: Boolean AND of top two elements."""
    b = ScriptStack.element_to_int(stack.pop())
    a = ScriptStack.element_to_int(stack.pop())
    stack.push(ScriptStack.bool_to_element(a != 0 and b != 0))


def op_boolor(stack: ScriptStack) -> None:
    """OP_BOOLOR: Boolean OR of top two elements."""
    b = ScriptStack.element_to_int(stack.pop())
    a = ScriptStack.element_to_int(stack.pop())
    stack.push(ScriptStack.bool_to_element(a != 0 or b != 0))


def op_numequal(stack: ScriptStack) -> None:
    """OP_NUMEQUAL: Push 1 if top two are numerically equal."""
    b = ScriptStack.element_to_int(stack.pop())
    a = ScriptStack.element_to_int(stack.pop())
    stack.push(ScriptStack.bool_to_element(a == b))


def op_numequalverify(stack: ScriptStack) -> None:
    """OP_NUMEQUALVERIFY: OP_NUMEQUAL then OP_VERIFY."""
    op_numequal(stack)
    op_verify(stack)


def op_numnotequal(stack: ScriptStack) -> None:
    """OP_NUMNOTEQUAL: Push 1 if top two are not equal."""
    b = ScriptStack.element_to_int(stack.pop())
    a = ScriptStack.element_to_int(stack.pop())
    stack.push(ScriptStack.bool_to_element(a != b))


def op_lessthan(stack: ScriptStack) -> None:
    """OP_LESSTHAN: Push 1 if second < top."""
    b = ScriptStack.element_to_int(stack.pop())
    a = ScriptStack.element_to_int(stack.pop())
    stack.push(ScriptStack.bool_to_element(a < b))


def op_greaterthan(stack: ScriptStack) -> None:
    """OP_GREATERTHAN: Push 1 if second > top."""
    b = ScriptStack.element_to_int(stack.pop())
    a = ScriptStack.element_to_int(stack.pop())
    stack.push(ScriptStack.bool_to_element(a > b))


def op_lessthanorequal(stack: ScriptStack) -> None:
    """OP_LESSTHANOREQUAL: Push 1 if second <= top."""
    b = ScriptStack.element_to_int(stack.pop())
    a = ScriptStack.element_to_int(stack.pop())
    stack.push(ScriptStack.bool_to_element(a <= b))


def op_greaterthanorequal(stack: ScriptStack) -> None:
    """OP_GREATERTHANOREQUAL: Push 1 if second >= top."""
    b = ScriptStack.element_to_int(stack.pop())
    a = ScriptStack.element_to_int(stack.pop())
    stack.push(ScriptStack.bool_to_element(a >= b))


def op_min(stack: ScriptStack) -> None:
    """OP_MIN: Push the smaller of the top two elements."""
    b = ScriptStack.element_to_int(stack.pop())
    a = ScriptStack.element_to_int(stack.pop())
    stack.push(ScriptStack.int_to_element(min(a, b)))


def op_max(stack: ScriptStack) -> None:
    """OP_MAX: Push the larger of the top two elements."""
    b = ScriptStack.element_to_int(stack.pop())
    a = ScriptStack.element_to_int(stack.pop())
    stack.push(ScriptStack.int_to_element(max(a, b)))


def op_within(stack: ScriptStack) -> None:
    """OP_WITHIN: Push 1 if x is within [min, max)."""
    max_val = ScriptStack.element_to_int(stack.pop())
    min_val = ScriptStack.element_to_int(stack.pop())
    x = ScriptStack.element_to_int(stack.pop())
    stack.push(ScriptStack.bool_to_element(min_val <= x < max_val))


# --- Equality ---


def op_equal(stack: ScriptStack) -> None:
    """OP_EQUAL: Push 1 if top two are byte-identical, else 0."""
    b = stack.pop()
    a = stack.pop()
    stack.push(ScriptStack.bool_to_element(a == b))


def op_equalverify(stack: ScriptStack) -> None:
    """OP_EQUALVERIFY: OP_EQUAL then OP_VERIFY."""
    op_equal(stack)
    op_verify(stack)


# --- Crypto ---


def op_ripemd160(stack: ScriptStack) -> None:
    """OP_RIPEMD160: Replace top with RIPEMD-160 hash."""
    data = stack.pop()
    stack.push(hashlib.new("ripemd160", data).digest())


def op_sha1(stack: ScriptStack) -> None:
    """OP_SHA1: Replace top with SHA-1 hash."""
    data = stack.pop()
    stack.push(hashlib.sha1(data).digest())  # noqa: S324


def op_sha256(stack: ScriptStack) -> None:
    """OP_SHA256: Replace top with SHA-256 hash."""
    data = stack.pop()
    stack.push(hashlib.sha256(data).digest())


def op_hash160(stack: ScriptStack) -> None:
    """OP_HASH160: Replace top with RIPEMD160(SHA256(x))."""
    data = stack.pop()
    stack.push(hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest())


def op_hash256(stack: ScriptStack) -> None:
    """OP_HASH256: Replace top with SHA256(SHA256(x))."""
    data = stack.pop()
    stack.push(hashlib.sha256(hashlib.sha256(data).digest()).digest())


def op_checksig(
    stack: ScriptStack,
    tx: CTransaction,
    input_index: int,
    input_value: int,
    script_code: bytes,
    sigversion: int = 0,
) -> None:
    """OP_CHECKSIG: Verify ECDSA signature against transaction.

    Pops pubkey and signature from stack, verifies against the
    transaction's signature hash, pushes True/False.
    sigversion: 0 = legacy, 1 = segwit v0 (BIP143).
    """
    from bitcoin.core.key import CECKey
    from bitcoin.core.script import CScript, SignatureHash

    pubkey = stack.pop()
    sig = stack.pop()

    if not sig:
        stack.push(b"")
        return

    hashtype = sig[-1]
    der_sig = sig[:-1]

    try:
        if sigversion == 1:
            sighash = SignatureHash(
                CScript(script_code), tx, input_index, hashtype,
                amount=input_value, sigversion=1,
            )
        else:
            sighash = SignatureHash(CScript(script_code), tx, input_index, hashtype)
        key = CECKey()
        key.set_pubkey(pubkey)
        result = key.verify(sighash, der_sig)
    except Exception:
        result = False

    stack.push(ScriptStack.bool_to_element(result))


def op_checksigverify(
    stack: ScriptStack,
    tx: CTransaction,
    input_index: int,
    input_value: int,
    script_code: bytes,
    sigversion: int = 0,
) -> None:
    """OP_CHECKSIGVERIFY: OP_CHECKSIG then OP_VERIFY."""
    op_checksig(stack, tx, input_index, input_value, script_code, sigversion)
    op_verify(stack)


def op_checkmultisig(
    stack: ScriptStack,
    tx: CTransaction,
    input_index: int,
    input_value: int,
    script_code: bytes,
    sigversion: int = 0,
) -> None:
    """OP_CHECKMULTISIG: M-of-N multi-signature verification.

    Pops N pubkeys, M signatures, and a dummy element (off-by-one bug),
    verifies M signatures against N pubkeys, pushes True/False.
    """
    from bitcoin.core.key import CECKey
    from bitcoin.core.script import CScript, SignatureHash

    n_keys = ScriptStack.element_to_int(stack.pop())
    pubkeys = [stack.pop() for _ in range(n_keys)]

    m_sigs = ScriptStack.element_to_int(stack.pop())
    sigs = [stack.pop() for _ in range(m_sigs)]

    stack.pop()  # consume dummy (Bitcoin's off-by-one bug)

    def _verify(sig: bytes, pubkey: bytes) -> bool:
        if not sig:
            return False
        try:
            hashtype = sig[-1]
            der_sig = sig[:-1]
            if sigversion == 1:
                sighash = SignatureHash(
                    CScript(script_code), tx, input_index, hashtype,
                    amount=input_value, sigversion=1,
                )
            else:
                sighash = SignatureHash(CScript(script_code), tx, input_index, hashtype)
            key = CECKey()
            key.set_pubkey(pubkey)
            return bool(key.verify(sighash, der_sig))
        except Exception:
            return False

    success = True
    key_idx = 0
    for sig in sigs:
        matched = False
        while key_idx < len(pubkeys):
            if _verify(sig, pubkeys[key_idx]):
                key_idx += 1
                matched = True
                break
            key_idx += 1
        if not matched:
            success = False
            break

    stack.push(ScriptStack.bool_to_element(success))


def op_checkmultisigverify(
    stack: ScriptStack,
    tx: CTransaction,
    input_index: int,
    input_value: int,
    script_code: bytes,
    sigversion: int = 0,
) -> None:
    """OP_CHECKMULTISIGVERIFY: OP_CHECKMULTISIG then OP_VERIFY."""
    op_checkmultisig(stack, tx, input_index, input_value, script_code, sigversion)
    op_verify(stack)


# --- Flow control ---


def op_verify(stack: ScriptStack) -> None:
    """OP_VERIFY: Fail if top is false, otherwise remove top.

    Raises:
        VerifyFailedError: If top element is false.
    """
    if not ScriptStack.element_to_bool(stack.pop()):
        raise VerifyFailedError("OP_VERIFY failed")


# --- Build dispatch table ---

_HANDLERS = {
    0x75: op_drop,
    0x76: op_dup,
    0x77: op_nip,
    0x78: op_over,
    0x79: op_pick,
    0x7A: op_roll,
    0x7B: op_rot,
    0x7C: op_swap,
    0x7D: op_tuck,
    0x6D: op_2drop,
    0x6E: op_2dup,
    0x6F: op_3dup,
    0x70: op_2over,
    0x71: op_2rot,
    0x72: op_2swap,
    0x73: op_ifdup,
    0x74: op_depth,
    0x82: op_size,
    0x87: op_equal,
    0x88: op_equalverify,
    0x8B: op_1add,
    0x8C: op_1sub,
    0x8F: op_negate,
    0x90: op_abs,
    0x91: op_not,
    0x92: op_0notequal,
    0x93: op_add,
    0x94: op_sub,
    0x9A: op_booland,
    0x9B: op_boolor,
    0x9C: op_numequal,
    0x9D: op_numequalverify,
    0x9E: op_numnotequal,
    0x9F: op_lessthan,
    0xA0: op_greaterthan,
    0xA1: op_lessthanorequal,
    0xA2: op_greaterthanorequal,
    0xA3: op_min,
    0xA4: op_max,
    0xA5: op_within,
    0xA6: op_ripemd160,
    0xA7: op_sha1,
    0xA8: op_sha256,
    0xA9: op_hash160,
    0xAA: op_hash256,
    0x69: op_verify,
}