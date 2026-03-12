"""Opcode category groupings as frozen sets."""

from __future__ import annotations

from typing import FrozenSet

from bitcoin_script.opcodes.opcode import Opcode

CONSTANT_OPS: FrozenSet[Opcode] = frozenset({
    Opcode.OP_0, Opcode.OP_1NEGATE,
    Opcode.OP_1, Opcode.OP_2, Opcode.OP_3, Opcode.OP_4,
    Opcode.OP_5, Opcode.OP_6, Opcode.OP_7, Opcode.OP_8,
    Opcode.OP_9, Opcode.OP_10, Opcode.OP_11, Opcode.OP_12,
    Opcode.OP_13, Opcode.OP_14, Opcode.OP_15, Opcode.OP_16,
    Opcode.OP_PUSHDATA1, Opcode.OP_PUSHDATA2, Opcode.OP_PUSHDATA4,
})

FLOW_CONTROL_OPS: FrozenSet[Opcode] = frozenset({
    Opcode.OP_NOP, Opcode.OP_IF, Opcode.OP_NOTIF,
    Opcode.OP_ELSE, Opcode.OP_ENDIF, Opcode.OP_VERIFY,
    Opcode.OP_RETURN,
})

STACK_OPS: FrozenSet[Opcode] = frozenset({
    Opcode.OP_TOALTSTACK, Opcode.OP_FROMALTSTACK,
    Opcode.OP_2DROP, Opcode.OP_2DUP, Opcode.OP_3DUP,
    Opcode.OP_2OVER, Opcode.OP_2ROT, Opcode.OP_2SWAP,
    Opcode.OP_IFDUP, Opcode.OP_DEPTH, Opcode.OP_DROP,
    Opcode.OP_DUP, Opcode.OP_NIP, Opcode.OP_OVER,
    Opcode.OP_PICK, Opcode.OP_ROLL, Opcode.OP_ROT,
    Opcode.OP_SWAP, Opcode.OP_TUCK, Opcode.OP_SIZE,
})

ARITHMETIC_OPS: FrozenSet[Opcode] = frozenset({
    Opcode.OP_1ADD, Opcode.OP_1SUB, Opcode.OP_NEGATE,
    Opcode.OP_ABS, Opcode.OP_NOT, Opcode.OP_0NOTEQUAL,
    Opcode.OP_ADD, Opcode.OP_SUB, Opcode.OP_BOOLAND,
    Opcode.OP_BOOLOR, Opcode.OP_NUMEQUAL, Opcode.OP_NUMEQUALVERIFY,
    Opcode.OP_NUMNOTEQUAL, Opcode.OP_LESSTHAN, Opcode.OP_GREATERTHAN,
    Opcode.OP_LESSTHANOREQUAL, Opcode.OP_GREATERTHANOREQUAL,
    Opcode.OP_MIN, Opcode.OP_MAX, Opcode.OP_WITHIN,
    Opcode.OP_EQUAL, Opcode.OP_EQUALVERIFY,
})

CRYPTO_OPS: FrozenSet[Opcode] = frozenset({
    Opcode.OP_RIPEMD160, Opcode.OP_SHA1, Opcode.OP_SHA256,
    Opcode.OP_HASH160, Opcode.OP_HASH256,
    Opcode.OP_CODESEPARATOR, Opcode.OP_CHECKSIG,
    Opcode.OP_CHECKSIGVERIFY, Opcode.OP_CHECKMULTISIG,
    Opcode.OP_CHECKMULTISIGVERIFY,
})

LOCKTIME_OPS: FrozenSet[Opcode] = frozenset({
    Opcode.OP_CHECKLOCKTIMEVERIFY,
    Opcode.OP_CHECKSEQUENCEVERIFY,
})

RESERVED_OPS: FrozenSet[Opcode] = frozenset({
    Opcode.OP_RESERVED, Opcode.OP_VER,
    Opcode.OP_RESERVED1, Opcode.OP_RESERVED2,
})

DISABLED_OPS: FrozenSet[Opcode] = frozenset({
    Opcode.OP_CAT, Opcode.OP_SUBSTR, Opcode.OP_LEFT,
    Opcode.OP_RIGHT, Opcode.OP_INVERT, Opcode.OP_AND,
    Opcode.OP_OR, Opcode.OP_XOR, Opcode.OP_2MUL,
    Opcode.OP_2DIV, Opcode.OP_MUL, Opcode.OP_DIV,
    Opcode.OP_MOD, Opcode.OP_LSHIFT, Opcode.OP_RSHIFT,
    Opcode.OP_VERIF, Opcode.OP_VERNOTIF,
})

NOP_OPS: FrozenSet[Opcode] = frozenset({
    Opcode.OP_NOP, Opcode.OP_NOP1, Opcode.OP_NOP4,
    Opcode.OP_NOP5, Opcode.OP_NOP6, Opcode.OP_NOP7,
    Opcode.OP_NOP8, Opcode.OP_NOP9, Opcode.OP_NOP10,
})
