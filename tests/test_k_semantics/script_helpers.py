"""Helper utilities for building Bitcoin Script hex programs in tests.

Provides opcode-to-hex mapping and convenience functions so tests
can express scripts readably while producing raw hex bytes.
"""

from __future__ import annotations

# Opcode name -> hex byte (without 0x prefix)
OPCODES: dict[str, str] = {
    # Constants
    "OP_0": "00",
    "OP_FALSE": "00",
    "OP_1NEGATE": "4f",
    "OP_1": "51",
    "OP_TRUE": "51",
    "OP_2": "52",
    "OP_3": "53",
    "OP_4": "54",
    "OP_5": "55",
    "OP_6": "56",
    "OP_7": "57",
    "OP_8": "58",
    "OP_9": "59",
    "OP_10": "5a",
    "OP_11": "5b",
    "OP_12": "5c",
    "OP_13": "5d",
    "OP_14": "5e",
    "OP_15": "5f",
    "OP_16": "60",
    # Flow control
    "OP_NOP": "61",
    "OP_IF": "63",
    "OP_NOTIF": "64",
    "OP_ELSE": "67",
    "OP_ENDIF": "68",
    "OP_VERIFY": "69",
    "OP_RETURN": "6a",
    # Stack
    "OP_TOALTSTACK": "6b",
    "OP_FROMALTSTACK": "6c",
    "OP_2DROP": "6d",
    "OP_2DUP": "6e",
    "OP_3DUP": "6f",
    "OP_2OVER": "70",
    "OP_2ROT": "71",
    "OP_2SWAP": "72",
    "OP_IFDUP": "73",
    "OP_DEPTH": "74",
    "OP_DROP": "75",
    "OP_DUP": "76",
    "OP_NIP": "77",
    "OP_OVER": "78",
    "OP_PICK": "79",
    "OP_ROLL": "7a",
    "OP_ROT": "7b",
    "OP_SWAP": "7c",
    "OP_TUCK": "7d",
    # Splice
    "OP_SIZE": "82",
    # Bitwise
    "OP_EQUAL": "87",
    "OP_EQUALVERIFY": "88",
    # Arithmetic
    "OP_1ADD": "8b",
    "OP_1SUB": "8c",
    "OP_NEGATE": "8f",
    "OP_ABS": "90",
    "OP_NOT": "91",
    "OP_0NOTEQUAL": "92",
    "OP_ADD": "93",
    "OP_SUB": "94",
    "OP_BOOLAND": "9a",
    "OP_BOOLOR": "9b",
    "OP_NUMEQUAL": "9c",
    "OP_NUMEQUALVERIFY": "9d",
    "OP_NUMNOTEQUAL": "9e",
    "OP_LESSTHAN": "9f",
    "OP_GREATERTHAN": "a0",
    "OP_LESSTHANOREQUAL": "a1",
    "OP_GREATERTHANOREQUAL": "a2",
    "OP_MIN": "a3",
    "OP_MAX": "a4",
    "OP_WITHIN": "a5",
    # Crypto
    "OP_RIPEMD160": "a6",
    "OP_SHA1": "a7",
    "OP_SHA256": "a8",
    "OP_HASH160": "a9",
    "OP_HASH256": "aa",
    "OP_CODESEPARATOR": "ab",
    "OP_CHECKSIG": "ac",
    "OP_CHECKSIGVERIFY": "ad",
    "OP_CHECKMULTISIG": "ae",
    "OP_CHECKMULTISIGVERIFY": "af",
    # NOP variants
    "OP_NOP1": "b0",
    "OP_NOP2": "b1",
    "OP_NOP3": "b2",
    "OP_NOP4": "b3",
    "OP_NOP5": "b4",
    "OP_NOP6": "b5",
    "OP_NOP7": "b6",
    "OP_NOP8": "b7",
    "OP_NOP9": "b8",
    "OP_NOP10": "b9",
    # Timelock (aliases for NOP2/NOP3)
    "OP_CHECKLOCKTIMEVERIFY": "b1",
    "OP_CHECKSEQUENCEVERIFY": "b2",
    # PUSHDATA
    "OP_PUSHDATA1": "4c",
    "OP_PUSHDATA2": "4d",
    "OP_PUSHDATA4": "4e",
    # Disabled opcodes
    "OP_CAT": "7e",
    "OP_SUBSTR": "7f",
    "OP_LEFT": "80",
    "OP_RIGHT": "81",
    "OP_INVERT": "83",
    "OP_AND": "84",
    "OP_OR": "85",
    "OP_XOR": "86",
    "OP_2MUL": "8d",
    "OP_2DIV": "8e",
    "OP_MUL": "95",
    "OP_DIV": "96",
    "OP_MOD": "97",
    "OP_LSHIFT": "98",
    "OP_RSHIFT": "99",
    # Reserved
    "OP_RESERVED": "50",
    "OP_VER": "62",
    "OP_VERIF": "65",
    "OP_VERNOTIF": "66",
    "OP_RESERVED1": "89",
    "OP_RESERVED2": "8a",
}


def push(data_hex: str) -> str:
    """Create a push operation: length byte + data.

    Args:
        data_hex: Hex string of data to push (e.g. "abcd" for 2 bytes).

    Returns:
        Hex string with push opcode prefix.
    """
    data_bytes = bytes.fromhex(data_hex)
    n = len(data_bytes)
    if n <= 75:
        return f"{n:02x}{data_hex}"
    raise ValueError(f"push() only supports up to 75 bytes, got {n}")


def push_int(n: int) -> str:
    """Push an integer using the smallest encoding.

    Uses OP_0..OP_16 for 0-16, OP_1NEGATE for -1,
    otherwise CScriptNum encoding with push opcode.
    """
    if n == 0:
        return OPCODES["OP_0"]
    if n == -1:
        return OPCODES["OP_1NEGATE"]
    if 1 <= n <= 16:
        return OPCODES[f"OP_{n}"]
    # CScriptNum encoding
    return push(_int_to_scriptnum_hex(n))


def _int_to_scriptnum_hex(n: int) -> str:
    """Encode an integer as CScriptNum bytes (hex string)."""
    if n == 0:
        return ""
    negative = n < 0
    absval = abs(n)

    # Encode as little-endian bytes
    result = []
    while absval > 0:
        result.append(absval & 0xFF)
        absval >>= 8

    # If the high bit is set, add an extra byte for the sign
    if result[-1] & 0x80:
        result.append(0x80 if negative else 0x00)
    elif negative:
        result[-1] |= 0x80

    return bytes(result).hex()


def script(*parts: str) -> bytes:
    """Build script bytes from opcode names and hex data.

    Each part is either:
    - An opcode name (e.g. "OP_DUP") -> looked up in OPCODES
    - A raw hex string (e.g. "41abcd...") -> passed through directly

    Returns:
        Raw script bytes.

    Example:
        script("OP_DUP", "OP_HASH160", push("ab" * 20), "OP_EQUALVERIFY", "OP_CHECKSIG")
    """
    hex_parts = []
    for part in parts:
        if part in OPCODES:
            hex_parts.append(OPCODES[part])
        else:
            # Raw hex data (e.g. from push())
            hex_parts.append(part)
    return bytes.fromhex("".join(hex_parts))
