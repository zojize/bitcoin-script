"""Parse Bitcoin Script ASM notation into raw script bytes.

Supports: OP_-prefixed opcodes, bare opcode names (DUP, ADD), hex data (0xabcd),
single-quoted strings ('hello'), and bare integers (0, -1, 42).
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
    # Timelock aliases
    "OP_CHECKLOCKTIMEVERIFY": "b1",
    "OP_CHECKSEQUENCEVERIFY": "b2",
    # PUSHDATA
    "OP_PUSHDATA1": "4c",
    "OP_PUSHDATA2": "4d",
    "OP_PUSHDATA4": "4e",
    # Disabled
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
    # Pseudo
    "OP_INVALIDOPCODE": "ff",
}

# Build bare-name -> hex map (DUP -> 76, ADD -> 93, etc.)
_BARE_TO_HEX: dict[str, str] = {}
for _name, _hex_val in OPCODES.items():
    _BARE_TO_HEX[_name] = _hex_val
    if _name.startswith("OP_"):
        _bare = _name[3:]
        if _bare not in _BARE_TO_HEX:
            _BARE_TO_HEX[_bare] = _hex_val

_BARE_TO_HEX.update(
    {
        "CHECKLOCKTIMEVERIFY": OPCODES["OP_CHECKLOCKTIMEVERIFY"],
        "CHECKSEQUENCEVERIFY": OPCODES["OP_CHECKSEQUENCEVERIFY"],
        "TRUE": OPCODES["OP_TRUE"],
        "FALSE": OPCODES["OP_FALSE"],
    }
)


def _int_to_scriptnum_hex(n: int) -> str:
    """Encode an integer as CScriptNum bytes (hex string)."""
    if n == 0:
        return ""
    negative = n < 0
    absval = abs(n)
    result: list[int] = []
    while absval > 0:
        result.append(absval & 0xFF)
        absval >>= 8
    if result[-1] & 0x80:
        result.append(0x80 if negative else 0x00)
    elif negative:
        result[-1] |= 0x80
    return bytes(result).hex()


def _push_data_hex(data: bytes) -> str:
    """Encode a data push using the smallest push opcode."""
    n = len(data)
    if n == 0:
        return "00"  # OP_0
    if n <= 75:
        return f"{n:02x}{data.hex()}"
    if n <= 255:
        return f"4c{n:02x}{data.hex()}"
    if n <= 65535:
        return f"4d{n.to_bytes(2, 'little').hex()}{data.hex()}"
    return f"4e{n.to_bytes(4, 'little').hex()}{data.hex()}"


def parse_asm(asm: str) -> bytes:
    """Parse Bitcoin Script ASM notation into raw script bytes.

    Handles: bare opcodes (DUP), OP_-prefixed opcodes, hex data (0xabcd),
    single-quoted strings ('hello'), and bare integers.
    """
    if not asm or not asm.strip():
        return b""

    tokens = asm.split()
    result: list[str] = []

    for token in tokens:
        # Single-quoted string: 'hello' -> length-prefixed push
        if token.startswith("'") and token.endswith("'") and len(token) > 1:
            data = token[1:-1].encode("ascii")
            result.append(_push_data_hex(data))
            continue

        # Hex data: 0xabcd -> length-prefixed push
        if token.startswith("0x") or token.startswith("0X"):
            data = bytes.fromhex(token[2:])
            result.append(_push_data_hex(data))
            continue

        # Opcode name (OP_-prefixed or bare)
        if token.upper() in _BARE_TO_HEX:
            result.append(_BARE_TO_HEX[token.upper()])
            continue

        # Bare integer
        try:
            n = int(token)
            if n == 0:
                result.append("00")
            elif n == -1:
                result.append("4f")
            elif 1 <= n <= 16:
                result.append(f"{0x50 + n:02x}")
            else:
                num_hex = _int_to_scriptnum_hex(n)
                num_bytes = len(num_hex) // 2
                result.append(f"{num_bytes:02x}")
                result.append(num_hex)
            continue
        except ValueError:
            pass

        raise ValueError(f"Unknown token: {token}")

    return bytes.fromhex("".join(result))
