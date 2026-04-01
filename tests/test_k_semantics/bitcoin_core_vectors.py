"""Parse Bitcoin Core's script_tests.json ASM format into raw script bytes.

Bitcoin Core's test vectors use a different ASM notation than our helpers:
- Bare opcode names without OP_ prefix: DUP, HASH160, EQUAL
- Hex data pushes: 0x14 0xabcd... (length byte + data as separate tokens)
- PUSHDATA variants: 0x4c/4d/4e followed by length + data tokens
- String literals: 'hello' (single-quoted ASCII)
- Bare integers: 0, 1, -1, 2147483647
"""

from __future__ import annotations

from .script_helpers import OPCODES, _int_to_scriptnum_hex

# Build bare-name -> hex map by stripping OP_ prefix
BARE_TO_HEX: dict[str, str] = {}
for name, hex_val in OPCODES.items():
    BARE_TO_HEX[name] = hex_val
    if name.startswith("OP_"):
        bare = name[3:]
        # Don't overwrite if bare name already exists
        if bare not in BARE_TO_HEX:
            BARE_TO_HEX[bare] = hex_val

# Additional bare-name aliases used in Bitcoin Core tests
BARE_TO_HEX.update({
    "CHECKLOCKTIMEVERIFY": OPCODES["OP_CHECKLOCKTIMEVERIFY"],
    "CHECKSEQUENCEVERIFY": OPCODES["OP_CHECKSEQUENCEVERIFY"],
    "TRUE": OPCODES["OP_TRUE"],
    "FALSE": OPCODES["OP_FALSE"],
})


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


def _token_to_raw_hex(token: str, byte_width: int) -> str:
    """Convert a token to a fixed-width hex string for PUSHDATA length fields.

    Handles both 0x-prefixed hex and bare integers.
    """
    if token.startswith("0x") or token.startswith("0X"):
        return token[2:]
    # Bare integer: encode as little-endian
    n = int(token)
    return n.to_bytes(byte_width, "little").hex()


def parse_bitcoin_core_asm(asm: str) -> bytes:
    """Parse Bitcoin Core ASM notation into raw script bytes.

    Handles: bare opcodes (DUP), OP_-prefixed opcodes, hex pushes (0x...),
    single-quoted strings ('hello'), and bare integers.
    """
    if not asm or not asm.strip():
        return b""

    tokens = asm.split()
    result: list[str] = []
    i = 0

    while i < len(tokens):
        token = tokens[i]

        # Single-quoted string: 'hello' -> length-prefixed push
        if token.startswith("'") and token.endswith("'"):
            data = token[1:-1].encode("ascii")
            result.append(_push_data_hex(data))
            i += 1
            continue

        # Multi-word quoted string: 'hello world'
        if token.startswith("'") and not token.endswith("'"):
            parts = [token[1:]]
            i += 1
            while i < len(tokens):
                if tokens[i].endswith("'"):
                    parts.append(tokens[i][:-1])
                    break
                parts.append(tokens[i])
                i += 1
            data = " ".join(parts).encode("ascii")
            result.append(_push_data_hex(data))
            i += 1
            continue

        # Hex literal: 0x...
        if token.startswith("0x") or token.startswith("0X"):
            raw = bytes.fromhex(token[2:])

            # Single byte: could be a push-length prefix or raw opcode byte
            if len(raw) == 1:
                byte_val = raw[0]

                # 0x01-0x4b: push N bytes (next token is the data)
                if 1 <= byte_val <= 75:
                    result.append(token[2:])
                    if i + 1 < len(tokens) and tokens[i + 1].startswith("0x"):
                        i += 1
                        result.append(tokens[i][2:])
                    i += 1
                    continue

                # 0x4c: PUSHDATA1 — next token is 1-byte length, then data
                if byte_val == 0x4C:
                    result.append("4c")
                    if i + 1 < len(tokens):
                        i += 1
                        length_hex = _token_to_raw_hex(tokens[i], 1)
                        result.append(length_hex)
                        if i + 1 < len(tokens) and tokens[i + 1].startswith("0x"):
                            i += 1
                            result.append(tokens[i][2:])
                    i += 1
                    continue

                # 0x4d: PUSHDATA2 — next token is 2-byte LE length, then data
                if byte_val == 0x4D:
                    result.append("4d")
                    if i + 1 < len(tokens):
                        i += 1
                        length_hex = _token_to_raw_hex(tokens[i], 2)
                        result.append(length_hex)
                        if i + 1 < len(tokens) and tokens[i + 1].startswith("0x"):
                            i += 1
                            result.append(tokens[i][2:])
                    i += 1
                    continue

                # 0x4e: PUSHDATA4 — next token is 4-byte LE length, then data
                if byte_val == 0x4E:
                    result.append("4e")
                    if i + 1 < len(tokens):
                        i += 1
                        length_hex = _token_to_raw_hex(tokens[i], 4)
                        result.append(length_hex)
                        if i + 1 < len(tokens) and tokens[i + 1].startswith("0x"):
                            i += 1
                            result.append(tokens[i][2:])
                    i += 1
                    continue

            # Otherwise: emit raw bytes
            result.append(raw.hex())
            i += 1
            continue

        # Bare opcode name or OP_-prefixed name
        if token in BARE_TO_HEX:
            result.append(BARE_TO_HEX[token])
            i += 1
            continue

        # Bare integer
        try:
            n = int(token)
            if n == 0:
                result.append("00")  # OP_0
            elif n == -1:
                result.append("4f")  # OP_1NEGATE
            elif 1 <= n <= 16:
                result.append(f"{0x50 + n:02x}")  # OP_1 through OP_16
            else:
                # CScriptNum encoding with push prefix
                num_hex = _int_to_scriptnum_hex(n)
                num_bytes = len(num_hex) // 2
                result.append(f"{num_bytes:02x}")
                result.append(num_hex)
            i += 1
            continue
        except ValueError:
            pass

        # Unknown token: emit as-is (will likely cause a test failure)
        result.append(token)
        i += 1

    return bytes.fromhex("".join(result))


def parse_flags(flags_str: str) -> set[str]:
    """Parse comma-separated flags string into a set."""
    if not flags_str or flags_str == "NONE":
        return set()
    return set(flags_str.split(","))


# Expected-result strings that correspond to validation flags we don't enforce
_FLAG_ERRORS = {
    "DERSIG", "SIG_DER",
    "MINIMALIF",
    "SIG_NULLFAIL",
}

# Resource limit errors we don't enforce (STACK_SIZE still pending)
_RESOURCE_ERRORS = {
    "STACK_SIZE",
}


def classify_vector(entry: list) -> str | None:
    """Return an xfail reason if this vector can't run, or None if it can."""
    sig_asm = entry[0]
    pubkey_asm = entry[1]
    flags_str = entry[2] if len(entry) > 2 else ""
    expected = entry[3] if len(entry) > 3 else "OK"
    combined = f"{sig_asm} {pubkey_asm}"
    tokens = combined.split()
    flags = parse_flags(flags_str)

    # --- OP_SHA1: no KRYPTO hook ---
    if "SHA1" in tokens:
        return "OP_SHA1 not implemented"

    # CLTV/CSV: partially implemented — CScriptNum minimal check with nMaxNumSize=5 not done
    if expected == "SCRIPTNUM" and ("CHECKSEQUENCEVERIFY" in flags or "CHECKLOCKTIMEVERIFY" in flags):
        return "CSV/CLTV SCRIPTNUM minimal encoding not implemented"

    # --- Expected errors that correspond to unimplemented validation ---
    if expected in _FLAG_ERRORS:
        return f"flag-dependent error: {expected}"
    if expected in _RESOURCE_ERRORS:
        return f"resource limit: {expected}"

    # (SCRIPTNUM range is now enforced via scriptNumToInt <=4 byte check)

    # --- Locktime errors ---
    if expected in ("UNSATISFIED_LOCKTIME", "NEGATIVE_LOCKTIME"):
        return f"locktime: {expected}"

    # --- Signature validation errors we don't enforce ---
    if expected in ("SIG_HIGH_S", "SIG_DER"):
        return f"sig validation: {expected}"

    # --- Witness program errors ---
    if expected.startswith("WITNESS"):
        return f"witness: {expected}"

    # (5-byte integer encoding now supported via intToScriptNumAbs 5-byte rule)

    # --- Flag-based enforcement we don't do ---
    # (DISCOURAGE_UPGRADABLE_NOPS, CLEANSTACK, NULLDUMMY, SIG_PUSHONLY, MINIMALDATA now enforced)
    # NULLFAIL enforced for CHECKSIG; multisig edge cases with NULLFAIL+NOT may still pass
    if expected == "NULLFAIL":
        return "flag-dependent error: NULLFAIL"
    if "CONST_SCRIPTCODE" in flags and expected != "OK":
        return "CONST_SCRIPTCODE not enforced"
    # STRICTENC pubkey validation in CHECKMULTISIG not yet implemented
    sig_ops = {"CHECKSIG", "CHECKSIGVERIFY", "CHECKMULTISIG", "CHECKMULTISIGVERIFY"}
    has_sig_op = any(op in tokens for op in sig_ops)
    if has_sig_op and expected == "PUBKEYTYPE" and "STRICTENC" in flags:
        # Check if any pubkey in the script is invalid (0, hybrid 06/07 prefix)
        for tok in tokens:
            if tok == "0" or (tok.startswith("0x") and len(tok) >= 4 and tok[2:4] in ("06", "07")):
                return "STRICTENC PUBKEYTYPE in multisig not enforced"

    return None
