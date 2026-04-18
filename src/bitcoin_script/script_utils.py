"""Shared Bitcoin script utility functions.

Low-level helpers for parsing scripts, detecting script types, computing
sighash subscripts, and encoding witness data. Used by both the chain
verifier and test infrastructure.
"""

from __future__ import annotations


def scriptnum_to_int(b: bytes) -> int:
    """Decode CScriptNum bytes (little-endian sign-magnitude) to Python int."""
    if len(b) == 0:
        return 0
    magnitude = int.from_bytes(b[:-1] + bytes([b[-1] & 0x7F]), "little")
    return -magnitude if b[-1] & 0x80 else magnitude


def encode_witness_blob(witness_stack: list[bytes]) -> bytes:
    """Encode witness stack as: <2B BE count> (<2B BE length> <data>)*"""
    result = len(witness_stack).to_bytes(2, "big")
    for item in witness_stack:
        result += len(item).to_bytes(2, "big") + item
    return result


def is_witness_program(script: bytes) -> tuple[int, bytes] | None:
    """Detect witness program: <version_byte> <push_2_to_40_bytes>."""
    if len(script) < 4 or len(script) > 42:
        return None
    v = script[0]
    if v == 0x00:
        version = 0
    elif 0x51 <= v <= 0x60:
        version = v - 0x50
    else:
        return None
    if script[1] + 2 != len(script):
        return None
    return (version, script[2:])


def is_p2sh(script: bytes) -> bool:
    """Check if scriptPubKey is P2SH: OP_HASH160 <20 bytes> OP_EQUAL."""
    return (
        len(script) == 23
        and script[0] == 0xA9
        and script[1] == 0x14
        and script[22] == 0x87
    )


def classify_script(
    script_pubkey: bytes,
    script_sig: bytes,
    witness: list[bytes],
) -> str:
    """Classify an input by its actual spending path.

    Returns one of: P2PKH, P2PK, P2PK-uncompressed, P2SH, P2SH-P2WPKH,
    P2SH-P2WSH, P2WPKH, P2WSH, P2TR-keypath, P2TR-scriptpath, or other.
    """
    wp = is_witness_program(script_pubkey)
    if wp is not None:
        version, program = wp
        if version == 0 and len(program) == 20:
            return "P2WPKH"
        if version == 0 and len(program) == 32:
            return "P2WSH"
        if version == 1 and len(program) == 32:
            w = list(witness)
            if len(w) >= 2 and w[-1][:1] == b"\x50":
                w = w[:-1]  # strip annex
            if len(w) == 1:
                return "P2TR-keypath"
            if len(w) >= 2:
                return "P2TR-scriptpath"
            return "P2TR-empty"
        return f"witness-v{version}"
    if is_p2sh(script_pubkey):
        if script_sig:
            redeem = extract_last_push(script_sig)
            if redeem is not None:
                wp2 = is_witness_program(redeem)
                if wp2 is not None:
                    if wp2[0] == 0 and len(wp2[1]) == 20:
                        return "P2SH-P2WPKH"
                    if wp2[0] == 0 and len(wp2[1]) == 32:
                        return "P2SH-P2WSH"
        return "P2SH"
    # P2PKH: OP_DUP OP_HASH160 <push20> <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    if (
        len(script_pubkey) == 25
        and script_pubkey[0] == 0x76
        and script_pubkey[1] == 0xA9
        and script_pubkey[2] == 0x14
        and script_pubkey[23] == 0x88
        and script_pubkey[24] == 0xAC
    ):
        return "P2PKH"
    # P2PK compressed: <push33> <33 bytes> OP_CHECKSIG
    if (
        len(script_pubkey) == 35
        and script_pubkey[0] == 0x21
        and script_pubkey[34] == 0xAC
    ):
        return "P2PK"
    # P2PK uncompressed: <push65> <65 bytes> OP_CHECKSIG
    if (
        len(script_pubkey) == 67
        and script_pubkey[0] == 0x41
        and script_pubkey[66] == 0xAC
    ):
        return "P2PK-uncompressed"
    return "other"


def extract_last_push(script: bytes) -> bytes | None:
    """Extract the last push data from a script."""
    pos = 0
    last_push: bytes | None = None
    while pos < len(script):
        op = script[pos]
        pos += 1
        if 1 <= op <= 75:
            last_push = script[pos : pos + op]
            pos += op
        elif op == 0x4C and pos < len(script):
            n = script[pos]
            pos += 1
            last_push = script[pos : pos + n]
            pos += n
        elif op == 0x4D and pos + 1 < len(script):
            n = int.from_bytes(script[pos : pos + 2], "little")
            pos += 2
            last_push = script[pos : pos + n]
            pos += n
        elif op == 0x4E and pos + 3 < len(script):
            n = int.from_bytes(script[pos : pos + 4], "little")
            pos += 4
            last_push = script[pos : pos + n]
            pos += n
    return last_push


def extract_sig_hashtypes(data: bytes) -> set[int]:
    """Extract hashtype bytes from push data that looks like DER signatures."""
    hashtypes: set[int] = set()
    pos = 0
    while pos < len(data):
        op = data[pos]
        pos += 1
        if 1 <= op <= 75:
            item = data[pos : pos + op]
            pos += op
            if len(item) >= 9 and item[0] == 0x30:
                hashtypes.add(item[-1])
        elif op == 0x4C and pos < len(data):
            n = data[pos]
            pos += 1
            pos += n
        elif op == 0x4D and pos + 1 < len(data):
            n = int.from_bytes(data[pos : pos + 2], "little")
            pos += 2
            pos += n
        elif op == 0x4E and pos + 3 < len(data):
            n = int.from_bytes(data[pos : pos + 4], "little")
            pos += 4
            pos += n
    return hashtypes


def extract_push_data(script: bytes) -> list[bytes]:
    """Walk script and extract all push data items."""
    items: list[bytes] = []
    pos = 0
    while pos < len(script):
        op = script[pos]
        pos += 1
        if 1 <= op <= 75:
            items.append(script[pos : pos + op])
            pos += op
        elif op == 0x4C and pos < len(script):
            n = script[pos]
            pos += 1
            items.append(script[pos : pos + n])
            pos += n
        elif op == 0x4D and pos + 1 < len(script):
            n = int.from_bytes(script[pos : pos + 2], "little")
            pos += 2
            items.append(script[pos : pos + n])
            pos += n
        elif op == 0x4E and pos + 3 < len(script):
            n = int.from_bytes(script[pos : pos + 4], "little")
            pos += 4
            items.append(script[pos : pos + n])
            pos += n
    return items


def find_codesep_positions(script: bytes) -> list[int]:
    """Find byte positions right after each OP_CODESEPARATOR (0xAB) in script."""
    positions: list[int] = []
    pos = 0
    while pos < len(script):
        op = script[pos]
        pos += 1
        if op == 0xAB:
            positions.append(pos)
        elif 1 <= op <= 75:
            pos += op
        elif op == 0x4C and pos < len(script):
            pos += 1 + script[pos]
        elif op == 0x4D and pos + 1 < len(script):
            pos += 2 + int.from_bytes(script[pos : pos + 2], "little")
        elif op == 0x4E and pos + 3 < len(script):
            pos += 4 + int.from_bytes(script[pos : pos + 4], "little")
    return positions


def remove_codeseparators(script: bytes) -> bytes:
    """Remove all OP_CODESEPARATOR (0xAB) bytes from script."""
    result = bytearray()
    pos = 0
    while pos < len(script):
        op = script[pos]
        if op == 0xAB:
            pos += 1
            continue
        result.append(op)
        pos += 1
        if 1 <= op <= 75:
            result.extend(script[pos : pos + op])
            pos += op
        elif op == 0x4C and pos < len(script):
            n = script[pos]
            result.append(n)
            pos += 1
            result.extend(script[pos : pos + n])
            pos += n
        elif op == 0x4D and pos + 1 < len(script):
            result.extend(script[pos : pos + 2])
            n = int.from_bytes(script[pos : pos + 2], "little")
            pos += 2
            result.extend(script[pos : pos + n])
            pos += n
        elif op == 0x4E and pos + 3 < len(script):
            result.extend(script[pos : pos + 4])
            n = int.from_bytes(script[pos : pos + 4], "little")
            pos += 4
            result.extend(script[pos : pos + n])
            pos += n
    return bytes(result)
