"""Fuzzing with a formal oracle: generate random scripts and verify them.

When building a new Bitcoin Script interpreter, how do you know it's
correct? You can't just test known scripts — you need to test *arbitrary*
scripts and compare against a known-correct reference.

The K Framework semantics serve as that reference (oracle). This example:

1. Generates random valid Bitcoin Scripts
2. Runs each through the K formal semantics
3. Records the result (stack, error, success/failure)

The output is a ground-truth dataset. Any alternative interpreter that
disagrees with K on *any* input has a consensus bug.

This is essentially differential fuzzing with a formal oracle —
one of the most powerful techniques for validating new implementations.
"""

from __future__ import annotations

import random
import sys
import time

from bitcoin_script.asm import OPCODES
from bitcoin_script.k_semantics import KBitcoinScript

# Opcodes safe to use in random scripts (no signatures, no timelocks)
FUZZABLE_OPCODES = [
    # Arithmetic
    "OP_ADD", "OP_SUB", "OP_1ADD", "OP_1SUB",
    "OP_NEGATE", "OP_ABS", "OP_NOT", "OP_0NOTEQUAL",
    "OP_BOOLAND", "OP_BOOLOR",
    "OP_NUMEQUAL", "OP_NUMNOTEQUAL",
    "OP_LESSTHAN", "OP_GREATERTHAN",
    "OP_LESSTHANOREQUAL", "OP_GREATERTHANOREQUAL",
    "OP_MIN", "OP_MAX", "OP_WITHIN",
    # Stack
    "OP_DUP", "OP_DROP", "OP_SWAP", "OP_OVER", "OP_ROT",
    "OP_NIP", "OP_TUCK", "OP_2DUP", "OP_2DROP",
    "OP_IFDUP", "OP_DEPTH", "OP_SIZE",
    # Bitwise
    "OP_EQUAL",
    # Crypto (hash only, no sig verification)
    "OP_SHA256", "OP_HASH160", "OP_HASH256", "OP_RIPEMD160",
]


def random_push_int() -> bytes:
    """Generate a random integer push (OP_0 through OP_16, or CScriptNum)."""
    n = random.randint(-1, 16)
    if n == 0:
        return b"\x00"
    if n == -1:
        return b"\x4f"
    if 1 <= n <= 16:
        return bytes([0x50 + n])
    return b"\x51"  # fallback: OP_1


def random_script(max_ops: int = 8) -> bytes:
    """Generate a random Bitcoin Script with stack setup + operations."""
    script = bytearray()

    # Push 2-4 random integers to set up the stack
    n_pushes = random.randint(2, 4)
    for _ in range(n_pushes):
        script.extend(random_push_int())

    # Add random operations
    n_ops = random.randint(1, max_ops)
    for _ in range(n_ops):
        opname = random.choice(FUZZABLE_OPCODES)
        script.append(int(OPCODES[opname], 16))

    return bytes(script)


def main() -> None:
    n_scripts = int(sys.argv[1]) if len(sys.argv) > 1 else 100
    seed = int(sys.argv[2]) if len(sys.argv) > 2 else 42
    random.seed(seed)

    print(f"Loading K Framework semantics...")
    k = KBitcoinScript()
    print(f"Ready. Generating {n_scripts} random scripts (seed={seed})...\n")

    results = {"success": 0, "fail": 0, "error": 0, "stuck": 0}
    t0 = time.monotonic()

    for i in range(n_scripts):
        script = random_script()
        try:
            result = k.verify_script(script_pubkey=script)
        except Exception as e:
            print(f"  [{i:4d}] CRASH: {script.hex()} — {e}")
            results["stuck"] += 1
            continue

        err = k.error(result)
        ok = k.success(result)
        stuck = k.is_stuck(result)
        stack = k.stack(result)

        if stuck:
            category = "stuck"
        elif err:
            category = "error"
        elif ok:
            category = "success"
        else:
            category = "fail"
        results[category] += 1

        if i < 20 or category in ("stuck", "error"):
            stack_str = [item.hex() for item in stack[:3]]
            print(
                f"  [{i:4d}] {category:7s} | "
                f"script={script.hex()[:40]:40s} | "
                f"stack={stack_str} | "
                f"err={err}"
            )

    elapsed = time.monotonic() - t0
    print(f"\n{'=' * 60}")
    print(f"Results ({n_scripts} scripts, {elapsed:.1f}s):")
    print(f"  Success (truthy top): {results['success']}")
    print(f"  Fail (falsy top):     {results['fail']}")
    print(f"  Error (explicit):     {results['error']}")
    print(f"  Stuck (underflow):    {results['stuck']}")
    print(f"\nEach result is canonical — any interpreter that disagrees has a bug.")


if __name__ == "__main__":
    main()
