"""Step-by-step execution tracing of Bitcoin Script.

Uses K's bounded execution (depth=N) to single-step through a script
and inspect every intermediate state. This is a powerful debugging and
educational tool — you can see exactly how the stack evolves at each
opcode.

Example output:

    Step 0: OP_2 OP_3 OP_ADD OP_5 OP_EQUAL
      stack: []
    Step 1: OP_3 OP_ADD OP_5 OP_EQUAL
      stack: [02]
    Step 2: OP_ADD OP_5 OP_EQUAL
      stack: [03, 02]
    Step 3: OP_5 OP_EQUAL
      stack: [05]
    Step 4: OP_EQUAL
      stack: [05, 05]
    Step 5: (done)
      stack: [01]
      result: PASS
"""

from __future__ import annotations

from pyk.kore.syntax import App, DV, LeftAssoc, String

from bitcoin_script.asm import parse_asm
from bitcoin_script.k_semantics import KBitcoinScript
from bitcoin_script.k_semantics.semantics import _find_cell, _list_items


def extract_k_cell_summary(pattern) -> str:
    """Extract a human-readable summary of what's left to execute in the <k> cell."""
    cell = _find_cell(pattern, "Lbl'-LT-'k'-GT-'")
    if cell is None:
        return "(unknown)"
    # Check if k cell is empty
    match cell:
        case App(args=[App(symbol="dotk"), *_]):
            return "(done)"
    # Just show the pretty-printed k cell (truncated)
    from bitcoin_script.k_semantics import KBitcoinScript
    k = KBitcoinScript()
    text = k.pretty(cell)
    # Extract just the interesting part
    if "<k>" in text:
        start = text.index("<k>") + 3
        end = text.index("</k>") if "</k>" in text else len(text)
        text = text[start:end].strip()
    return text[:120] + ("..." if len(text) > 120 else "")


def format_stack(stack_items: list[bytes]) -> str:
    """Format stack for display."""
    if not stack_items:
        return "[]"
    return "[" + ", ".join(item.hex() for item in stack_items) + "]"


def trace(script_asm: str, max_steps: int = 50) -> None:
    """Trace execution of a Bitcoin Script, printing state at each step."""
    k = KBitcoinScript()
    script_bytes = parse_asm(script_asm)

    print(f"Script: {script_asm}")
    print(f"Hex:    {script_bytes.hex()}")
    print(f"Length: {len(script_bytes)} bytes")
    print()

    # Build initial pattern and step through
    pattern = k.pattern(script_pubkey=script_bytes)

    for step in range(max_steps):
        # Run one step
        next_pattern = k.run(pattern, depth=1)

        stack = k.stack(next_pattern)
        err = k.error(next_pattern)

        print(f"  Step {step + 1}:")
        print(f"    stack: {format_stack(stack)}")

        if err:
            print(f"    error: {err}")
            break

        if not k.is_stuck(next_pattern) and _is_done(next_pattern):
            ok = k.success(next_pattern)
            print(f"    result: {'PASS' if ok else 'FAIL'}")
            break

        if k.is_stuck(next_pattern):
            print("    (stuck — pattern match failure)")
            break

        # Check if we made progress
        if _patterns_equal(pattern, next_pattern):
            print("    (no progress — execution complete)")
            break

        pattern = next_pattern

    print()


def _is_done(pattern) -> bool:
    """Check if k cell is empty (execution complete)."""
    match _find_cell(pattern, "Lbl'-LT-'k'-GT-'"):
        case App(args=[App(symbol="dotk"), *_]):
            return True
    return False


def _patterns_equal(a, b) -> bool:
    """Rough equality check via string comparison."""
    return str(a) == str(b)


def main() -> None:
    print("Loading K Framework semantics...")
    k = KBitcoinScript()
    print("Ready.\n")

    print("=" * 60)
    print("Example 1: Simple arithmetic")
    print("=" * 60)
    trace("OP_2 OP_3 OP_ADD OP_5 OP_EQUAL")

    print("=" * 60)
    print("Example 2: DUP + hash verification")
    print("=" * 60)
    trace("OP_1 OP_DUP OP_ADD OP_2 OP_EQUAL")

    print("=" * 60)
    print("Example 3: Conditional execution")
    print("=" * 60)
    trace("OP_1 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF")

    print("=" * 60)
    print("Example 4: Stack manipulation")
    print("=" * 60)
    trace("OP_3 OP_5 OP_2 OP_PICK OP_ADD")


if __name__ == "__main__":
    main()
