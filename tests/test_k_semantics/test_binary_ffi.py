"""Equivalence test for the binary KORE construction path.

Exercises ``_KRuntime.run_binary`` against the existing text-based path
on a trivial OP_TRUE script and asserts the resulting <stack> cells
match.
"""

from __future__ import annotations

import sys

import pytest

from bitcoin_script.k_semantics import KBitcoinScript


pytestmark = pytest.mark.k


def test_run_binary_matches_text_path(k: KBitcoinScript) -> None:
    """Text and binary KORE construction paths must produce identical stacks."""
    rt = k._runtime
    if rt is None:
        pytest.skip("FFI runtime unavailable")

    script_pubkey = b"\x51"  # OP_TRUE

    text_pattern = k.verify_script(script_pubkey)
    text_stack = k.stack(text_pattern)

    config_vars: dict[str, tuple[str, bytes | int]] = {
        "$SCRIPTSIG": ("SortBytes", b""),
        "$SCRIPTPUBKEY": ("SortBytes", script_pubkey),
        "$SIGHASH": ("SortBytes", b""),
        "$WITNESS": ("SortBytes", b""),
        "$FLAGS": ("SortInt", 0),
        "$TXVERSION": ("SortInt", 1),
        "$NLOCKTIME": ("SortInt", 0),
        "$NSEQUENCE": ("SortInt", 0xFFFFFFFF),
        "$SIGOPSBUDGET": ("SortInt", 2_000_000_000),
        "$TX": ("SortBytes", b""),
        "$PREVOUTS": ("SortBytes", b""),
        "$INPUTINDEX": ("SortInt", 0),
        "$AMOUNT": ("SortInt", 0),
    }

    from pyk.kore.parser import KoreParser

    binary_text = rt.run_binary(config_vars)
    old_limit = sys.getrecursionlimit()
    sys.setrecursionlimit(max(old_limit, 50_000))
    try:
        binary_pattern = KoreParser(binary_text).pattern()
    finally:
        sys.setrecursionlimit(old_limit)

    binary_stack = k.stack(binary_pattern)

    assert binary_stack == text_stack
    assert binary_stack == [b"\x01"]
