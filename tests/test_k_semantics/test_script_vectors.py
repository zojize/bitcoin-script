"""Bitcoin Core script_tests.json test vectors."""

from __future__ import annotations

import pytest

from .bitcoin_core_vectors import classify_vector, parse_bitcoin_core_asm, parse_flags
from .conftest import load_vector

pytestmark = pytest.mark.k

# Load vectors eagerly at module level (file is cached on disk after first download)
_RAW = load_vector("script_tests.json")

# Filter: keep only test entries with [sig, pubkey, flags, expected, ...]
# Skip: bare strings, single-element comment arrays, witness-format entries
SCRIPT_ENTRIES: list[tuple[int, list]] = [
    (i, v)
    for i, v in enumerate(_RAW)
    if isinstance(v, list) and len(v) >= 4 and not isinstance(v[0], list)
]


def _test_id(i: int, v: list) -> str:
    """Generate a human-readable test ID from entry comment or index."""
    if len(v) > 4 and isinstance(v[4], str):
        return v[4][:80]
    return f"vector_{i}"


@pytest.mark.parametrize(
    "entry",
    [v for _, v in SCRIPT_ENTRIES],
    ids=[_test_id(i, v) for i, v in SCRIPT_ENTRIES],
)
def test_script_vector(k, entry):
    sig_asm, pubkey_asm, flags_str, expected = entry[0], entry[1], entry[2], entry[3]

    reason = classify_vector(entry)
    if reason:
        pytest.xfail(reason)

    sig_bytes = parse_bitcoin_core_asm(sig_asm)
    pubkey_bytes = parse_bitcoin_core_asm(pubkey_asm)
    flags = parse_flags(flags_str)

    timestamp = 1333238400 if "P2SH" in flags else 0

    result = k.verify_script(
        script_sig=sig_bytes,
        script_pubkey=pubkey_bytes,
        timestamp=timestamp,
    )

    if expected == "OK":
        assert k.success(result), f"Expected OK but failed: {entry}"
    else:
        assert not k.success(result), f"Expected {expected} but got OK: {entry}"
