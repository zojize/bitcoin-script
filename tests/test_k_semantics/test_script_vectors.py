"""Bitcoin Core script_tests.json test vectors."""

from __future__ import annotations

import pytest

from .bitcoin_core_vectors import classify_vector, parse_bitcoin_core_asm, parse_flags
from .conftest import (
    compute_sighash_blob,
    compute_witness_sighash_blob,
    encode_witness_blob,
    expand_taproot_witness,
    flags_to_bitmask,
    load_vector,
)

pytestmark = pytest.mark.k

# Load vectors eagerly at module level (file is cached on disk after first download)
_RAW = load_vector("script_tests.json")

# Standard entries: [sig, pubkey, flags, expected, ...]
# Witness entries: [[wit_items...], amount, sig, pubkey, flags, expected, ...]
SCRIPT_ENTRIES: list[tuple[int, list]] = [
    (i, v)
    for i, v in enumerate(_RAW)
    if isinstance(v, list) and len(v) >= 4 and not isinstance(v[0], list)
]

WITNESS_ENTRIES: list[tuple[int, list]] = [
    (i, v)
    for i, v in enumerate(_RAW)
    if isinstance(v, list) and len(v) >= 5 and isinstance(v[0], list)
]


def _test_id(i: int, v: list) -> str:
    """Generate a human-readable test ID from entry comment or index."""
    if len(v) > 4 and isinstance(v[4], str):
        return v[4][:80]
    return f"vector_{i}"


def _witness_test_id(i: int, v: list) -> str:
    """Generate a human-readable test ID for witness vectors."""
    if len(v) > 5 and isinstance(v[5], str):
        return v[5][:80]
    return f"witness_{i}"


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

    sighash = compute_sighash_blob(pubkey_bytes, sig_bytes)
    flags_mask = flags_to_bitmask(flags)

    result = k.verify_script(
        script_sig=sig_bytes,
        script_pubkey=pubkey_bytes,
        sighash=sighash,
        flags=flags_mask,
    )

    if expected == "OK":
        assert k.success(result), f"Expected OK but failed: {entry}"
    else:
        assert not k.success(result), f"Expected {expected} but got OK: {entry}"


@pytest.mark.parametrize(
    "entry",
    [v for _, v in WITNESS_ENTRIES],
    ids=[_witness_test_id(i, v) for i, v in WITNESS_ENTRIES],
)
def test_witness_vector(k, entry):
    """Test witness-format vectors: [[wit_hex..., amount_float], sig, pubkey, flags, expected, ...]"""
    witness_array = entry[0]
    # Last element of witness array is the spending amount (float, in BTC)
    amount_btc = witness_array[-1] if isinstance(witness_array[-1], float) else 0.0
    witness_hex_list = [x for x in witness_array if isinstance(x, str)]
    sig_asm = entry[1]
    pubkey_asm = entry[2]
    flags_str = entry[3]
    expected = entry[4]

    reason = classify_vector(entry)
    if reason:
        pytest.xfail(reason)

    flags = parse_flags(flags_str)

    # Taproot placeholder expansion (#SCRIPT#, #CONTROLBLOCK#, #TAPROOTOUTPUT#)
    has_taproot_placeholders = any("#SCRIPT#" in h for h in witness_hex_list)
    if has_taproot_placeholders:
        witness_items, pubkey_asm = expand_taproot_witness(witness_hex_list, pubkey_asm)
    else:
        witness_items = [bytes.fromhex(h) for h in witness_hex_list]
    witness_blob = encode_witness_blob(witness_items)

    sig_bytes = parse_bitcoin_core_asm(sig_asm)
    pubkey_bytes = parse_bitcoin_core_asm(pubkey_asm)
    flags_mask = flags_to_bitmask(flags)

    amount_satoshis = int(amount_btc * 1e8 + 0.5)

    # Taproot vectors don't need legacy sighash (no ECDSA signatures)
    if "TAPROOT" in flags:
        sighash = b""
    else:
        sighash = compute_witness_sighash_blob(
            pubkey_bytes,
            sig_bytes,
            witness_items,
            amount_satoshis,
        )

    result = k.verify_script(
        script_sig=sig_bytes,
        script_pubkey=pubkey_bytes,
        sighash=sighash,
        witness=witness_blob,
        flags=flags_mask,
    )

    if expected == "OK":
        assert k.success(result), f"Expected OK but failed: {entry}"
    else:
        assert not k.success(result), f"Expected {expected} but got OK: {entry}"
