"""Bitcoin Core tx_valid.json and tx_invalid.json test vectors.

These require full transaction deserialization and sighash computation,
which is not yet implemented. All tests are skipped for now.
"""

from __future__ import annotations

import pytest

from .conftest import load_vector

pytestmark = [pytest.mark.k, pytest.mark.skip(reason="requires transaction deserialization")]

_TX_VALID_RAW = load_vector("tx_valid.json")
_TX_INVALID_RAW = load_vector("tx_invalid.json")

TX_VALID = [
    (i, v)
    for i, v in enumerate(_TX_VALID_RAW)
    if isinstance(v, list) and len(v) >= 3 and isinstance(v[0], list)
]

TX_INVALID = [
    (i, v)
    for i, v in enumerate(_TX_INVALID_RAW)
    if isinstance(v, list) and len(v) >= 3 and isinstance(v[0], list)
]


def _tx_id(i: int, v: list) -> str:
    if isinstance(v[-1], str) and not v[-1].startswith("["):
        return f"tx_{i}_{v[-1][:60]}"
    return f"tx_{i}"


@pytest.mark.parametrize(
    "entry",
    [v for _, v in TX_VALID],
    ids=[_tx_id(i, v) for i, v in TX_VALID],
)
def test_tx_valid(entry):
    pass


@pytest.mark.parametrize(
    "entry",
    [v for _, v in TX_INVALID],
    ids=[_tx_id(i, v) for i, v in TX_INVALID],
)
def test_tx_invalid(entry):
    pass
