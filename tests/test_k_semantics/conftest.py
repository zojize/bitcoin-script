from __future__ import annotations

import json
import urllib.request
from pathlib import Path

import pytest

from bitcoin_script.k_semantics import KBitcoinScript, ScriptDist

DATA_DIR = Path(__file__).parent / "data"
_VECTOR_BASE = "https://raw.githubusercontent.com/bitcoin/bitcoin/master/src/test/data"
VECTOR_URLS = {
    "script_tests.json": f"{_VECTOR_BASE}/script_tests.json",
    "tx_valid.json": f"{_VECTOR_BASE}/tx_valid.json",
    "tx_invalid.json": f"{_VECTOR_BASE}/tx_invalid.json",
}


def load_vector(name: str) -> list:
    """Download a Bitcoin Core test vector file (cached locally)."""
    DATA_DIR.mkdir(exist_ok=True)
    path = DATA_DIR / name
    if not path.exists():
        urllib.request.urlretrieve(VECTOR_URLS[name], path)
    return json.loads(path.read_text())


@pytest.fixture(scope="session")
def _dist() -> ScriptDist:
    return ScriptDist.load()


@pytest.fixture(scope="session")
def k(_dist: ScriptDist) -> KBitcoinScript:
    """Shared KBitcoinScript instance (auto-detects hex vs ASM from input)."""
    return KBitcoinScript(_dist)


@pytest.fixture(scope="session")
def k_hex(_dist: ScriptDist) -> KBitcoinScript:
    """Alias for k — kept for test readability."""
    return KBitcoinScript(_dist)
