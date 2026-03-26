from __future__ import annotations

import pytest

from bitcoin_script.k_semantics import KBitcoinScript, ScriptDist


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
