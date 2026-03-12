"""Shared type aliases used across the bitcoin_script package."""

from __future__ import annotations

from typing import NewType

# Raw byte sequences
ScriptBytes = NewType("ScriptBytes", bytes)
TxId = NewType("TxId", bytes)  # 32-byte transaction hash
BlockHash = NewType("BlockHash", bytes)  # 32-byte block hash
PubKeyBytes = NewType("PubKeyBytes", bytes)
SignatureBytes = NewType("SignatureBytes", bytes)

# Stack element is always bytes (Bitcoin Script is untyped at runtime)
StackElement = bytes
