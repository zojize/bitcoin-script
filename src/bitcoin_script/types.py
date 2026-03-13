"""Shared type aliases used across the bitcoin_script package."""

from __future__ import annotations

# Stack element is always bytes (Bitcoin Script is untyped at runtime)
StackElement = bytes
