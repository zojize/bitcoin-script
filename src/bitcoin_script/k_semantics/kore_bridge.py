"""Bridge between Python script engine state and K Framework configurations.

This module will provide conversion utilities between the Python
interpreter's internal representations and K's term format (KORE),
enabling formal verification of Bitcoin Script semantics.

Requires the kframework (pyk) package to be installed.
"""

from __future__ import annotations

from typing import Any

from bitcoin_script.engine.stack import ScriptStack
from bitcoin_script.model.script import Script


class KoreBridge:
    """Convert between Python Bitcoin Script objects and K terms."""

    def stack_to_kore(self, stack: ScriptStack) -> Any:
        """Convert a ScriptStack to a K term representation.

        Args:
            stack: The script execution stack.

        Returns:
            A K term representing the stack state.
        """
        ...

    def script_to_kore(self, script: Script) -> Any:
        """Convert a Script to a K term representation.

        Args:
            script: The Bitcoin script.

        Returns:
            A K term representing the script.
        """
        ...

    def kore_result_to_bool(self, kore_term: Any) -> bool:
        """Interpret a K execution result as pass/fail.

        Args:
            kore_term: The K term result from execution.

        Returns:
            True if the K execution indicates script success.
        """
        ...
