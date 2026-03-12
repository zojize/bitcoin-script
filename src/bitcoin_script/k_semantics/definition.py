"""Load and interact with K Framework definitions for Bitcoin Script.

This module will handle loading the K definition files (.k),
compiling them with kompile, and executing programs against
the formal semantics.

Requires the kframework (pyk) package to be installed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


class KDefinition:
    """Manage a compiled K definition for Bitcoin Script."""

    _definition_dir: Path

    def __init__(self, definition_dir: Path) -> None:
        """Initialize with the path to compiled K definition.

        Args:
            definition_dir: Path to the kompiled definition directory.
        """
        ...

    @classmethod
    def compile(cls, source_dir: Path, output_dir: Path) -> KDefinition:
        """Compile K source files into a definition.

        Args:
            source_dir: Directory containing .k source files.
            output_dir: Directory for the compiled output.

        Returns:
            A KDefinition pointing to the compiled output.
        """
        ...

    def run(self, program: Any) -> Any:
        """Execute a program against the K definition.

        Args:
            program: A K term representing the program to execute.

        Returns:
            The final K configuration after execution.
        """
        ...
