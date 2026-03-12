"""Command-line interface for the Bitcoin Script interpreter."""

from __future__ import annotations

import argparse


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser with subcommands.

    Subcommands:
        execute  - Execute a script from hex or ASM
        verify   - Verify a transaction input's scripts
        parse    - Parse and display a raw transaction or block
        validate - Validate blockchain from local block files
    """
    ...


def cmd_execute(args: argparse.Namespace) -> None:
    """Execute a Bitcoin script and display the result."""
    ...


def cmd_verify(args: argparse.Namespace) -> None:
    """Verify a transaction input against its referenced output."""
    ...


def cmd_parse(args: argparse.Namespace) -> None:
    """Parse and display a raw transaction or block."""
    ...


def cmd_validate(args: argparse.Namespace) -> None:
    """Validate the blockchain from local block files."""
    ...


def main() -> None:
    """CLI entry point."""
    ...
