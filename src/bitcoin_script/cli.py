"""Command-line interface for the Bitcoin Script interpreter."""

from __future__ import annotations

from typing import Annotated, Optional

import typer

app = typer.Typer(
    name="bitcoin-script",
    help="Bitcoin Script interpreter with K Framework integration.",
)


@app.command()
def execute(
    script: Annotated[str, typer.Argument(help="Script in hex or ASM format.")],
    hex: Annotated[
        bool, typer.Option("--hex", help="Treat input as raw hex.")
    ] = False,
) -> None:
    """Execute a Bitcoin script and display the result."""
    ...


@app.command()
def verify(
    txid: Annotated[str, typer.Argument(help="Transaction ID to verify.")],
    input_index: Annotated[
        int, typer.Option("--input", "-i", help="Input index to verify.")
    ] = 0,
) -> None:
    """Verify a transaction input against its referenced output."""
    ...


@app.command()
def parse(
    raw: Annotated[str, typer.Argument(help="Raw transaction or block hex.")],
    block: Annotated[
        bool, typer.Option("--block", "-b", help="Parse as a block instead of a transaction.")
    ] = False,
) -> None:
    """Parse and display a raw transaction or block."""
    ...


@app.command()
def validate(
    path: Annotated[
        Optional[str],
        typer.Argument(help="Path to local block files directory."),
    ] = None,
) -> None:
    """Validate the blockchain from local block files."""
    ...
