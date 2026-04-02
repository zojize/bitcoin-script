"""Command-line interface for the Bitcoin Script interpreter."""

from __future__ import annotations

import logging
import sys
from enum import Enum
from pathlib import Path
from typing import Annotated, Optional

import typer

app = typer.Typer(
    name="bitcoin-script",
    help="Bitcoin Script interpreter and formal verification toolkit.",
)


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    """Bitcoin Script interpreter and formal verification toolkit."""
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit()


class Backend(str, Enum):
    k = "k"
    # python = "python"  # not yet implemented


def _default_bitcoin_dir() -> Path:
    """Auto-detect the Bitcoin Core data directory."""
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Bitcoin"
    return Path.home() / ".bitcoin"


@app.command()
def verify(
    start: Annotated[int, typer.Option("--start", "-s", help="Start block height.")] = 0,
    end: Annotated[Optional[int], typer.Option("--end", "-e", help="End block height (inclusive).")] = None,
    block: Annotated[Optional[int], typer.Option("--block", "-b", help="Verify a single block at this height.")] = None,
    blocks_dir: Annotated[Optional[str], typer.Option("--blocks-dir", help="Bitcoin Core data directory.")] = None,
    db: Annotated[str, typer.Option("--db", help="UTXO database path.")] = "utxo.db",
    workers: Annotated[int, typer.Option("--workers", "-w", help="Parallel K workers.")] = 1,
    backend: Annotated[Backend, typer.Option("--backend", help="Execution backend.")] = Backend.k,
) -> None:
    """Verify Bitcoin mainnet scripts via K Framework formal semantics.

    Reads blocks from Bitcoin Core's local .blk files, builds a UTXO set,
    and verifies every script execution (scriptSig + scriptPubKey + witness)
    for every transaction input.

    Examples:

        # Verify first 1000 blocks
        bitcoin-script verify --end 1000

        # Verify a single block
        bitcoin-script verify --block 170

        # Resume from checkpoint (UTXO state persisted in utxo.db)
        bitcoin-script verify --end 50000
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )

    if backend != Backend.k:
        typer.echo(f"Backend '{backend.value}' is not yet implemented.", err=True)
        raise typer.Exit(1)

    data_dir = Path(blocks_dir) if blocks_dir else _default_bitcoin_dir()
    if not (data_dir / "blocks" / "blk00000.dat").exists():
        typer.echo(f"Block files not found at {data_dir}/blocks/", err=True)
        typer.echo("Provide --blocks-dir or sync a Bitcoin Core node first.", err=True)
        raise typer.Exit(1)

    from bitcoin_script.blockchain.verifier import ChainVerifier

    verifier = ChainVerifier(data_dir, utxo_db_path=db, max_workers=workers)

    if block is not None:
        # Single-block mode
        if verifier.utxo.checkpoint_height < block - 1:
            typer.echo(f"Building UTXO set up to block {block - 1}...")
            pre = verifier.verify_chain(start=0, end=block - 1)
            if not pre.ok:
                typer.echo(f"Failed building UTXO state: {pre.errors[0]}", err=True)
                raise typer.Exit(1)

        typer.echo(f"Verifying block {block}...")
        result = verifier.verify_block(block)
        typer.echo(
            f"Block {block}: {result.tx_count} txs, "
            f"{result.input_count} inputs verified, "
            f"{result.elapsed_s:.3f}s"
        )
        if not result.ok:
            for e in result.errors:
                typer.echo(f"  ERROR: {e}", err=True)
            raise typer.Exit(1)
        typer.echo("OK")
    else:
        # Chain verification mode
        from tqdm import tqdm

        checkpoint = verifier.utxo.checkpoint_height
        effective_start = max(start, checkpoint + 1)
        total = (end - effective_start + 1) if end is not None else None
        label = f"Blocks {effective_start}-{end if end is not None else '...'}"

        inputs_verified = 0
        with tqdm(
            total=total,
            desc=label,
            unit="blk",
            dynamic_ncols=True,
        ) as pbar:

            def _on_block(br: object) -> None:
                nonlocal inputs_verified
                inputs_verified += br.input_count  # type: ignore[attr-defined]
                pbar.set_postfix(
                    h=br.height,  # type: ignore[attr-defined]
                    inputs=inputs_verified,
                    refresh=False,
                )
                pbar.update(1)

            result = verifier.verify_chain(
                start=start, end=end, on_block=_on_block
            )

        typer.echo(
            f"\n{'OK' if result.ok else 'FAILED'}: "
            f"{result.blocks_verified} blocks, "
            f"{result.inputs_verified} inputs, "
            f"{result.elapsed_s:.1f}s, "
            f"UTXO size: {verifier.utxo.size()}"
        )
        if not result.ok:
            for e in result.errors[:10]:
                typer.echo(f"  ERROR: {e}", err=True)
            raise typer.Exit(1)
