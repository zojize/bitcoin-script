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


def _format_stack_item(item: bytes) -> str:
    """Format a stack item for display."""
    if len(item) == 0:
        return "(empty)"
    # Try to show as integer if it's a valid CScriptNum
    if len(item) <= 4:
        # Little-endian sign-magnitude
        val = int.from_bytes(item[:-1] if len(item) > 1 else b"\x00", "little")
        val |= (item[-1] & 0x7F) << (8 * (len(item) - 1))
        if item[-1] & 0x80:
            val = -val
        return f"0x{item.hex()} ({val})"
    return f"0x{item.hex()}"


def _default_bitcoin_dir() -> Path:
    """Auto-detect the Bitcoin Core data directory."""
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Bitcoin"
    return Path.home() / ".bitcoin"


@app.command()
def verify(
    start: Annotated[
        int, typer.Option("--start", "-s", help="Start block height.")
    ] = 0,
    end: Annotated[
        Optional[int], typer.Option("--end", "-e", help="End block height (inclusive).")
    ] = None,
    block: Annotated[
        Optional[int],
        typer.Option("--block", "-b", help="Verify a single block at this height."),
    ] = None,
    blocks_dir: Annotated[
        Optional[str], typer.Option("--blocks-dir", help="Bitcoin Core data directory.")
    ] = None,
    db: Annotated[str, typer.Option("--db", help="UTXO database path.")] = "utxo.db",
    workers: Annotated[
        int, typer.Option("--workers", "-w", help="Parallel K workers.")
    ] = 1,
    backend: Annotated[
        Backend, typer.Option("--backend", help="Execution backend.")
    ] = Backend.k,
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

            result = verifier.verify_chain(start=start, end=end, on_block=_on_block)

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


@app.command()
def repl(
    backend: Annotated[
        Backend, typer.Option("--backend", help="Execution backend.")
    ] = Backend.k,
) -> None:
    """Interactive Bitcoin Script REPL.

    Type opcodes and data to build a script, then execute it through the
    K Framework formal semantics. Supports both OP_-prefixed and bare
    opcode names, hex data, quoted strings, and bare integers.

    Commands:

        .run          Execute the current script
        .stack        Show the stack from the last execution
        .reset        Clear the script buffer
        .script       Show the current script (hex)
        .asm          Show the current script (ASM tokens)
        .flags N      Set verification flags bitmask
        .help         Show this help
        .quit         Exit the REPL

    Examples:

        btc> OP_1 OP_2 OP_ADD
        btc> .run
        Stack (1 item):
          0: 0x03 (3)
    """
    from prompt_toolkit import PromptSession
    from prompt_toolkit.history import InMemoryHistory
    from rich.console import Console

    from bitcoin_script.k_semantics import KBitcoinScript

    console = Console()
    session: PromptSession[str] = PromptSession(history=InMemoryHistory())

    console.print("[bold]Bitcoin Script REPL[/bold]")
    console.print(
        "Type opcodes to build a script. Use .run to execute, .help for commands.\n"
    )

    from bitcoin_script.asm import parse_asm

    if backend != Backend.k:
        typer.echo(f"Backend '{backend.value}' is not yet implemented.", err=True)
        raise typer.Exit(1)

    console.print("Loading K Framework semantics...", style="dim")
    try:
        k = KBitcoinScript()
    except Exception as e:
        console.print(f"[red]Failed to load K semantics: {e}[/red]")
        console.print(
            "Run: uv run kdist build bitcoin-script-semantics.llvm", style="dim"
        )
        raise typer.Exit(1) from e
    console.print("[green]Ready.[/green]\n")

    asm_tokens: list[str] = []
    flags: int = 0
    last_result = None

    def _show_stack() -> None:
        nonlocal last_result
        if last_result is None:
            console.print("[dim]No execution yet. Use .run first.[/dim]")
            return
        err = k.error(last_result)
        if err:
            console.print(f"[red]Error: {err}[/red]")
        elif k.is_stuck(last_result):
            console.print("[red]Execution stuck (pattern match failure)[/red]")
        stack = k.stack(last_result)
        if not stack:
            console.print("[dim]Stack is empty.[/dim]")
        else:
            console.print(
                f"[bold]Stack ({len(stack)} item{'s' if len(stack) != 1 else ''}):[/bold]"
            )
            for i, item in enumerate(stack):
                console.print(f"  {i}: {_format_stack_item(item)}")
        ok = k.success(last_result)
        console.print(
            f"Result: [{'green' if ok else 'red'}]{'PASS' if ok else 'FAIL'}[/]"
        )

    def _show_help() -> None:
        console.print("[bold]Commands:[/bold]")
        console.print("  .run          Execute script through K semantics")
        console.print("  .stack        Show stack from last execution")
        console.print("  .reset        Clear the script buffer")
        console.print("  .script       Show current script (hex)")
        console.print("  .asm          Show current script (ASM tokens)")
        console.print("  .flags [N]    Show or set verification flags")
        console.print("  .help         Show this help")
        console.print("  .quit         Exit")
        console.print()
        console.print("[bold]Input:[/bold]")
        console.print("  OP_DUP, DUP       Opcodes (OP_ prefix optional)")
        console.print("  0x1234             Hex data push")
        console.print("  'hello'            String data push")
        console.print("  42, -1             Integer push")
        console.print("  OP_1 OP_2 OP_ADD   Multiple tokens per line")

    while True:
        try:
            line = session.prompt("btc> ").strip()
        except EOFError, KeyboardInterrupt:
            console.print()
            break

        if not line:
            continue

        # Dot commands
        if line.startswith("."):
            cmd = line.split()[0].lower()
            args = line.split()[1:]

            if cmd in (".quit", ".exit", ".q"):
                break
            elif cmd == ".help":
                _show_help()
            elif cmd == ".reset":
                asm_tokens.clear()
                last_result = None
                console.print("[dim]Script cleared.[/dim]")
            elif cmd == ".script":
                if not asm_tokens:
                    console.print("[dim]Script is empty.[/dim]")
                else:
                    raw = parse_asm(" ".join(asm_tokens))
                    console.print(f"[bold]Hex:[/bold] {raw.hex()}")
                    console.print(f"[bold]Len:[/bold] {len(raw)} bytes")
            elif cmd == ".asm":
                if not asm_tokens:
                    console.print("[dim]Script is empty.[/dim]")
                else:
                    console.print(" ".join(asm_tokens))
            elif cmd == ".flags":
                if args:
                    try:
                        flags = int(args[0], 0)
                        console.print(f"Flags set to {flags} (0x{flags:x})")
                    except ValueError:
                        console.print("[red]Invalid flags value[/red]")
                else:
                    console.print(f"Flags: {flags} (0x{flags:x})")
            elif cmd == ".stack":
                _show_stack()
            elif cmd == ".run":
                if not asm_tokens:
                    console.print(
                        "[dim]Script is empty. Type some opcodes first.[/dim]"
                    )
                    continue
                asm_str = " ".join(asm_tokens)
                try:
                    raw = parse_asm(asm_str)
                except Exception as e:
                    console.print(f"[red]Parse error: {e}[/red]")
                    continue
                console.print(f"[dim]Executing {len(raw)} bytes...[/dim]")
                try:
                    last_result = k.verify_script(
                        script_pubkey=raw,
                        flags=flags,
                    )
                except Exception as e:
                    console.print(f"[red]K execution error: {e}[/red]")
                    continue
                _show_stack()
            else:
                console.print(f"[red]Unknown command: {cmd}[/red] (try .help)")
            continue

        # Script input: accumulate tokens
        asm_tokens.extend(line.split())
        # Show a preview of the accumulated script
        try:
            raw = parse_asm(" ".join(asm_tokens))
            console.print(f"[dim]  script: {raw.hex()} ({len(raw)} bytes)[/dim]")
        except Exception as e:
            console.print(f"[yellow]  warning: {e}[/yellow]")
