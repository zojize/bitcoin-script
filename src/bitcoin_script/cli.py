"""Command-line interface for the Bitcoin Script interpreter."""

from __future__ import annotations

import logging
import sys
from enum import Enum
from pathlib import Path
from typing import Annotated, Optional

import typer
from bitcoin.core.script import CScript, OPCODES_BY_NAME

from bitcoin_script.engine.engine import ScriptEngine
from bitcoin_script.engine.errors import ScriptError
from bitcoin_script.engine.flags import ScriptVerifyFlag
from bitcoin_script.engine.stack import ScriptStack
from bitcoin_script.script_types.classifier import classify

app = typer.Typer(
    name="bitcoin-script",
    help="Bitcoin Script interpreter and formal verification toolkit.",
)


class Backend(str, Enum):
    k = "k"
    python = "python"


# ---------------------------------------------------------------------------
# Helpers (Python engine)
# ---------------------------------------------------------------------------


def _parse_script(raw: str, as_hex: bool) -> CScript:
    """Parse a script from hex bytes or ASM notation."""
    if as_hex or _looks_like_hex(raw):
        try:
            return CScript(bytes.fromhex(raw.strip()))
        except ValueError as exc:
            typer.echo(f"Error: invalid hex script: {exc}", err=True)
            raise typer.Exit(1) from exc
    return _parse_asm(raw)


def _looks_like_hex(s: str) -> bool:
    s = s.strip()
    return bool(s) and all(c in "0123456789abcdefABCDEF" for c in s) and len(s) % 2 == 0


def _parse_asm(asm: str) -> CScript:
    """Parse a space-separated Bitcoin Script ASM string into a CScript."""
    tokens = asm.strip().split()
    items: list[bytes | int] = []

    for token in tokens:
        upper = token.upper()

        # Named opcode
        if upper in OPCODES_BY_NAME:
            items.append(OPCODES_BY_NAME[upper])
            continue

        # Also accept without OP_ prefix for convenience
        if "OP_" + upper in OPCODES_BY_NAME:
            items.append(OPCODES_BY_NAME["OP_" + upper])
            continue

        # Hex data push (even-length hex string)
        if all(c in "0123456789abcdefABCDEF" for c in token) and len(token) % 2 == 0:
            items.append(bytes.fromhex(token))
            continue

        # Integer literal
        try:
            items.append(int(token))
            continue
        except ValueError:
            pass

        typer.echo(f"Error: unknown ASM token '{token}'", err=True)
        raise typer.Exit(1)

    return CScript(items)  # type: ignore[arg-type]


def _display_stack(stack: ScriptStack) -> None:
    """Pretty-print the stack (top first)."""
    if stack.is_empty():
        typer.echo("  (empty)")
        return
    # Access internal list; top of stack is the last element
    for i, elem in enumerate(reversed(stack._main)):
        label = " <- top" if i == 0 else ""
        typer.echo(f"  [{i}] {elem.hex() or '(empty)'}{label}")


# ---------------------------------------------------------------------------
# Helpers (K / mainnet verification)
# ---------------------------------------------------------------------------


def _format_stack_item(item: bytes) -> str:
    """Format a stack item for display."""
    if len(item) == 0:
        return "(empty)"
    # Try to show as integer if it's a valid CScriptNum
    if len(item) <= 4:
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


# ---------------------------------------------------------------------------
# Commands: Python engine
# ---------------------------------------------------------------------------


@app.command()
def execute(
    script: Annotated[str, typer.Argument(help="Script in hex or ASM format.")],
    hex: Annotated[bool, typer.Option("--hex", help="Treat input as raw hex.")] = False,
    script_sig: Annotated[
        Optional[str],
        typer.Option(
            "--sig", "-s", help="Optional scriptSig (hex or ASM) to run first."
        ),
    ] = None,
) -> None:
    """Execute a Bitcoin script and display the result."""
    engine = ScriptEngine(flags=ScriptVerifyFlag.P2SH)

    # Optionally run a scriptSig first (so the stack is pre-populated)
    if script_sig is not None:
        sig_script = _parse_script(script_sig, hex)
        try:
            engine._run_script(sig_script)
        except ScriptError as exc:
            typer.echo(f"scriptSig failed: {exc}", err=True)
            raise typer.Exit(1) from exc

    parsed = _parse_script(script, hex)

    try:
        result = engine.execute(parsed)
    except ScriptError as exc:
        typer.echo(f"Script error: {exc}", err=True)
        typer.echo("Result: FAIL")
        raise typer.Exit(1) from exc

    typer.echo(f"Result: {'PASS' if result else 'FAIL'}")
    typer.echo("Final stack (top first):")
    _display_stack(engine._stack)


@app.command()
def verify(
    script_sig: Annotated[
        str,
        typer.Argument(help="scriptSig in hex or ASM (empty string '' for SegWit)."),
    ],
    script_pubkey: Annotated[str, typer.Argument(help="scriptPubKey in hex or ASM.")],
    hex: Annotated[
        bool, typer.Option("--hex", help="Treat script inputs as raw hex.")
    ] = False,
    p2sh: Annotated[
        bool, typer.Option("--p2sh/--no-p2sh", help="Enable P2SH evaluation.")
    ] = True,
    segwit: Annotated[
        bool,
        typer.Option(
            "--segwit/--no-segwit",
            help="Enable SegWit (P2WPKH/P2WSH) evaluation.",
        ),
    ] = True,
    witness: Annotated[
        Optional[list[str]],
        typer.Option(
            "--witness",
            "-w",
            help="Witness stack items as hex (repeat for each item).",
        ),
    ] = None,
    value: Annotated[
        int,
        typer.Option(
            "--value",
            "-v",
            help="Input value in satoshis (required for SegWit sighash).",
        ),
    ] = 0,
) -> None:
    """Verify a scriptSig against a scriptPubKey (with optional witness for SegWit)."""
    sig = _parse_script(script_sig, hex)
    pubkey = _parse_script(script_pubkey, hex)

    flags = ScriptVerifyFlag.NONE
    if p2sh:
        flags |= ScriptVerifyFlag.P2SH
    if segwit:
        flags |= ScriptVerifyFlag.WITNESS

    witness_stack: list[bytes] | None = None
    if witness:
        try:
            witness_stack = [bytes.fromhex(w) for w in witness]
        except ValueError as exc:
            typer.echo(f"Error: invalid witness hex: {exc}", err=True)
            raise typer.Exit(1) from exc

    engine = ScriptEngine(flags=flags)

    try:
        result = engine.verify(sig, pubkey, input_value=value, witness=witness_stack)
    except ScriptError as exc:
        typer.echo(f"Script error: {exc}", err=True)
        typer.echo("Result: FAIL")
        raise typer.Exit(1) from exc

    typer.echo(f"Result: {'PASS' if result else 'FAIL'}")
    if not result:
        raise typer.Exit(1)


@app.command()
def parse(
    raw: Annotated[str, typer.Argument(help="Raw transaction or block hex.")],
    block: Annotated[
        bool,
        typer.Option(
            "--block", "-b", help="Parse as a block instead of a transaction."
        ),
    ] = False,
) -> None:
    """Parse and display a raw transaction or block."""
    try:
        data = bytes.fromhex(raw.strip())
    except ValueError as exc:
        typer.echo(f"Error: not valid hex: {exc}", err=True)
        raise typer.Exit(1) from exc

    if block:
        _parse_block(data)
    else:
        _parse_transaction(data)


@app.command()
def classify_script(
    script: Annotated[str, typer.Argument(help="Script in hex or ASM format.")],
    hex: Annotated[bool, typer.Option("--hex", help="Treat input as raw hex.")] = False,
) -> None:
    """Classify a scriptPubKey into its standard template type."""
    parsed = _parse_script(script, hex)
    script_type = classify(parsed)
    typer.echo(f"Type: {script_type.name}")


def _parse_transaction(data: bytes) -> None:
    from bitcoin.core import CTransaction, b2lx

    try:
        tx = CTransaction.deserialize(data)
    except Exception as exc:
        typer.echo(f"Error deserializing transaction: {exc}", err=True)
        raise typer.Exit(1) from exc

    typer.echo(f"txid   : {b2lx(tx.GetTxid())}")
    typer.echo(f"version: {tx.nVersion}")
    typer.echo(f"locktime: {tx.nLockTime}")
    typer.echo(f"inputs ({len(tx.vin)}):")
    for i, inp in enumerate(tx.vin):
        typer.echo(f"  [{i}] prevout={b2lx(inp.prevout.hash)}:{inp.prevout.n}")
        typer.echo(f"       scriptSig={inp.scriptSig.hex()}")
        typer.echo(f"       sequence=0x{inp.nSequence:08x}")
    typer.echo(f"outputs ({len(tx.vout)}):")
    for i, out in enumerate(tx.vout):
        typer.echo(
            f"  [{i}] value={out.nValue} sat  scriptPubKey={out.scriptPubKey.hex()}"
        )


def _parse_block(data: bytes) -> None:
    from bitcoin.core import CBlock, b2lx

    try:
        block = CBlock.deserialize(data)
    except Exception as exc:
        typer.echo(f"Error deserializing block: {exc}", err=True)
        raise typer.Exit(1) from exc

    typer.echo(f"hash    : {b2lx(block.GetHash())}")
    typer.echo(f"version : {block.nVersion}")
    typer.echo(f"prev    : {b2lx(block.hashPrevBlock)}")
    typer.echo(f"merkle  : {b2lx(block.hashMerkleRoot)}")
    typer.echo(f"time    : {block.nTime}")
    typer.echo(f"bits    : 0x{block.nBits:08x}")
    typer.echo(f"nonce   : {block.nNonce}")
    typer.echo(f"tx count: {len(block.vtx)}")


@app.command()
def validate(
    path: Annotated[
        Optional[str],
        typer.Argument(help="Path to local block files directory."),
    ] = None,
) -> None:
    """Validate the blockchain from local block files."""
    from bitcoin_script.blockchain.parser import BlockFileParser
    from bitcoin_script.blockchain.utxo import UTXOSet
    from bitcoin_script.blockchain.validation import (
        validate_block,
        validate_transaction,
    )

    data_dir = Path(path) if path else Path.home() / ".bitcoin"
    if not data_dir.exists():
        typer.echo(f"Error: block data directory not found: {data_dir}", err=True)
        typer.echo(
            "Provide a path with: bitcoin-script validate /path/to/bitcoin/blocks",
            err=True,
        )
        raise typer.Exit(1)

    typer.echo(f"Validating from: {data_dir}")
    utxo_set = UTXOSet()
    prev_hash = b"\x00" * 32  # genesis prev block hash

    try:
        parser = BlockFileParser(data_dir)
        for height, block in enumerate(parser):
            try:
                validate_block(block, prev_hash, height)
            except Exception as exc:
                typer.echo(f"Block {height} validation failed: {exc}", err=True)
                raise typer.Exit(1) from exc

            for i, tx in enumerate(block.vtx):
                is_coinbase = i == 0
                try:
                    validate_transaction(tx, utxo_set, height, is_coinbase)
                except Exception as exc:
                    from bitcoin.core import b2lx

                    txid = b2lx(tx.GetTxid()).decode()
                    typer.echo(
                        f"Block {height} tx {txid} validation failed: {exc}",
                        err=True,
                    )
                    raise typer.Exit(1) from exc

            prev_hash = block.GetHash()

            if height % 1000 == 0:
                typer.echo(f"  validated block {height}  (UTXO set: {utxo_set.size()})")

    except typer.Exit:
        raise
    except KeyboardInterrupt:
        typer.echo("\nInterrupted.")
    except Exception as exc:
        typer.echo(f"Unexpected error: {exc}", err=True)
        raise typer.Exit(1) from exc

    typer.echo("Validation complete.")


# ---------------------------------------------------------------------------
# Commands: K Framework (mainnet verification + REPL)
# ---------------------------------------------------------------------------


@app.command(name="verify-chain")
def verify_chain(
    start: Annotated[
        int, typer.Option("--start", "-s", help="Start block height.")
    ] = 0,
    end: Annotated[
        Optional[int],
        typer.Option("--end", "-e", help="End block height (inclusive)."),
    ] = None,
    block: Annotated[
        Optional[int],
        typer.Option("--block", "-b", help="Verify a single block at this height."),
    ] = None,
    blocks_dir: Annotated[
        Optional[str],
        typer.Option("--blocks-dir", help="Bitcoin Core data directory."),
    ] = None,
    db: Annotated[str, typer.Option("--db", help="UTXO database path.")] = "utxo.db",
    workers: Annotated[
        int, typer.Option("--workers", "-w", help="Parallel K workers.")
    ] = 1,
) -> None:
    """Verify Bitcoin mainnet scripts via K Framework formal semantics.

    Reads blocks from Bitcoin Core's local .blk files, builds a UTXO set,
    and verifies every script execution (scriptSig + scriptPubKey + witness)
    for every transaction input.

    Examples:

        # Verify first 1000 blocks
        bitcoin-script verify-chain --end 1000

        # Verify a single block
        bitcoin-script verify-chain --block 170

        # Resume from checkpoint (UTXO state persisted in utxo.db)
        bitcoin-script verify-chain --end 50000
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )

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

    from bitcoin_script.asm import parse_asm
    from bitcoin_script.k_semantics import KBitcoinScript

    console = Console()
    session: PromptSession[str] = PromptSession(history=InMemoryHistory())

    if backend != Backend.k:
        typer.echo(f"Backend '{backend.value}' is not yet implemented.", err=True)
        raise typer.Exit(1)

    console.print("[bold]Bitcoin Script REPL[/bold]")
    console.print(
        "Type opcodes to build a script. Use .run to execute, .help for commands.\n"
    )

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


# ---------------------------------------------------------------------------
# Benchmark commands
# ---------------------------------------------------------------------------

benchmark_app = typer.Typer(
    name="benchmark",
    help="Benchmark script verification: K Framework vs Bitcoin Core.",
)
app.add_typer(benchmark_app)


@benchmark_app.command(name="extract")
def benchmark_extract(
    blocks_dir: Annotated[
        Optional[str],
        typer.Option("--blocks-dir", help="Bitcoin Core data directory."),
    ] = None,
    output: Annotated[
        str, typer.Option("--output", "-o", help="Output dataset file.")
    ] = "benchmark-dataset.msgpack",
    continuous_end: Annotated[
        int, typer.Option("--continuous-end", help="Last block for continuous range.")
    ] = 9999,
    representative: Annotated[
        int, typer.Option("--representative", help="Blocks per era to sample.")
    ] = 10,
    stress_count: Annotated[
        int, typer.Option("--stress-count", help="Number of stress blocks.")
    ] = 20,
    utxo_db: Annotated[
        Optional[str],
        typer.Option(
            "--utxo-db", help="SQLite file for UTXO set (enables resume on crash)."
        ),
    ] = None,
    skip_taproot: Annotated[
        bool,
        typer.Option("--skip-taproot", help="Skip Taproot-era representative blocks."),
    ] = False,
    source: Annotated[
        str,
        typer.Option(
            "--source",
            help="Data source: 'local' (Bitcoin Core .blk files) or 'api' (Blockstream esplora).",
        ),
    ] = "local",
) -> None:
    """Extract benchmark inputs from mainnet blocks into a dataset file.

    With --source api, fetches blocks from Blockstream's esplora REST API
    (no Bitcoin Core node required). Only target blocks are fetched — the
    continuous range is skipped unless --continuous-end is set explicitly.
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )
    from tqdm import tqdm

    out_path = Path(output)

    if source == "api":
        from bitcoin_script.benchmark.api_extractor import extract_dataset_api

        # Skip continuous range for API mode (10K blocks is impractical).
        api_continuous = -1 if continuous_end == 9999 else continuous_end

        with tqdm(desc="Fetching blocks", unit="blk", dynamic_ncols=True) as pbar:

            def _on_block_api(height: int, count: int) -> None:
                pbar.set_postfix(h=height, inputs=count, refresh=False)
                pbar.update(1)

            ds = extract_dataset_api(
                output=out_path,
                continuous_end=api_continuous,
                blocks_per_era=representative,
                stress_count=stress_count,
                skip_taproot=skip_taproot,
                on_block=_on_block_api,
            )
    else:
        from bitcoin_script.benchmark.extractor import extract_dataset

        data_dir = Path(blocks_dir) if blocks_dir else _default_bitcoin_dir()
        if not (data_dir / "blocks" / "blk00000.dat").exists():
            typer.echo(f"Block files not found at {data_dir}/blocks/", err=True)
            raise typer.Exit(1)

        with tqdm(desc="Extracting", unit="blk", dynamic_ncols=True) as pbar:

            def _on_block(height: int, count: int) -> None:
                pbar.set_postfix(h=height, inputs=count, refresh=False)
                pbar.update(1)

            ds = extract_dataset(
                data_dir,
                output=out_path,
                continuous_end=continuous_end,
                blocks_per_era=representative,
                stress_count=stress_count,
                on_block=_on_block,
                utxo_db=utxo_db,
                skip_taproot=skip_taproot,
            )

    typer.echo(
        f"Extracted {len(ds.inputs):,} inputs from {ds.header['block_count']} blocks -> {out_path}"
    )


@benchmark_app.command(name="run")
def benchmark_run(
    dataset: Annotated[
        str, typer.Option("--dataset", "-d", help="Input dataset file.")
    ] = "benchmark-dataset.msgpack",
    output: Annotated[
        str, typer.Option("--output", "-o", help="Output results file.")
    ] = "benchmark-results.json",
    k_only: Annotated[
        bool, typer.Option("--k-only", help="Only run K Framework.")
    ] = False,
    core_only: Annotated[
        bool, typer.Option("--core-only", help="Only run libbitcoinconsensus.")
    ] = False,
    k_iterations: Annotated[
        int, typer.Option("--k-iterations", help="Iterations for K timing.")
    ] = 1,
    core_iterations: Annotated[
        int, typer.Option("--core-iterations", help="Iterations for Core timing.")
    ] = 100,
) -> None:
    """Run benchmark on a dataset, timing both K Framework and libbitcoinconsensus."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )
    from tqdm import tqdm

    from bitcoin_script.benchmark.dataset import load_dataset
    from bitcoin_script.benchmark.runner import run_benchmark, save_results

    ds = load_dataset(Path(dataset))
    typer.echo(f"Loaded dataset: {len(ds.inputs):,} inputs")

    run_k = not core_only
    run_core = not k_only

    with tqdm(total=len(ds.inputs), desc="Benchmarking", unit="inp") as pbar:

        def _on_input(_i: int, _total: int) -> None:
            pbar.update(1)

        results = run_benchmark(
            ds,
            run_k=run_k,
            run_core=run_core,
            k_iterations=k_iterations,
            core_iterations=core_iterations,
            on_input=_on_input,
        )

    out_path = Path(output)
    save_results(results, out_path)
    typer.echo(f"Results saved: {len(results.input_results):,} inputs -> {out_path}")


@benchmark_app.command(name="report")
def benchmark_report(
    results: Annotated[
        str, typer.Option("--results", "-r", help="Input results file.")
    ] = "benchmark-results.json",
    fmt: Annotated[
        str, typer.Option("--format", "-f", help="Output format: table, json, csv.")
    ] = "table",
) -> None:
    """Generate a benchmark report from results."""
    from bitcoin_script.benchmark.report import format_csv, format_json, format_table
    from bitcoin_script.benchmark.runner import load_results

    res = load_results(Path(results))

    if fmt == "json":
        typer.echo(format_json(res))
    elif fmt == "csv":
        typer.echo(format_csv(res))
    else:
        typer.echo(format_table(res))
