"""Command-line interface for the Bitcoin Script interpreter."""

from __future__ import annotations

import sys
from typing import Annotated, Optional

import typer
from bitcoin.core.script import CScript, OPCODES_BY_NAME

from bitcoin_script.engine.engine import ScriptEngine
from bitcoin_script.engine.errors import ScriptError
from bitcoin_script.engine.flags import ScriptVerifyFlag
from bitcoin_script.engine.stack import ScriptStack

app = typer.Typer(
    name="bitcoin-script",
    help="Bitcoin Script interpreter with K Framework integration.",
)


# ---------------------------------------------------------------------------
# Helpers
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

    return CScript(items)


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
# Commands
# ---------------------------------------------------------------------------

@app.command()
def execute(
    script: Annotated[str, typer.Argument(help="Script in hex or ASM format.")],
    hex: Annotated[bool, typer.Option("--hex", help="Treat input as raw hex.")] = False,
    script_sig: Annotated[
        Optional[str],
        typer.Option("--sig", "-s", help="Optional scriptSig (hex or ASM) to run first."),
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
    script_sig: Annotated[str, typer.Argument(help="scriptSig in hex or ASM (empty string '' for SegWit).")],
    script_pubkey: Annotated[str, typer.Argument(help="scriptPubKey in hex or ASM.")],
    hex: Annotated[bool, typer.Option("--hex", help="Treat script inputs as raw hex.")] = False,
    p2sh: Annotated[bool, typer.Option("--p2sh/--no-p2sh", help="Enable P2SH evaluation.")] = True,
    segwit: Annotated[bool, typer.Option("--segwit/--no-segwit", help="Enable SegWit (P2WPKH/P2WSH) evaluation.")] = True,
    witness: Annotated[
        Optional[list[str]],
        typer.Option("--witness", "-w", help="Witness stack items as hex (repeat for each item)."),
    ] = None,
    value: Annotated[
        int,
        typer.Option("--value", "-v", help="Input value in satoshis (required for SegWit sighash)."),
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

    typer.echo(f"Result: {'PASS ✓' if result else 'FAIL ✗'}")
    if not result:
        raise typer.Exit(1)


@app.command()
def parse(
    raw: Annotated[str, typer.Argument(help="Raw transaction or block hex.")],
    block: Annotated[
        bool,
        typer.Option("--block", "-b", help="Parse as a block instead of a transaction."),
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


def _parse_transaction(data: bytes) -> None:
    from bitcoin.core import CTransaction

    try:
        tx = CTransaction.deserialize(data)
    except Exception as exc:
        typer.echo(f"Error deserializing transaction: {exc}", err=True)
        raise typer.Exit(1) from exc

    from bitcoin.core import b2lx

    typer.echo(f"txid   : {b2lx(tx.GetTxid()).decode()}")
    typer.echo(f"version: {tx.nVersion}")
    typer.echo(f"locktime: {tx.nLockTime}")
    typer.echo(f"inputs ({len(tx.vin)}):")
    for i, inp in enumerate(tx.vin):
        typer.echo(f"  [{i}] prevout={b2lx(inp.prevout.hash).decode()}:{inp.prevout.n}")
        typer.echo(f"       scriptSig={inp.scriptSig.hex()}")
        typer.echo(f"       sequence=0x{inp.nSequence:08x}")
    typer.echo(f"outputs ({len(tx.vout)}):")
    for i, out in enumerate(tx.vout):
        typer.echo(f"  [{i}] value={out.nValue} sat  scriptPubKey={out.scriptPubKey.hex()}")


def _parse_block(data: bytes) -> None:
    from bitcoin.core import CBlock, b2lx

    try:
        block = CBlock.deserialize(data)
    except Exception as exc:
        typer.echo(f"Error deserializing block: {exc}", err=True)
        raise typer.Exit(1) from exc

    typer.echo(f"hash    : {b2lx(block.GetHash()).decode()}")
    typer.echo(f"version : {block.nVersion}")
    typer.echo(f"prev    : {b2lx(block.hashPrevBlock).decode()}")
    typer.echo(f"merkle  : {b2lx(block.hashMerkleRoot).decode()}")
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
    import os
    from pathlib import Path

    from bitcoin_script.blockchain.parser import BlockFileParser
    from bitcoin_script.blockchain.validation import validate_block, validate_transaction
    from bitcoin_script.blockchain.utxo import UTXOSet

    data_dir = Path(path) if path else Path.home() / ".bitcoin"
    if not data_dir.exists():
        typer.echo(f"Error: block data directory not found: {data_dir}", err=True)
        typer.echo("Provide a path with: bitcoin-script validate /path/to/bitcoin/blocks", err=True)
        raise typer.Exit(1)

    typer.echo(f"Validating from: {data_dir}")
    utxo_set = UTXOSet()
    prev_hash = b"\x00" * 32  # genesis prev block hash

    try:
        parser = BlockFileParser(str(data_dir))
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