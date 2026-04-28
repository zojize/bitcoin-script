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


@app.command(name="k-verify")
def k_verify(
    script_pubkey: Annotated[
        Optional[str],
        typer.Argument(
            help="scriptPubKey in hex or ASM (e.g. 'OP_DUP OP_HASH160 ...')."
        ),
    ] = None,
    script_sig: Annotated[
        str,
        typer.Option(
            "--sig",
            "-s",
            help="scriptSig in hex or ASM. Defaults to empty (native segwit / single-script).",
        ),
    ] = "",
    hex_input: Annotated[
        bool,
        typer.Option(
            "--hex",
            help="Treat script inputs as raw hex (otherwise auto-detect).",
        ),
    ] = False,
    flag: Annotated[
        Optional[list[str]],
        typer.Option(
            "--flag",
            "-f",
            help=(
                "Verification flag name (repeatable; comma-separated also OK). "
                "Use ALL for every flag, STANDARD for Bitcoin Core's "
                "STANDARD_SCRIPT_VERIFY_FLAGS. Examples: -f P2SH -f WITNESS "
                "or -f STANDARD."
            ),
        ),
    ] = None,
    flags_int: Annotated[
        Optional[int],
        typer.Option(
            "--flags-int",
            help=(
                "Set the raw flags bitmask integer directly (overrides --flag). "
                "Useful for reproducing exact Bitcoin Core SCRIPT_VERIFY_* combinations."
            ),
        ),
    ] = None,
    witness: Annotated[
        Optional[list[str]],
        typer.Option(
            "--witness",
            "-w",
            help="Witness stack item (hex). Repeat for each item, top-of-stack last.",
        ),
    ] = None,
    amount: Annotated[
        int,
        typer.Option(
            "--amount", help="Spent-output amount in satoshis (BIP-143 sighash)."
        ),
    ] = 0,
    tx_hex: Annotated[
        Optional[str],
        typer.Option(
            "--tx",
            help=(
                "Raw spending transaction hex. Required for K-native sighash "
                "(BIP-143 / BIP-341 / legacy)."
            ),
        ),
    ] = None,
    input_index: Annotated[
        int,
        typer.Option(
            "--input-index",
            help="Index of the input being verified (used with --tx).",
        ),
    ] = 0,
    prevout: Annotated[
        Optional[list[str]],
        typer.Option(
            "--prevout",
            help=(
                "Spent-output as 'AMOUNT:SCRIPTPUBKEY_HEX' (e.g. "
                "'100000:00208d7a...'), repeated in vin order. Required for "
                "BIP-341 taproot sighash."
            ),
        ),
    ] = None,
    sighash_blob: Annotated[
        Optional[str],
        typer.Option(
            "--sighash",
            help=(
                "Pre-computed sighash blob (hex). Used for legacy paths when "
                "--tx is not supplied; otherwise K computes sighash natively."
            ),
        ),
    ] = None,
    tx_version: Annotated[
        int,
        typer.Option("--tx-version", help="Spending tx version (BIP-68 CSV)."),
    ] = 1,
    n_locktime: Annotated[
        int,
        typer.Option(
            "--locktime",
            help="Spending tx nLockTime (BIP-65 CLTV).",
        ),
    ] = 0,
    n_sequence: Annotated[
        int,
        typer.Option(
            "--sequence",
            help="Input nSequence (BIP-65 CLTV / BIP-68 CSV).",
        ),
    ] = 0xFFFFFFFF,
    sigops_budget: Annotated[
        Optional[int],
        typer.Option(
            "--sigops-budget",
            help="BIP-342 signature validation weight budget (default unlimited).",
        ),
    ] = None,
    list_flags: Annotated[
        bool,
        typer.Option(
            "--list-flags",
            help="Print all supported flag names and bit values, then exit.",
        ),
    ] = False,
    show_flags: Annotated[
        bool,
        typer.Option(
            "--show-flags",
            help="Print the resolved flag set before running.",
        ),
    ] = False,
) -> None:
    """Verify a script through the K Framework formal semantics with full state.

    Exposes every K config cell so users can drive the semantics exactly as
    a node would. Flags can be passed by name (recommended) or as an
    integer bitmask.

    Examples:

        # Pure script execution, no flags:
        bitcoin-script k-verify "OP_1 OP_2 OP_ADD"

        # P2PKH spend with sighash blob:
        bitcoin-script k-verify --sig <sig_hex> <p2pkh_hex> --hex \\
            -f STANDARD --sighash <32-byte-hex>

        # Full BIP-341 taproot key-path verify:
        bitcoin-script k-verify --tx <tx_hex> --input-index 0 \\
            --prevout '100000:00208d7a...' --amount 100000 \\
            -f STANDARD,TAPROOT --witness <schnorr_sig_hex> \\
            <p2tr_hex> --hex
    """
    if list_flags:
        typer.echo("Supported flag names (use with --flag / -f):")
        max_w = max(len(m.name or "") for m in ScriptVerifyFlag if m.name)
        for m in ScriptVerifyFlag:
            if m and m.name:
                typer.echo(
                    f"  {m.name:<{max_w}}  bit {int(m).bit_length() - 1}  (0x{int(m):x})"
                )
        typer.echo("\nAliases:")
        typer.echo("  ALL       — every flag")
        typer.echo(
            "  STANDARD  — Bitcoin Core's STANDARD_SCRIPT_VERIFY_FLAGS (mempool/relay)"
        )
        return

    if script_pubkey is None:
        typer.echo(
            "Error: SCRIPT_PUBKEY argument required (use --list-flags to see flag names).",
            err=True,
        )
        raise typer.Exit(2)

    from bitcoin_script.k_semantics import KBitcoinScript
    from bitcoin_script.script_utils import encode_witness_blob

    # Resolve flags
    if flags_int is not None:
        active_flags = ScriptVerifyFlag(flags_int)
    elif flag:
        try:
            active_flags = ScriptVerifyFlag.from_names(flag)
        except ValueError as exc:
            typer.echo(f"Error: {exc}", err=True)
            raise typer.Exit(2) from exc
    else:
        active_flags = ScriptVerifyFlag.NONE

    if show_flags:
        names = active_flags.names() or ["NONE"]
        typer.echo(f"Flags: 0x{int(active_flags):05x} ({', '.join(names)})")

    # Parse scripts
    try:
        sig_bytes = bytes(_parse_script(script_sig, hex_input)) if script_sig else b""
    except (ScriptError, ValueError) as exc:
        typer.echo(f"Error: bad scriptSig: {exc}", err=True)
        raise typer.Exit(2) from exc
    try:
        spk_bytes = bytes(_parse_script(script_pubkey, hex_input))
    except (ScriptError, ValueError) as exc:
        typer.echo(f"Error: bad scriptPubKey: {exc}", err=True)
        raise typer.Exit(2) from exc

    # Witness
    witness_blob = b""
    if witness:
        try:
            witness_items = [bytes.fromhex(w) for w in witness]
        except ValueError as exc:
            typer.echo(f"Error: invalid witness hex: {exc}", err=True)
            raise typer.Exit(2) from exc
        witness_blob = encode_witness_blob(witness_items)

    # tx + prevouts
    tx_bytes = b""
    if tx_hex is not None:
        try:
            tx_bytes = bytes.fromhex(tx_hex)
        except ValueError as exc:
            typer.echo(f"Error: invalid --tx hex: {exc}", err=True)
            raise typer.Exit(2) from exc

    prevouts_blob = b""
    if prevout:
        chunks: list[bytes] = []
        for spec in prevout:
            if ":" not in spec:
                typer.echo(
                    f"Error: --prevout must be 'AMOUNT:SCRIPTPUBKEY_HEX', got {spec!r}",
                    err=True,
                )
                raise typer.Exit(2)
            amt_str, spk_hex = spec.split(":", 1)
            try:
                amt = int(amt_str)
                spk = bytes.fromhex(spk_hex)
            except ValueError as exc:
                typer.echo(f"Error: bad --prevout {spec!r}: {exc}", err=True)
                raise typer.Exit(2) from exc
            chunks.append(amt.to_bytes(8, "little"))
            n = len(spk)
            if n <= 252:
                chunks.append(n.to_bytes(1, "little"))
            elif n <= 0xFFFF:
                chunks.append(b"\xfd" + n.to_bytes(2, "little"))
            else:
                chunks.append(b"\xfe" + n.to_bytes(4, "little"))
            chunks.append(spk)
        prevouts_blob = b"".join(chunks)

    # sighash blob
    if sighash_blob is not None:
        try:
            sighash_bytes = bytes.fromhex(sighash_blob)
        except ValueError as exc:
            typer.echo(f"Error: invalid --sighash hex: {exc}", err=True)
            raise typer.Exit(2) from exc
    else:
        sighash_bytes = b""

    # Run K
    typer.echo("Loading K Framework semantics...", err=True)
    try:
        k = KBitcoinScript()
    except Exception as exc:
        typer.echo(f"Error: failed to load K runtime: {exc}", err=True)
        raise typer.Exit(1) from exc

    pat = k.verify_script(
        script_pubkey=spk_bytes,
        script_sig=sig_bytes,
        sighash=sighash_bytes,
        witness=witness_blob,
        flags=int(active_flags),
        tx_version=tx_version,
        n_locktime=n_locktime,
        n_sequence=n_sequence,
        sigops_budget=sigops_budget,
        tx=tx_bytes,
        prevouts=prevouts_blob,
        input_index=input_index,
        amount=amount,
    )

    err = k.error(pat)
    ok = k.success(pat)
    stack = k.stack(pat)

    typer.echo(f"Result: {'PASS' if ok else 'FAIL'}")
    if err:
        typer.echo(f"Error: {err}")
    elif not ok and k.is_stuck(pat):
        typer.echo(
            "Stuck: K rewrite halted on an unmatched pattern (likely an "
            "implicit failure such as stack underflow)."
        )
    typer.echo(f"Stack ({len(stack)} item{'s' if len(stack) != 1 else ''}):")
    for i, item in enumerate(stack):
        typer.echo(f"  {i}: {_format_stack_item(item)}")

    if not ok:
        raise typer.Exit(1)


@app.command()
def repl(
    backend: Annotated[
        Backend, typer.Option("--backend", help="Execution backend.")
    ] = Backend.k,
) -> None:
    """Interactive Bitcoin Script REPL with full K state.

    Type opcodes and data to build a scriptPubKey, then execute it through
    the K Framework formal semantics. Supports both OP_-prefixed and bare
    opcode names, hex data, quoted strings, and bare integers.

    The REPL exposes every K config cell so you can drive the semantics
    exactly as a node would: scriptSig, witness items, flags by name, full
    BIP-143/341 sighash context (tx + prevouts + amount + input_index).

    Top-level commands (use .help for full list):

        .run, .stack, .reset, .help, .quit
        .sig <hex|asm>            scriptSig
        .witness <hex>            push a witness item
        .flag NAME [...]          toggle flag(s) by name
        .tx <hex>                 raw spending tx
        .state                    show every K state cell

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
    from bitcoin_script.script_utils import encode_witness_blob

    console = Console()
    session: PromptSession[str] = PromptSession(history=InMemoryHistory())

    if backend != Backend.k:
        typer.echo(f"Backend '{backend.value}' is not yet implemented.", err=True)
        raise typer.Exit(1)

    console.print("[bold]Bitcoin Script REPL[/bold]")
    console.print(
        "Type opcodes to build a scriptPubKey. Use .run to execute, .help for commands.\n"
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

    # K state mirroring KBitcoinScript.verify_script's parameters.
    asm_tokens: list[str] = []
    sig_bytes: bytes = b""
    sig_repr: str = "(empty)"
    witness_items: list[bytes] = []
    flags = ScriptVerifyFlag.NONE
    tx_bytes: bytes = b""
    prevouts: list[tuple[int, bytes]] = []  # (amount, scriptPubKey)
    input_index: int = 0
    amount: int = 0
    tx_version: int = 1
    n_locktime: int = 0
    n_sequence: int = 0xFFFFFFFF
    sigops_budget: int | None = None
    sighash_blob: bytes = b""
    last_result = None

    def _parse_value_arg(s: str, *, want_hex: bool = False) -> bytes:
        """Parse a token (hex with optional 0x, or ASM) into bytes."""
        s = s.strip()
        if want_hex or s.startswith("0x") or _looks_like_hex(s):
            return bytes.fromhex(s.removeprefix("0x"))
        return bytes(parse_asm(s))

    def _prevouts_blob() -> bytes:
        chunks: list[bytes] = []
        for amt, spk in prevouts:
            chunks.append(amt.to_bytes(8, "little"))
            n = len(spk)
            if n <= 252:
                chunks.append(n.to_bytes(1, "little"))
            elif n <= 0xFFFF:
                chunks.append(b"\xfd" + n.to_bytes(2, "little"))
            else:
                chunks.append(b"\xfe" + n.to_bytes(4, "little"))
            chunks.append(spk)
        return b"".join(chunks)

    def _show_stack() -> None:
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

    def _show_state() -> None:
        names = flags.names() or ["NONE"]
        console.print(
            f"[bold]flags[/bold]       0x{int(flags):05x} ({', '.join(names)})"
        )
        console.print(f"[bold]scriptSig[/bold]   {sig_repr} ({len(sig_bytes)} bytes)")
        if asm_tokens:
            try:
                spk = parse_asm(" ".join(asm_tokens))
                console.print(
                    f"[bold]scriptPubKey[/bold] {spk.hex()} ({len(spk)} bytes)"
                )
            except Exception as e:
                console.print(
                    f"[bold]scriptPubKey[/bold] [yellow]parse error: {e}[/yellow]"
                )
        else:
            console.print("[bold]scriptPubKey[/bold] (empty)")
        console.print(f"[bold]witness[/bold]     {len(witness_items)} item(s)")
        for i, w in enumerate(witness_items):
            console.print(f"  [{i}] {w.hex() if w else '(empty)'}")
        console.print(
            f"[bold]tx[/bold]          {len(tx_bytes)} bytes (input_index={input_index})"
        )
        console.print(f"[bold]prevouts[/bold]    {len(prevouts)} entry(ies)")
        for i, (amt, spk) in enumerate(prevouts):
            console.print(
                f"  [{i}] {amt} sat -> {spk.hex()[:40]}{'...' if len(spk) > 20 else ''}"
            )
        console.print(
            f"[bold]amount[/bold]      {amount} sat   "
            f"[bold]version[/bold] {tx_version}   "
            f"[bold]locktime[/bold] {n_locktime}   "
            f"[bold]sequence[/bold] 0x{n_sequence:08x}"
        )
        budget_str = "unlimited" if sigops_budget is None else str(sigops_budget)
        console.print(f"[bold]sigops_budget[/bold] {budget_str}")
        if sighash_blob:
            console.print(
                f"[bold]sighash_blob[/bold] {len(sighash_blob)} bytes (precomputed)"
            )

    def _show_help() -> None:
        console.print("[bold]Execution & buffer:[/bold]")
        console.print("  .run                Execute script through K semantics")
        console.print("  .stack              Show stack from last execution")
        console.print("  .state              Show every current state cell")
        console.print("  .reset              Clear scriptPubKey buffer + last result")
        console.print("  .reset-all          Clear ALL state (sig, witness, tx, etc.)")
        console.print("  .script             Show current scriptPubKey (hex)")
        console.print("  .asm                Show current scriptPubKey (ASM tokens)")
        console.print("  .help               Show this help")
        console.print("  .quit               Exit")
        console.print()
        console.print("[bold]Inputs to verify_script:[/bold]")
        console.print("  .sig <hex|asm>      Set scriptSig (empty arg clears)")
        console.print("  .witness <hex>      Append a witness stack item")
        console.print("  .witness-clear      Clear all witness items")
        console.print("  .flag NAME [NAME..] Toggle flag(s) by name (e.g. .flag P2SH)")
        console.print("  .flag-clear         Clear all flags")
        console.print("  .flag-set ALL|STANDARD  Apply preset")
        console.print("  .flags-int [N]      Show or set raw bitmask")
        console.print("  .flags-list         List all valid flag names")
        console.print()
        console.print("[bold]Sighash context (for K-native sighash):[/bold]")
        console.print("  .tx <hex>           Set raw spending tx (empty clears)")
        console.print("  .input-index N      Set input being verified")
        console.print("  .amount N           Set spent-output amount (sat)")
        console.print("  .prevout AMT:HEX    Append a prevout (BIP-341)")
        console.print("  .prevout-clear      Clear prevouts")
        console.print("  .version N          Set tx version")
        console.print("  .locktime N         Set tx nLockTime")
        console.print("  .sequence N         Set input nSequence")
        console.print("  .sigops-budget N    Set BIP-342 sigops budget (or 'none')")
        console.print("  .sighash <hex>      Set precomputed sighash blob")
        console.print()
        console.print("[bold]ScriptPubKey input:[/bold]")
        console.print("  OP_DUP, DUP         Opcodes (OP_ prefix optional)")
        console.print("  0x1234              Hex data push")
        console.print("  'hello'             String data push")
        console.print("  42, -1              Integer push")

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
            parts = line.split()
            cmd = parts[0].lower()
            args = parts[1:]

            try:
                if cmd in (".quit", ".exit", ".q"):
                    break
                elif cmd == ".help":
                    _show_help()
                elif cmd == ".reset":
                    asm_tokens.clear()
                    last_result = None
                    console.print("[dim]Script cleared (other state preserved).[/dim]")
                elif cmd == ".reset-all":
                    asm_tokens.clear()
                    sig_bytes = b""
                    sig_repr = "(empty)"
                    witness_items.clear()
                    flags = ScriptVerifyFlag.NONE
                    tx_bytes = b""
                    prevouts.clear()
                    input_index = 0
                    amount = 0
                    tx_version = 1
                    n_locktime = 0
                    n_sequence = 0xFFFFFFFF
                    sigops_budget = None
                    sighash_blob = b""
                    last_result = None
                    console.print("[dim]All state cleared.[/dim]")
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
                elif cmd == ".state":
                    _show_state()
                elif cmd == ".sig":
                    if not args:
                        sig_bytes = b""
                        sig_repr = "(empty)"
                        console.print("[dim]scriptSig cleared.[/dim]")
                    else:
                        rest = line[len(".sig") :].strip()
                        sig_bytes = _parse_value_arg(rest)
                        sig_repr = sig_bytes.hex() or "(empty)"
                        console.print(f"scriptSig: {sig_repr} ({len(sig_bytes)} bytes)")
                elif cmd == ".witness":
                    if not args:
                        console.print("[red]usage: .witness <hex>[/red]")
                    else:
                        item = bytes.fromhex(args[0].removeprefix("0x"))
                        witness_items.append(item)
                        console.print(
                            f"witness[{len(witness_items) - 1}] = {item.hex() or '(empty)'} "
                            f"({len(item)} bytes)"
                        )
                elif cmd in (".witness-clear", ".clear-witness"):
                    witness_items.clear()
                    console.print("[dim]Witness cleared.[/dim]")
                elif cmd == ".flag":
                    if not args:
                        console.print(
                            f"flags: 0x{int(flags):05x} ({', '.join(flags.names()) or 'NONE'})"
                        )
                    else:
                        new_bits = ScriptVerifyFlag.from_names(args)
                        # Toggle: XOR each flag mentioned
                        flags = ScriptVerifyFlag(int(flags) ^ int(new_bits))
                        console.print(
                            f"flags: 0x{int(flags):05x} ({', '.join(flags.names()) or 'NONE'})"
                        )
                elif cmd == ".flag-clear":
                    flags = ScriptVerifyFlag.NONE
                    console.print("flags: 0x00000 (NONE)")
                elif cmd == ".flag-set":
                    if not args:
                        console.print(
                            "[red]usage: .flag-set ALL|STANDARD|<NAMES>[/red]"
                        )
                    else:
                        flags = ScriptVerifyFlag.from_names(args)
                        console.print(
                            f"flags: 0x{int(flags):05x} ({', '.join(flags.names()) or 'NONE'})"
                        )
                elif cmd == ".flags-int":
                    if args:
                        flags = ScriptVerifyFlag(int(args[0], 0))
                    console.print(
                        f"flags: 0x{int(flags):05x} ({', '.join(flags.names()) or 'NONE'})"
                    )
                elif cmd == ".flags-list":
                    for m in ScriptVerifyFlag:
                        if m and m.name:
                            console.print(
                                f"  {m.name}  (bit {int(m).bit_length() - 1}, 0x{int(m):x})"
                            )
                # Backward compat for old .flags command
                elif cmd == ".flags":
                    if args:
                        flags = ScriptVerifyFlag(int(args[0], 0))
                    console.print(
                        f"flags: 0x{int(flags):05x} ({', '.join(flags.names()) or 'NONE'})"
                    )
                elif cmd == ".tx":
                    if not args:
                        tx_bytes = b""
                        console.print("[dim]tx cleared.[/dim]")
                    else:
                        tx_bytes = bytes.fromhex(args[0].removeprefix("0x"))
                        console.print(f"tx: {len(tx_bytes)} bytes")
                elif cmd == ".input-index":
                    input_index = int(args[0], 0) if args else 0
                    console.print(f"input_index: {input_index}")
                elif cmd == ".amount":
                    amount = int(args[0], 0) if args else 0
                    console.print(f"amount: {amount} sat")
                elif cmd == ".prevout":
                    if len(args) != 1 or ":" not in args[0]:
                        console.print(
                            "[red]usage: .prevout AMOUNT:SCRIPTPUBKEY_HEX[/red]"
                        )
                    else:
                        amt_str, spk_hex = args[0].split(":", 1)
                        prevouts.append(
                            (int(amt_str), bytes.fromhex(spk_hex.removeprefix("0x")))
                        )
                        console.print(
                            f"prevouts[{len(prevouts) - 1}] = {prevouts[-1][0]} sat / "
                            f"{prevouts[-1][1].hex()[:32]}..."
                        )
                elif cmd in (".prevout-clear", ".prevouts-clear"):
                    prevouts.clear()
                    console.print("[dim]Prevouts cleared.[/dim]")
                elif cmd == ".version":
                    tx_version = int(args[0], 0) if args else 1
                    console.print(f"tx_version: {tx_version}")
                elif cmd == ".locktime":
                    n_locktime = int(args[0], 0) if args else 0
                    console.print(f"n_locktime: {n_locktime}")
                elif cmd == ".sequence":
                    n_sequence = int(args[0], 0) if args else 0xFFFFFFFF
                    console.print(f"n_sequence: 0x{n_sequence:08x}")
                elif cmd == ".sigops-budget":
                    if args and args[0].lower() != "none":
                        sigops_budget = int(args[0], 0)
                        console.print(f"sigops_budget: {sigops_budget}")
                    else:
                        sigops_budget = None
                        console.print("sigops_budget: unlimited")
                elif cmd == ".sighash":
                    if not args:
                        sighash_blob = b""
                        console.print("[dim]sighash cleared.[/dim]")
                    else:
                        sighash_blob = bytes.fromhex(args[0].removeprefix("0x"))
                        console.print(f"sighash: {len(sighash_blob)} bytes")
                elif cmd == ".stack":
                    _show_stack()
                elif cmd == ".run":
                    if not asm_tokens:
                        console.print(
                            "[dim]ScriptPubKey is empty. Type some opcodes first.[/dim]"
                        )
                        continue
                    asm_str = " ".join(asm_tokens)
                    try:
                        spk = parse_asm(asm_str)
                    except Exception as e:
                        console.print(f"[red]Parse error: {e}[/red]")
                        continue
                    witness_blob = (
                        encode_witness_blob(witness_items) if witness_items else b""
                    )
                    console.print(
                        f"[dim]Executing scriptPubKey={len(spk)}B sig={len(sig_bytes)}B "
                        f"witness={len(witness_items)}items flags=0x{int(flags):05x}...[/dim]"
                    )
                    try:
                        last_result = k.verify_script(
                            script_pubkey=spk,
                            script_sig=sig_bytes,
                            sighash=sighash_blob,
                            witness=witness_blob,
                            flags=int(flags),
                            tx_version=tx_version,
                            n_locktime=n_locktime,
                            n_sequence=n_sequence,
                            sigops_budget=sigops_budget,
                            tx=tx_bytes,
                            prevouts=_prevouts_blob(),
                            input_index=input_index,
                            amount=amount,
                        )
                    except Exception as e:
                        console.print(f"[red]K execution error: {e}[/red]")
                        continue
                    _show_stack()
                else:
                    console.print(f"[red]Unknown command: {cmd}[/red] (try .help)")
            except ValueError as e:
                console.print(f"[red]error: {e}[/red]")
            except Exception as e:
                console.print(f"[red]error: {e}[/red]")
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
