"""Block-by-block script verification using K Framework semantics."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterator, Mapping
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from bitcoin.core import CBlock, CTransaction

from bitcoin_script.blockchain.flags import flags_for_block
from bitcoin_script.blockchain.parser import BlockFileParser
from bitcoin_script.blockchain.utxo import UTXOSet
from bitcoin_script.k_semantics import KBitcoinScript, ScriptDist

log = logging.getLogger(__name__)

# Global K instance for worker processes (initialized once per process)
_worker_k: KBitcoinScript | None = None


def _init_worker() -> None:
    """Initialize K instance in worker process."""
    global _worker_k
    dist = ScriptDist.load()
    _worker_k = KBitcoinScript(dist)


def _verify_input_worker(
    script_sig: bytes,
    script_pubkey: bytes,
    sighash: bytes,
    witness: bytes,
    flags: int,
    tx_version: int,
    n_locktime: int,
    n_sequence: int,
    tx_idx: int,
    input_index: int,
) -> tuple[int, int, str | None]:
    """Worker function: verify a single input. Returns (tx_idx, input_index, error_or_None)."""
    global _worker_k
    assert _worker_k is not None
    result = _worker_k.verify_script(
        script_sig=script_sig,
        script_pubkey=script_pubkey,
        sighash=sighash,
        witness=witness,
        flags=flags,
        tx_version=tx_version,
        n_locktime=n_locktime,
        n_sequence=n_sequence,
    )
    if not _worker_k.success(result):
        return (tx_idx, input_index, _worker_k.error(result))
    return (tx_idx, input_index, None)


@dataclass
class BlockResult:
    """Result of verifying a single block."""

    height: int
    tx_count: int
    input_count: int
    elapsed_s: float
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return len(self.errors) == 0


@dataclass
class ChainResult:
    """Result of verifying a range of blocks."""

    start_height: int
    end_height: int
    blocks_verified: int
    inputs_verified: int
    elapsed_s: float
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return len(self.errors) == 0


def _encode_witness_blob(witness_stack: list[bytes]) -> bytes:
    """Encode witness stack as: <2B BE count> (<2B BE length> <data>)*"""
    result = len(witness_stack).to_bytes(2, "big")
    for item in witness_stack:
        result += len(item).to_bytes(2, "big") + item
    return result


def _is_witness_program(script: bytes) -> tuple[int, bytes] | None:
    """Detect witness program: <version_byte> <push_2_to_40_bytes>."""
    if len(script) < 4 or len(script) > 42:
        return None
    v = script[0]
    if v == 0x00:
        version = 0
    elif 0x51 <= v <= 0x60:
        version = v - 0x50
    else:
        return None
    if script[1] + 2 != len(script):
        return None
    return (version, script[2:])


def _is_p2sh(script: bytes) -> bool:
    return (
        len(script) == 23
        and script[0] == 0xA9
        and script[1] == 0x14
        and script[22] == 0x87
    )


def _extract_last_push(script: bytes) -> bytes | None:
    """Extract the last push data from a script."""
    pos = 0
    last_push: bytes | None = None
    while pos < len(script):
        op = script[pos]
        pos += 1
        if 1 <= op <= 75:
            last_push = script[pos : pos + op]
            pos += op
        elif op == 0x4C and pos < len(script):
            n = script[pos]
            pos += 1
            last_push = script[pos : pos + n]
            pos += n
        elif op == 0x4D and pos + 1 < len(script):
            n = int.from_bytes(script[pos : pos + 2], "little")
            pos += 2
            last_push = script[pos : pos + n]
            pos += n
        elif op == 0x4E and pos + 3 < len(script):
            n = int.from_bytes(script[pos : pos + 4], "little")
            pos += 4
            last_push = script[pos : pos + n]
            pos += n
    return last_push


def _extract_sig_hashtypes(data: bytes) -> set[int]:
    """Extract hashtype bytes from push data that looks like DER signatures."""
    hashtypes: set[int] = set()
    pos = 0
    while pos < len(data):
        op = data[pos]
        pos += 1
        if 1 <= op <= 75:
            item = data[pos : pos + op]
            pos += op
            if len(item) >= 9 and item[0] == 0x30:
                hashtypes.add(item[-1])
        elif op == 0x4C and pos < len(data):
            n = data[pos]
            pos += 1
            pos += n
        elif op == 0x4D and pos + 1 < len(data):
            n = int.from_bytes(data[pos : pos + 2], "little")
            pos += 2
            pos += n
        elif op == 0x4E and pos + 3 < len(data):
            n = int.from_bytes(data[pos : pos + 4], "little")
            pos += 4
            pos += n
    return hashtypes


def _compute_sighash_blob(
    tx: CTransaction,
    input_index: int,
    script_pubkey: bytes,
    amount: int,
) -> bytes:
    """Compute sighash blob for a transaction input.

    Returns concatenated (1-byte hashtype + 32-byte sighash) entries.
    """
    from bitcoin.core.script import (
        CScript,
        SIGHASH_ALL,
        SIGHASH_ANYONECANPAY,
        SIGHASH_NONE,
        SIGHASH_SINGLE,
        SIGVERSION_WITNESS_V0,
        SignatureHash,
    )

    standard_hashtypes = [
        0,  # hashtype 0x00: valid in early Bitcoin, distinct from SIGHASH_ALL
        SIGHASH_ALL,
        SIGHASH_NONE,
        SIGHASH_SINGLE,
        SIGHASH_ALL | SIGHASH_ANYONECANPAY,
        SIGHASH_NONE | SIGHASH_ANYONECANPAY,
        SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,
    ]

    hashtypes: set[int] = set(standard_hashtypes)
    script_sig = bytes(tx.vin[input_index].scriptSig)
    hashtypes |= _extract_sig_hashtypes(script_sig)

    witness_items: list[bytes] = []
    if tx.wit and input_index < len(tx.wit.vtxinwit):
        witness_items = [
            bytes(item) for item in tx.wit.vtxinwit[input_index].scriptWitness.stack
        ]
        for item in witness_items:
            if len(item) >= 9 and item[0] == 0x30:
                hashtypes.add(item[-1])

    # Note: hashtype 0x00 is valid in early Bitcoin (treated differently from
    # SIGHASH_ALL by SignatureHash). Do NOT discard it.

    # Determine witness program
    wp = _is_witness_program(script_pubkey)
    if wp is None and _is_p2sh(script_pubkey):
        redeem = _extract_last_push(script_sig)
        if redeem is not None:
            wp = _is_witness_program(redeem)

    parts: list[bytes] = []

    # BIP-143 witness sighash
    if wp is not None and wp[0] == 0:
        _version, program = wp
        if len(program) == 20:
            subscript = CScript(
                bytes([0x76, 0xA9, 0x14]) + program + bytes([0x88, 0xAC])
            )
        elif len(program) == 32 and witness_items:
            subscript = CScript(witness_items[-1])
        else:
            subscript = None

        if subscript is not None:
            for ht in sorted(hashtypes):
                try:
                    sh = SignatureHash(
                        subscript,
                        tx,
                        input_index,
                        ht,
                        amount=amount,
                        sigversion=SIGVERSION_WITNESS_V0,
                    )
                    parts.append(bytes([ht]) + bytes(sh))
                except AssertionError, ValueError:
                    continue

    # Legacy sighash
    legacy_subscript = script_pubkey
    if _is_p2sh(script_pubkey):
        redeem = _extract_last_push(script_sig)
        if redeem is not None:
            legacy_subscript = redeem

    for ht in sorted(hashtypes):
        try:
            sh = SignatureHash(CScript(legacy_subscript), tx, input_index, ht)
            parts.append(bytes([ht]) + bytes(sh))
        except (ValueError,):
            # SIGHASH_SINGLE bug
            if (ht & 0x1F) == SIGHASH_SINGLE and input_index >= len(tx.vout):
                parts.append(bytes([ht]) + b"\x01" + b"\x00" * 31)
            continue
        except AssertionError:
            continue

    return b"".join(parts)


class ChainVerifier:
    """Orchestrates block-by-block script verification via K Framework."""

    def __init__(
        self,
        blocks_dir: Path,
        utxo_db_path: str | Path = ":memory:",
        *,
        k: KBitcoinScript | None = None,
        max_workers: int = 1,
    ) -> None:
        self._parser = BlockFileParser(blocks_dir)
        self._utxo = UTXOSet(utxo_db_path)
        if k is None:
            dist = ScriptDist.load()
            k = KBitcoinScript(dist)
        self._k = k
        self._max_workers = max_workers
        self._pool: ProcessPoolExecutor | None = None
        if max_workers > 1:
            self._pool = ProcessPoolExecutor(
                max_workers=max_workers, initializer=_init_worker
            )

    @property
    def utxo(self) -> UTXOSet:
        return self._utxo

    def verify_chain(
        self,
        start: int = 0,
        end: int | None = None,
        on_block: Callable[[BlockResult], None] | None = None,
    ) -> ChainResult:
        """Verify blocks from start to end (inclusive).

        Resumes from UTXO checkpoint if start <= checkpoint.
        Blocks are loaded from .blk files and sorted by prev-hash linkage
        since .blk files may store blocks out of order.

        If *on_block* is given, it is called after each block is verified
        (useful for progress reporting).
        """
        checkpoint = self._utxo.checkpoint_height
        effective_start = max(start, checkpoint + 1)

        t0 = time.monotonic()
        total_inputs = 0
        total_blocks = 0
        errors: list[str] = []
        height = effective_start

        # Load and sort blocks by chain order
        chain = self._load_chain(effective_start, end)

        for height, block in chain:
            if end is not None and height > end:
                break

            result = self._verify_block_inner(block, height)
            total_inputs += result.input_count
            total_blocks += 1
            errors.extend(result.errors)

            if on_block is not None:
                on_block(result)

            if height % 1000 == 0 or (end is not None and height == end):
                elapsed = time.monotonic() - t0
                log.info(
                    "height=%d utxo=%d inputs=%d elapsed=%.1fs",
                    height,
                    self._utxo.size(),
                    total_inputs,
                    elapsed,
                )

            if result.errors:
                log.error("Block %d failed: %s", height, result.errors)
                break

        return ChainResult(
            start_height=effective_start,
            end_height=height if total_blocks > 0 else effective_start,
            blocks_verified=total_blocks,
            inputs_verified=total_inputs,
            elapsed_s=time.monotonic() - t0,
            errors=errors,
        )

    def _load_chain(self, start: int, end: int | None) -> Iterator[tuple[int, CBlock]]:
        """Yield (height, block) pairs in chain order.

        Uses a two-pass approach to avoid holding all blocks in memory:
        1. Scan 80-byte headers to build hash linkage + file positions
           (stores only hashes and file offsets — ~100 bytes per block)
        2. Walk the chain from genesis, deserializing blocks lazily
        """
        # Pass 1: scan headers (only 80 bytes per block, no full deserialization)
        target_end = end if end is not None else start + 10000
        prev_to_hash: dict[bytes, bytes] = {}
        location: dict[
            bytes, tuple[Path, int, int]
        ] = {}  # hash -> (path, offset, size)
        scanned = 0

        for block_hash, prev_hash, path, offset, size in self._parser.scan_headers():
            if prev_hash not in prev_to_hash:
                prev_to_hash[prev_hash] = block_hash
            location[block_hash] = (path, offset, size)
            scanned += 1
            if scanned % 50000 == 0:
                chain_len = self._walk_chain_length(prev_to_hash, location)
                log.info("Scanned %d headers, chain length %d", scanned, chain_len)
                if chain_len > target_end:
                    break

        log.info("Scanned %d block headers, walking chain...", scanned)

        # Pass 2: walk chain from genesis, deserialize on demand
        genesis_prev = b"\x00" * 32
        if genesis_prev not in prev_to_hash:
            return

        current_hash = prev_to_hash[genesis_prev]
        height = 0

        while current_hash in location:
            if height >= start:
                path, offset, size = location[current_hash]
                block = self._parser.read_block_at(path, offset, size)
                yield (height, block)
            if end is not None and height >= end:
                break
            height += 1
            current_hash = prev_to_hash.get(current_hash, b"")

    @staticmethod
    def _walk_chain_length(
        prev_to_hash: dict[bytes, bytes],
        known_hashes: Mapping[bytes, object],
    ) -> int:
        """Count chain length from genesis without building the full list."""
        genesis_prev = b"\x00" * 32
        if genesis_prev not in prev_to_hash:
            return 0
        current = prev_to_hash[genesis_prev]
        length = 0
        while current in known_hashes:
            length += 1
            current = prev_to_hash.get(current, b"")
        return length

    def verify_block(self, height: int) -> BlockResult:
        """Verify a single block at the given height.

        Requires UTXO set to be populated up to height-1.
        """
        block = self._parser.get_block_at_height(height)
        return self._verify_block_inner(block, height)

    def verify_block_raw(self, block: CBlock, height: int) -> BlockResult:
        """Verify a block object directly."""
        return self._verify_block_inner(block, height)

    def _verify_block_inner(self, block: CBlock, height: int) -> BlockResult:
        t0 = time.monotonic()
        flags = flags_for_block(height, block.nTime)
        input_count = 0
        errors: list[str] = []

        for tx_idx, tx in enumerate(block.vtx):
            is_coinbase = tx_idx == 0
            txid = tx.GetTxid()

            if not is_coinbase:
                # Collect all inputs to verify
                tasks: list[tuple[int, int, dict]] = []
                for input_index, vin in enumerate(tx.vin):
                    prev_txid = bytes(vin.prevout.hash)
                    prev_vout = vin.prevout.n

                    utxo = self._utxo.get(prev_txid, prev_vout)
                    if utxo is None:
                        errors.append(
                            f"tx {tx_idx} input {input_index}: "
                            f"UTXO not found {prev_txid.hex()}:{prev_vout}"
                        )
                        continue

                    script_pubkey, amount = utxo
                    script_sig = bytes(vin.scriptSig)

                    witness_items: list[bytes] = []
                    if tx.wit and input_index < len(tx.wit.vtxinwit):
                        stack = tx.wit.vtxinwit[input_index].scriptWitness.stack
                        witness_items = [bytes(w) for w in stack]

                    witness_blob = (
                        _encode_witness_blob(witness_items) if witness_items else b""
                    )

                    sighash = _compute_sighash_blob(
                        tx, input_index, script_pubkey, amount
                    )

                    tasks.append(
                        (
                            tx_idx,
                            input_index,
                            {
                                "script_sig": script_sig,
                                "script_pubkey": script_pubkey,
                                "sighash": sighash,
                                "witness": witness_blob,
                                "flags": flags,
                                "tx_version": tx.nVersion,
                                "n_locktime": tx.nLockTime,
                                "n_sequence": vin.nSequence,
                            },
                        )
                    )

                # Verify inputs (parallel or sequential)
                if self._pool is not None and len(tasks) > 1:
                    futures = [
                        self._pool.submit(
                            _verify_input_worker,
                            **t[2],
                            tx_idx=t[0],
                            input_index=t[1],
                        )
                        for t in tasks
                    ]
                    for future in futures:
                        tidx, iidx, err = future.result()
                        if err is not None:
                            errors.append(f"tx {tidx} input {iidx}: {err}")
                        input_count += 1
                else:
                    for tidx, iidx, kwargs in tasks:
                        result = self._k.verify_script(**kwargs)
                        if not self._k.success(result):
                            error = self._k.error(result)
                            errors.append(f"tx {tidx} input {iidx}: {error}")
                        input_count += 1

                # Spend inputs
                for vin in tx.vin:
                    prev_txid = bytes(vin.prevout.hash)
                    prev_vout = vin.prevout.n
                    try:
                        self._utxo.spend(prev_txid, prev_vout)
                    except KeyError:
                        pass  # already reported above

            # Add outputs
            for vout_idx, txout in enumerate(tx.vout):
                self._utxo.add(txid, vout_idx, bytes(txout.scriptPubKey), txout.nValue)

        self._utxo.checkpoint_height = height
        self._utxo.commit()

        return BlockResult(
            height=height,
            tx_count=len(block.vtx),
            input_count=input_count,
            elapsed_s=time.monotonic() - t0,
            errors=errors,
        )
