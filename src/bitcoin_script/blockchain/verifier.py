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
from bitcoin_script.script_utils import (
    encode_witness_blob,
    extract_last_push,
    extract_sig_hashtypes,
    find_codesep_positions,
    is_p2sh,
    is_witness_program,
    remove_codeseparators,
)

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
    tx: bytes,
    input_index: int,
    amount: int,
    tx_idx: int,
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
        tx=tx,
        input_index=input_index,
        amount=amount,
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


def _compact_size(n: int) -> bytes:
    """Bitcoin compact size encoding."""
    if n <= 252:
        return n.to_bytes(1, "little")
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def _tagged_hash(tag: str, msg: bytes) -> bytes:
    """BIP 340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg)."""
    import hashlib

    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()


def _taproot_sighash(
    tx: CTransaction,
    input_index: int,
    hash_type: int,
    ext_flag: int,
    all_prevout_scriptpubkeys: list[bytes],
    all_prevout_amounts: list[int],
    annex: bytes | None = None,
    tapleaf_hash: bytes | None = None,
    codesep_pos: int = 0xFFFFFFFF,
) -> bytes:
    """Compute BIP 341 taproot sighash.

    Args:
        tx: The spending transaction.
        input_index: Index of the input being signed.
        hash_type: Sighash type (0x00=DEFAULT, 0x01=ALL, ...).
        ext_flag: 0 for key-path, 1 for script-path (tapscript).
        all_prevout_scriptpubkeys: scriptPubKey of each input's prevout.
        all_prevout_amounts: Amount (satoshis) of each input's prevout.
        annex: Annex data if present (raw bytes including 0x50 prefix).
        tapleaf_hash: Tapleaf hash for script-path (ext_flag=1).
        codesep_pos: Last executed OP_CODESEPARATOR position, or 0xFFFFFFFF.
    """
    import hashlib
    import struct

    # Effective hash type for computing which fields to include
    if hash_type == 0:
        base_type = 1  # DEFAULT behaves like ALL
    else:
        base_type = hash_type & 0x1F
    anyone_can_pay = (hash_type & 0x80) != 0

    msg = b"\x00"  # epoch
    msg += struct.pack("<B", hash_type)
    msg += struct.pack("<i", tx.nVersion)
    msg += struct.pack("<I", tx.nLockTime)

    if not anyone_can_pay:
        # sha256(outpoints)
        prevouts = b""
        for vin in tx.vin:
            prevouts += bytes(vin.prevout.hash) + struct.pack("<I", vin.prevout.n)
        msg += hashlib.sha256(prevouts).digest()

        # sha256(amounts)
        amounts = b""
        for amt in all_prevout_amounts:
            amounts += struct.pack("<q", amt)
        msg += hashlib.sha256(amounts).digest()

        # sha256(scriptpubkeys)
        spks = b""
        for spk in all_prevout_scriptpubkeys:
            spks += _compact_size(len(spk)) + spk
        msg += hashlib.sha256(spks).digest()

        # sha256(sequences)
        sequences = b""
        for vin in tx.vin:
            sequences += struct.pack("<I", vin.nSequence)
        msg += hashlib.sha256(sequences).digest()

    if base_type != 2 and base_type != 3:  # not NONE and not SINGLE
        # sha256(outputs)
        outputs = b""
        for vout in tx.vout:
            outputs += struct.pack("<q", vout.nValue)
            outputs += _compact_size(len(vout.scriptPubKey)) + bytes(vout.scriptPubKey)
        msg += hashlib.sha256(outputs).digest()

    # spend_type
    has_annex = annex is not None
    spend_type = (ext_flag << 1) | (1 if has_annex else 0)
    msg += struct.pack("<B", spend_type)

    if anyone_can_pay:
        vin = tx.vin[input_index]
        msg += bytes(vin.prevout.hash) + struct.pack("<I", vin.prevout.n)
        msg += struct.pack("<q", all_prevout_amounts[input_index])
        spk = all_prevout_scriptpubkeys[input_index]
        msg += _compact_size(len(spk)) + spk
        msg += struct.pack("<I", vin.nSequence)
    else:
        msg += struct.pack("<I", input_index)

    if has_annex:
        assert annex is not None
        msg += hashlib.sha256(_compact_size(len(annex)) + annex).digest()

    if base_type == 3:  # SINGLE
        if input_index < len(tx.vout):
            vout = tx.vout[input_index]
            out_data = struct.pack("<q", vout.nValue)
            out_data += _compact_size(len(vout.scriptPubKey)) + bytes(vout.scriptPubKey)
            msg += hashlib.sha256(out_data).digest()
        else:
            # SIGHASH_SINGLE with no matching output
            msg += b"\x00" * 32

    if ext_flag == 1:
        assert tapleaf_hash is not None
        msg += tapleaf_hash
        msg += b"\x00"  # key_version
        msg += struct.pack("<I", codesep_pos)

    return _tagged_hash("TapSighash", msg)


def _compute_sighash_blob(
    tx: CTransaction,
    input_index: int,
    script_pubkey: bytes,
    _amount: int,
    *,
    all_prevout_scriptpubkeys: list[bytes] | None = None,
    all_prevout_amounts: list[int] | None = None,
) -> bytes:
    """Compute sighash blob for a transaction input.

    Returns concatenated (1-byte hashtype + 2-byte BE codesepIdx + 32-byte sighash) entries.
    Computes sighashes for each CODESEPARATOR position in the subscript.

    Witness-v0 (BIP-143) sighashes are no longer emitted here — the K
    semantics compute them natively via #bip143Sighash from the <tx> /
    <inputIndex> / <scriptCode> / <amount> cells. Legacy and BIP-341
    taproot still use this blob as the input-side representation.
    """
    from bitcoin.core.script import (
        CScript,
        SIGHASH_ALL,
        SIGHASH_ANYONECANPAY,
        SIGHASH_NONE,
        SIGHASH_SINGLE,
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
    hashtypes |= extract_sig_hashtypes(script_sig)

    witness_items: list[bytes] = []
    if tx.wit and input_index < len(tx.wit.vtxinwit):
        witness_items = [
            bytes(item) for item in tx.wit.vtxinwit[input_index].scriptWitness.stack
        ]
        for item in witness_items:
            if len(item) >= 9 and item[0] == 0x30:
                hashtypes.add(item[-1])

    # Determine witness program
    wp = is_witness_program(script_pubkey)
    if wp is None and is_p2sh(script_pubkey):
        redeem = extract_last_push(script_sig)
        if redeem is not None:
            wp = is_witness_program(redeem)

    parts: list[bytes] = []

    # BIP-341 taproot sighash (witness v1)
    if (
        wp is not None
        and wp[0] == 1
        and all_prevout_scriptpubkeys is not None
        and all_prevout_amounts is not None
    ):
        _version, program = wp

        # Taproot hashtypes: 0x00 (DEFAULT) + standard ALL/NONE/SINGLE/ANYONECANPAY
        taproot_hashtypes = [0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83]
        # Also extract hashtypes from Schnorr sigs (64 or 65 bytes) in witness
        for item in witness_items:
            if len(item) == 65:
                taproot_hashtypes.append(item[64])
        taproot_ht_set = sorted(set(taproot_hashtypes))

        # Detect annex (last witness item starting with 0x50, if 2+ items)
        annex: bytes | None = None
        effective_witness = list(witness_items)
        if len(effective_witness) >= 2 and effective_witness[-1][:1] == b"\x50":
            annex = effective_witness.pop()

        if len(effective_witness) == 1:
            # Key-path spend: ext_flag=0
            for ht in taproot_ht_set:
                try:
                    sh = _taproot_sighash(
                        tx,
                        input_index,
                        ht,
                        0,
                        all_prevout_scriptpubkeys,
                        all_prevout_amounts,
                        annex,
                    )
                    parts.append(bytes([ht]) + (0).to_bytes(2, "big") + sh)
                except Exception:
                    continue
        elif len(effective_witness) >= 2:
            # Script-path spend: ext_flag=1
            control_block = effective_witness[-1]
            tapscript = effective_witness[-2]
            leaf_version = control_block[0] & 0xFE

            tapleaf_hash = _tagged_hash(
                "TapLeaf",
                bytes([leaf_version]) + _compact_size(len(tapscript)) + tapscript,
            )

            # Compute sighash for each CODESEPARATOR position
            codesep_positions_tap = find_codesep_positions(tapscript)
            # codesepIdx 0 = no CODESEP executed → codesep_pos = 0xFFFFFFFF
            tap_subscripts: list[tuple[int, int]] = [(0, 0xFFFFFFFF)]
            for idx, bp in enumerate(codesep_positions_tap):
                # bp is byte position right AFTER the CODESEP opcode
                # BIP 341 codesep_pos is the position of the opcode itself = bp - 1
                tap_subscripts.append((idx + 1, bp - 1))

            for csi, cspos in tap_subscripts:
                for ht in taproot_ht_set:
                    try:
                        sh = _taproot_sighash(
                            tx,
                            input_index,
                            ht,
                            1,
                            all_prevout_scriptpubkeys,
                            all_prevout_amounts,
                            annex,
                            tapleaf_hash,
                            cspos,
                        )
                        parts.append(bytes([ht]) + csi.to_bytes(2, "big") + sh)
                    except Exception:
                        continue

        # For taproot, don't compute legacy sighash — return early
        return b"".join(parts)

    # Legacy sighash
    legacy_subscript = script_pubkey
    if is_p2sh(script_pubkey):
        redeem = extract_last_push(script_sig)
        if redeem is not None:
            legacy_subscript = redeem

    codesep_positions = find_codesep_positions(legacy_subscript)
    legacy_subscripts: list[tuple[int, bytes]] = [
        (0, remove_codeseparators(legacy_subscript))
    ]
    for idx, bp in enumerate(codesep_positions):
        legacy_subscripts.append(
            (idx + 1, remove_codeseparators(legacy_subscript[bp:]))
        )

    for csi, sub in legacy_subscripts:
        for ht in sorted(hashtypes):
            try:
                sh = SignatureHash(CScript(sub), tx, input_index, ht)
                parts.append(bytes([ht]) + csi.to_bytes(2, "big") + bytes(sh))
            except AssertionError, ValueError:
                # SIGHASH_SINGLE bug: hash is 0x0100...00 when input_index >= len(vout)
                if (ht & 0x1F) == SIGHASH_SINGLE and input_index >= len(tx.vout):
                    parts.append(
                        bytes([ht]) + csi.to_bytes(2, "big") + b"\x01" + b"\x00" * 31
                    )
                log.debug("sighash failed for ht=%d csi=%d", ht, csi)
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
                        encode_witness_blob(witness_items) if witness_items else b""
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
                                "tx": tx.serialize(),
                                "input_index": input_index,
                                "amount": amount,
                            },
                        )
                    )

                # Verify inputs (parallel or sequential). `input_index` is
                # already present in the kwargs dict (passed to verify_script
                # for K-side BIP-143 sighash); the worker also uses it for
                # result tuple indexing.
                if self._pool is not None and len(tasks) > 1:
                    futures = [
                        self._pool.submit(
                            _verify_input_worker,
                            **t[2],
                            tx_idx=t[0],
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

            # Add outputs (BIP-30: blocks 91842 and 91880 have duplicate txids)
            bip30 = height in (91842, 91880)
            for vout_idx, txout in enumerate(tx.vout):
                self._utxo.add(
                    txid,
                    vout_idx,
                    bytes(txout.scriptPubKey),
                    txout.nValue,
                    allow_overwrite=bip30,
                )

        self._utxo.checkpoint_height = height
        self._utxo.commit()

        return BlockResult(
            height=height,
            tx_count=len(block.vtx),
            input_count=input_count,
            elapsed_s=time.monotonic() - t0,
            errors=errors,
        )
