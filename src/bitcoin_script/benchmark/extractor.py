"""Extract benchmark inputs from mainnet blocks."""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator
from pathlib import Path

from bitcoin.core import CBlock

from bitcoin_script.blockchain.flags import flags_for_block
from bitcoin_script.blockchain.parser import BlockFileParser
from bitcoin_script.blockchain.utxo import UTXOSet
from bitcoin_script.blockchain.verifier import _compute_sighash_blob

from .dataset import (
    BenchmarkInput,
    Dataset,
    append_inputs,
    load_partial_inputs,
    save_dataset,
)
from .stress import (
    KNOWN_STRESS_BLOCKS,
    classify_era,
    select_representative_heights,
)

log = logging.getLogger(__name__)


def extract_inputs_from_block(
    block: CBlock,
    height: int,
    utxo: UTXOSet,
    category: str,
) -> list[BenchmarkInput]:
    """Extract all non-coinbase inputs from a block as BenchmarkInput records.

    Also updates the UTXO set (spends inputs, adds outputs) so that
    subsequent blocks can find their UTXOs.
    """
    flags = flags_for_block(height, block.nTime)
    era = classify_era(height)
    inputs: list[BenchmarkInput] = []

    for tx_idx, tx in enumerate(block.vtx):
        is_coinbase = tx_idx == 0
        txid = tx.GetTxid()

        if not is_coinbase:
            # Collect all prevout data for BIP 341 taproot sighash
            all_prevout_spks: list[bytes] = []
            all_prevout_amounts: list[int] = []
            all_resolved = True
            for _vin in tx.vin:
                entry = utxo.get(bytes(_vin.prevout.hash), _vin.prevout.n)
                if entry is None:
                    all_resolved = False
                    break
                all_prevout_spks.append(entry[0])
                all_prevout_amounts.append(entry[1])

            for input_index, vin in enumerate(tx.vin):
                prev_txid = bytes(vin.prevout.hash)
                prev_vout = vin.prevout.n

                utxo_entry = utxo.get(prev_txid, prev_vout)
                if utxo_entry is None:
                    log.warning(
                        "UTXO not found for block %d tx %d input %d: %s:%d",
                        height,
                        tx_idx,
                        input_index,
                        prev_txid.hex(),
                        prev_vout,
                    )
                    continue

                script_pubkey, amount = utxo_entry
                script_sig = bytes(vin.scriptSig)

                witness_items: list[bytes] = []
                if tx.wit and input_index < len(tx.wit.vtxinwit):
                    stack = tx.wit.vtxinwit[input_index].scriptWitness.stack
                    witness_items = [bytes(w) for w in stack]

                sighash_blob = _compute_sighash_blob(
                    tx,
                    input_index,
                    script_pubkey,
                    amount,
                    all_prevout_scriptpubkeys=all_prevout_spks
                    if all_resolved
                    else None,
                    all_prevout_amounts=all_prevout_amounts if all_resolved else None,
                )

                tx_serialized = tx.serialize()

                inputs.append(
                    BenchmarkInput(
                        block_height=height,
                        tx_index=tx_idx,
                        input_index=input_index,
                        txid=bytes(txid),
                        era=era,
                        category=category,
                        script_pubkey=script_pubkey,
                        script_sig=script_sig,
                        amount=amount,
                        flags=flags,
                        witness=witness_items,
                        tx_serialized=tx_serialized,
                        n_in=input_index,
                        sighash_blob=sighash_blob,
                        tx_version=tx.nVersion,
                        n_locktime=tx.nLockTime,
                        n_sequence=vin.nSequence,
                        all_prevout_scriptpubkeys=all_prevout_spks
                        if all_resolved
                        else None,
                        all_prevout_amounts=all_prevout_amounts
                        if all_resolved
                        else None,
                    )
                )

            # Spend inputs in UTXO set
            for vin in tx.vin:
                prev_txid = bytes(vin.prevout.hash)
                prev_vout = vin.prevout.n
                try:
                    utxo.spend(prev_txid, prev_vout)
                except KeyError:
                    pass

        # Add outputs to UTXO set
        bip30 = height in (91842, 91880)
        for vout_idx, txout in enumerate(tx.vout):
            utxo.add(
                txid,
                vout_idx,
                bytes(txout.scriptPubKey),
                txout.nValue,
                allow_overwrite=bip30,
            )

    return inputs


def extract_dataset(
    blocks_dir: Path,
    *,
    output: Path,
    continuous_end: int = 9999,
    blocks_per_era: int = 10,
    stress_count: int = 20,
    on_block: Callable[[int, int], None] | None = None,
    utxo_db: str | None = None,
    skip_taproot: bool = False,
) -> Dataset:
    """Extract a complete benchmark dataset from mainnet .blk files.

    Walks the chain from genesis, building UTXO state and extracting inputs
    for three categories: continuous, representative, and stress.

    If *utxo_db* is a file path, the UTXO set is persisted to SQLite on disk
    and the walk resumes from the last committed height on re-run.  Extracted
    inputs are saved incrementally to a partial file (``output.partial``) so
    they survive crashes too.
    """
    parser = BlockFileParser(blocks_dir)
    utxo = UTXOSet(utxo_db if utxo_db else ":memory:")

    representative_heights = set(
        select_representative_heights(blocks_per_era, skip_taproot=skip_taproot)
    )
    stress_heights = set(KNOWN_STRESS_BLOCKS[:stress_count])

    max_height = max(
        continuous_end,
        max(representative_heights) if representative_heights else 0,
        max(stress_heights) if stress_heights else 0,
    )

    # Resume: reload inputs saved to the partial file and skip processed blocks.
    resume_height = utxo.checkpoint_height
    partial_path = output.with_suffix(output.suffix + ".partial")
    all_inputs: list[BenchmarkInput] = []

    if resume_height >= 0:
        all_inputs = load_partial_inputs(partial_path)
        log.info(
            "Resuming from checkpoint height %d (%d inputs recovered)",
            resume_height,
            len(all_inputs),
        )

    log.info("Extracting dataset up to block %d...", max_height)

    for height, block in _walk_chain(parser, end=max_height):
        # Skip blocks whose UTXO state is already committed.
        if height <= resume_height:
            continue

        category: str | None = None

        if height <= continuous_end:
            category = "continuous"
        elif height in representative_heights:
            category = "representative"
        elif height in stress_heights:
            category = "stress"

        if category is not None:
            block_inputs = extract_inputs_from_block(block, height, utxo, category)
            all_inputs.extend(block_inputs)
            if utxo_db:
                append_inputs(partial_path, block_inputs)
            if on_block is not None:
                on_block(height, len(block_inputs))
        else:
            _update_utxo_only(block, height, utxo)

        # Checkpoint every 1,000 blocks when using on-disk UTXO.
        if utxo_db and height % 1_000 == 0:
            utxo.checkpoint_height = height
            utxo.commit()

        if height % 10_000 == 0:
            log.info(
                "height=%d inputs_extracted=%d utxo_size=%d",
                height,
                len(all_inputs),
                utxo.size(),
            )

    # Final checkpoint.
    if utxo_db:
        utxo.checkpoint_height = max_height
        utxo.commit()

    dataset = Dataset(inputs=all_inputs)
    save_dataset(dataset, output)

    # Clean up partial file now that the final dataset is written.
    if partial_path.exists():
        partial_path.unlink()

    log.info(
        "Dataset saved: %d inputs from %d blocks -> %s",
        len(all_inputs),
        dataset.header["block_count"],
        output,
    )
    return dataset


def _walk_chain(parser: BlockFileParser, end: int) -> Iterator[tuple[int, CBlock]]:
    """Walk chain in order from genesis to end height.

    Replicates ChainVerifier._load_chain() logic: two-pass header scan
    then lazy deserialization in chain order.
    """
    prev_to_hash: dict[bytes, bytes] = {}
    location: dict[bytes, tuple[Path, int, int]] = {}

    for block_hash, prev_hash, path, offset, size in parser.scan_headers():
        if prev_hash not in prev_to_hash:
            prev_to_hash[prev_hash] = block_hash
        location[block_hash] = (path, offset, size)

    log.info("Scanned %d block headers", len(location))

    genesis_prev = b"\x00" * 32
    if genesis_prev not in prev_to_hash:
        return

    current_hash = prev_to_hash[genesis_prev]
    height = 0

    while current_hash in location:
        path, offset, size = location[current_hash]
        block = parser.read_block_at(path, offset, size)
        yield (height, block)
        if height >= end:
            break
        height += 1
        current_hash = prev_to_hash.get(current_hash, b"")


def _update_utxo_only(block: CBlock, height: int, utxo: UTXOSet) -> None:
    """Update UTXO set from a block without extracting benchmark inputs."""
    for tx_idx, tx in enumerate(block.vtx):
        txid = tx.GetTxid()
        is_coinbase = tx_idx == 0

        if not is_coinbase:
            for vin in tx.vin:
                try:
                    utxo.spend(bytes(vin.prevout.hash), vin.prevout.n)
                except KeyError:
                    pass

        bip30 = height in (91842, 91880)
        for vout_idx, txout in enumerate(tx.vout):
            utxo.add(
                txid,
                vout_idx,
                bytes(txout.scriptPubKey),
                txout.nValue,
                allow_overwrite=bip30,
            )
