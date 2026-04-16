"""Extract benchmark inputs from mainnet using the Blockstream esplora REST API.

No Bitcoin Core node required. Fetches only the target blocks (representative +
stress), resolving spent outputs via the API's ``prevout`` field instead of
maintaining a local UTXO set.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from bitcoin_script.blockchain.flags import flags_for_block
from bitcoin_script.blockchain.verifier import _compute_sighash_blob

from .dataset import BenchmarkInput, Dataset, save_dataset
from .stress import (
    KNOWN_STRESS_BLOCKS,
    classify_era,
    select_representative_heights,
)

log = logging.getLogger(__name__)

ESPLORA_BASE = "https://blockstream.info/api"
REQUEST_DELAY = 0.1  # seconds between requests (rate-limit politeness)


def _get_json(path: str) -> Any:
    """GET JSON from esplora API."""
    import json
    import urllib.request

    url = f"{ESPLORA_BASE}{path}"
    time.sleep(REQUEST_DELAY)
    with urllib.request.urlopen(url, timeout=30) as resp:
        return json.loads(resp.read())


def _get_text(path: str) -> str:
    """GET text from esplora API."""
    import urllib.request

    url = f"{ESPLORA_BASE}{path}"
    time.sleep(REQUEST_DELAY)
    with urllib.request.urlopen(url, timeout=30) as resp:
        return resp.read().decode("utf-8").strip()


def _fetch_block_txs(block_hash: str) -> list[dict]:
    """Fetch all transactions for a block (paginated, 25 per page)."""
    txs: list[dict] = []
    start = 0
    while True:
        page = _get_json(f"/block/{block_hash}/txs/{start}")
        if not page:
            break
        txs.extend(page)
        if len(page) < 25:
            break
        start += 25
    return txs


def _reconstruct_tx(api_tx: dict) -> bytes:
    """Reconstruct raw transaction bytes from esplora JSON.

    Builds a CTransaction from the API fields and serializes it, producing
    the exact same bytes as the wire format.
    """
    from bitcoin.core import (
        CMutableTransaction,
        CMutableTxIn,
        CMutableTxOut,
        COutPoint,
    )
    from bitcoin.core.script import CScript

    vin = []
    for inp in api_tx["vin"]:
        prevout = COutPoint(bytes.fromhex(inp["txid"])[::-1], inp["vout"])
        scriptsig = CScript(bytes.fromhex(inp.get("scriptsig", "")))
        vin.append(CMutableTxIn(prevout, scriptsig, inp.get("sequence", 0xFFFFFFFF)))

    vout = []
    for out in api_tx["vout"]:
        script = CScript(bytes.fromhex(out["scriptpubkey"]))
        vout.append(CMutableTxOut(out["value"], script))

    tx = CMutableTransaction(vin, vout)
    tx.nVersion = api_tx["version"]
    tx.nLockTime = api_tx["locktime"]

    # Add witness data if present.
    has_witness = any(inp.get("witness") for inp in api_tx["vin"])
    if has_witness:
        from bitcoin.core import CTxInWitness, CTxWitness, CScriptWitness

        wit_items = []
        for inp in api_tx["vin"]:
            stack = [bytes.fromhex(w) for w in inp.get("witness", [])]
            wit_items.append(CTxInWitness(CScriptWitness(stack)))
        tx.wit = CTxWitness(wit_items)

    return tx.serialize()


def _extract_inputs_from_api_block(
    height: int,
    block_timestamp: int,
    txs: list[dict],
    category: str,
) -> list[BenchmarkInput]:
    """Extract BenchmarkInput records from API transaction data."""
    from bitcoin.core import CTransaction

    flags = flags_for_block(height, block_timestamp)
    era = classify_era(height)
    inputs: list[BenchmarkInput] = []

    for tx_idx, api_tx in enumerate(txs):
        if api_tx.get("vin", [{}])[0].get("is_coinbase", False):
            continue

        raw_tx = _reconstruct_tx(api_tx)
        tx = CTransaction.deserialize(raw_tx)
        txid = tx.GetTxid()

        # Collect all prevout data for BIP 341 taproot sighash
        all_prevout_spks: list[bytes] = []
        all_prevout_amounts: list[int] = []
        all_resolved = True
        for vin_data in api_tx["vin"]:
            pv = vin_data.get("prevout")
            if pv is None:
                all_resolved = False
                break
            all_prevout_spks.append(bytes.fromhex(pv["scriptpubkey"]))
            all_prevout_amounts.append(pv["value"])

        for input_index, api_vin in enumerate(api_tx["vin"]):
            prevout = api_vin.get("prevout")
            if prevout is None:
                log.warning(
                    "No prevout for block %d tx %d input %d (spent output unavailable)",
                    height,
                    tx_idx,
                    input_index,
                )
                continue

            script_pubkey = bytes.fromhex(prevout["scriptpubkey"])
            amount = prevout["value"]
            script_sig = bytes.fromhex(api_vin.get("scriptsig", ""))

            witness_items: list[bytes] = [
                bytes.fromhex(w) for w in api_vin.get("witness", [])
            ]

            sighash_blob = _compute_sighash_blob(
                tx,
                input_index,
                script_pubkey,
                amount,
                all_prevout_scriptpubkeys=all_prevout_spks if all_resolved else None,
                all_prevout_amounts=all_prevout_amounts if all_resolved else None,
            )

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
                    tx_serialized=raw_tx,
                    n_in=input_index,
                    sighash_blob=sighash_blob,
                    tx_version=tx.nVersion,
                    n_locktime=tx.nLockTime,
                    n_sequence=tx.vin[input_index].nSequence,
                )
            )

    return inputs


def extract_dataset_api(
    *,
    output: Path,
    continuous_end: int = 9999,
    blocks_per_era: int = 10,
    stress_count: int = 20,
    skip_taproot: bool = False,
    on_block: Callable[[int, int], None] | None = None,
) -> Dataset:
    """Extract a benchmark dataset via the esplora REST API.

    Unlike the local extractor, this does NOT walk the chain from genesis.
    It fetches only the target blocks directly, using the API's prevout
    resolution to get spent output data.

    Note: the ``continuous_end`` range (blocks 0–9999) is skipped by default
    for API extraction because fetching 10,000 blocks is impractical. Pass
    ``continuous_end=-1`` explicitly to disable, or a small value to include
    a few early blocks.
    """
    representative_heights = set(
        select_representative_heights(blocks_per_era, skip_taproot=skip_taproot)
    )
    stress_heights = set(KNOWN_STRESS_BLOCKS[:stress_count])

    target_blocks: dict[int, str] = {}
    if continuous_end >= 0:
        for h in range(continuous_end + 1):
            target_blocks[h] = "continuous"
    for h in representative_heights:
        if h not in target_blocks:
            target_blocks[h] = "representative"
    for h in stress_heights:
        if h not in target_blocks:
            target_blocks[h] = "stress"

    sorted_heights = sorted(target_blocks)
    log.info(
        "Fetching %d blocks via esplora API (%d continuous, %d representative, %d stress)",
        len(sorted_heights),
        sum(1 for c in target_blocks.values() if c == "continuous"),
        sum(1 for c in target_blocks.values() if c == "representative"),
        sum(1 for c in target_blocks.values() if c == "stress"),
    )

    all_inputs: list[BenchmarkInput] = []

    for i, height in enumerate(sorted_heights):
        category = target_blocks[height]

        block_hash = _get_text(f"/block-height/{height}")
        block_info = _get_json(f"/block/{block_hash}")
        block_timestamp = block_info["timestamp"]
        txs = _fetch_block_txs(block_hash)

        block_inputs = _extract_inputs_from_api_block(
            height, block_timestamp, txs, category
        )
        all_inputs.extend(block_inputs)

        if on_block is not None:
            on_block(height, len(block_inputs))

        log.info(
            "[%d/%d] block %d (%s): %d txs, %d inputs extracted",
            i + 1,
            len(sorted_heights),
            height,
            category,
            len(txs),
            len(block_inputs),
        )

    dataset = Dataset(inputs=all_inputs)
    save_dataset(dataset, output)
    log.info(
        "Dataset saved: %d inputs from %d blocks -> %s",
        len(all_inputs),
        len(sorted_heights),
        output,
    )
    return dataset
