"""Block and transaction consensus validation rules."""

from __future__ import annotations

from bitcoin_script.blockchain.utxo import UTXOSet
from bitcoin_script.model.block import Block
from bitcoin_script.model.transaction import Transaction


def validate_block(block: Block, prev_block_hash: bytes, height: int) -> bool:
    """Validate a block against consensus rules.

    Checks:
    - Proof of work (block hash <= target)
    - Previous block hash linkage
    - Merkle root integrity
    - Timestamp constraints
    - Transaction validity

    Args:
        block: The block to validate.
        prev_block_hash: Expected previous block hash.
        height: The block height (for coinbase maturity, subsidy, etc.).

    Returns:
        True if the block is valid.
    """
    ...


def validate_transaction(
    tx: Transaction,
    utxo_set: UTXOSet,
    block_height: int,
    is_coinbase: bool = False,
) -> bool:
    """Validate a transaction against consensus rules.

    Checks:
    - Input references exist in UTXO set (except coinbase)
    - Script verification passes for each input
    - No double-spends within the transaction
    - Value conservation (sum inputs >= sum outputs)
    - Coinbase maturity

    Args:
        tx: The transaction to validate.
        utxo_set: Current UTXO set for input lookups.
        block_height: Current block height.
        is_coinbase: Whether this is a coinbase transaction.

    Returns:
        True if the transaction is valid.
    """
    ...


def calculate_block_subsidy(height: int) -> int:
    """Calculate the block subsidy (coinbase reward) at a given height.

    Starts at 50 BTC (5_000_000_000 satoshis), halves every 210,000 blocks.

    Args:
        height: Block height.

    Returns:
        Subsidy in satoshis.
    """
    ...
