"""Verify a real Bitcoin mainnet block through formal semantics.

This is the most direct demonstration of formal verification applied to
production systems: take a real block from the Bitcoin blockchain, and
verify every single script execution through the K Framework semantics.

If K agrees with the Bitcoin network on every transaction in every block,
it provides strong evidence that the formal model captures Bitcoin's
actual consensus rules — or reveals divergences that could indicate
consensus bugs.

Usage:
    # Verify block 170 (first real transaction: Satoshi -> Hal Finney)
    uv run python examples/verify_block.py 170

    # Verify a range of blocks
    uv run python examples/verify_block.py 170 180

Requires: synced Bitcoin Core node (for local .blk files).
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

from bitcoin_script.blockchain.verifier import ChainVerifier


def default_bitcoin_dir() -> Path:
    """Auto-detect the Bitcoin Core data directory."""
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Bitcoin"
    return Path.home() / ".bitcoin"


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: verify_block.py <height> [end_height]")
        print()
        print("Examples:")
        print("  verify_block.py 170       # Block 170 (first real tx)")
        print("  verify_block.py 170 180   # Blocks 170-180")
        print("  verify_block.py 0 999     # First 1000 blocks")
        sys.exit(1)

    height = int(sys.argv[1])
    end_height = int(sys.argv[2]) if len(sys.argv) > 2 else height

    data_dir = default_bitcoin_dir()
    if not (data_dir / "blocks" / "blk00000.dat").exists():
        print(f"Block files not found at {data_dir}/blocks/")
        print("Sync a Bitcoin Core node first: bitcoind -daemon")
        sys.exit(1)

    print(f"Initializing verifier (K Framework + UTXO database)...")
    t0 = time.monotonic()
    verifier = ChainVerifier(data_dir, utxo_db_path=":memory:")

    if height == end_height:
        print(f"Verifying block {height}...")
        # Need to build UTXO up to height-1
        if height > 0:
            print(f"  Building UTXO set (blocks 0-{height - 1})...")
            pre = verifier.verify_chain(start=0, end=height - 1)
            if not pre.ok:
                print(f"  Failed: {pre.errors[0]}")
                sys.exit(1)
            print(f"  UTXO set: {verifier.utxo.size()} outputs")

        result = verifier.verify_block(height)
        elapsed = time.monotonic() - t0

        print(f"\nBlock {height}:")
        print(f"  Transactions: {result.tx_count}")
        print(f"  Inputs verified: {result.input_count}")
        print(f"  Time: {elapsed:.1f}s")
        print(f"  Result: {'OK' if result.ok else 'FAILED'}")

        if not result.ok:
            for e in result.errors:
                print(f"  ERROR: {e}")
            sys.exit(1)
    else:
        print(f"Verifying blocks {height}-{end_height}...")
        result = verifier.verify_chain(start=height, end=end_height)
        elapsed = time.monotonic() - t0

        print(f"\nBlocks {height}-{end_height}:")
        print(f"  Blocks verified: {result.blocks_verified}")
        print(f"  Inputs verified: {result.inputs_verified}")
        print(f"  Time: {elapsed:.1f}s")
        print(f"  UTXO set size: {verifier.utxo.size()}")
        print(f"  Result: {'OK' if result.ok else 'FAILED'}")

        if not result.ok:
            for e in result.errors[:5]:
                print(f"  ERROR: {e}")
            sys.exit(1)

    print("\nFormal verification complete. K semantics agree with Bitcoin consensus.")


if __name__ == "__main__":
    main()
