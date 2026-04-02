#!/usr/bin/env python3
"""Demo: verify Bitcoin mainnet blocks via K Framework formal semantics.

Reads blocks from Bitcoin Core's local .blk files, builds a UTXO set,
and formally verifies every script execution for every transaction input
using the K Framework LLVM backend.

Usage:
    uv run python scripts/demo_verify.py              # verify first 1000 blocks
    uv run python scripts/demo_verify.py 5000          # verify first 5000 blocks
    uv run python scripts/demo_verify.py 170 170       # verify just block 170

Or via the CLI:
    uv run bitcoin-script verify --end 1000
    uv run bitcoin-script verify --block 170
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(message)s",
    datefmt="%H:%M:%S",
)


def main() -> None:
    # Auto-detect Bitcoin Core data directory
    if sys.platform == "darwin":
        data_dir = Path.home() / "Library" / "Application Support" / "Bitcoin"
    else:
        data_dir = Path.home() / ".bitcoin"

    if not (data_dir / "blocks" / "blk00000.dat").exists():
        print(f"Bitcoin Core block files not found at {data_dir}")
        print("Sync a Bitcoin Core node first, or set the path manually.")
        sys.exit(1)

    # Parse args
    end_height = int(sys.argv[1]) if len(sys.argv) > 1 else 999
    start_height = int(sys.argv[2]) if len(sys.argv) > 2 else 0

    from bitcoin_script.blockchain.verifier import ChainVerifier

    print(f"Verifying mainnet blocks {start_height}-{end_height}")
    print(f"Data directory: {data_dir}")
    print()

    verifier = ChainVerifier(data_dir)
    result = verifier.verify_chain(start=start_height, end=end_height)

    print()
    print(f"{'OK' if result.ok else 'FAILED'}")
    print(f"  Blocks verified: {result.blocks_verified}")
    print(f"  Inputs verified: {result.inputs_verified}")
    print(f"  UTXO set size:   {verifier.utxo.size()}")
    print(f"  Elapsed:         {result.elapsed_s:.1f}s")

    if result.errors:
        print(f"  Errors:          {len(result.errors)}")
        for e in result.errors[:5]:
            print(f"    {e}")

    sys.exit(0 if result.ok else 1)


if __name__ == "__main__":
    main()
