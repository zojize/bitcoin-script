# blockchain

Bitcoin blockchain data access, UTXO tracking, and formal script verification.

## Modules

- **`verifier.py`** — `ChainVerifier` orchestrates block-by-block script verification via K Framework. Reads `.blk` files, builds UTXO set, computes sighash, and invokes K for every transaction input. Supports single-block and chain-range verification with SQLite checkpointing.
- **`parser.py`** — `BlockFileParser` reads Bitcoin Core's `.blk` dat files with XOR deobfuscation support (v28+). Use `iter_blocks(start=N)` to skip blocks efficiently.
- **`utxo.py`** — `UTXOSet` tracks unspent transaction outputs in SQLite. Supports add, spend, get, commit, and checkpoint/resume.
- **`flags.py`** — `flags_for_block(height, timestamp)` returns the bitmask of active consensus verification flags at a given block, covering P2SH through SegWit activation.
- **`downloader.py`** — `BlockchainDownloader` fetches blocks via Bitcoin Core RPC.

## Quick start

### Verify mainnet blocks via CLI

```sh
# First 1000 blocks
uv run bitcoin-script verify --end 1000

# Single block (block 170: first real transaction)
uv run bitcoin-script verify --block 170

# Resume from checkpoint
uv run bitcoin-script verify --end 50000 --db chain.db
```

### Python API

```python
from pathlib import Path
from bitcoin_script.blockchain.verifier import ChainVerifier

verifier = ChainVerifier(Path.home() / "Library/Application Support/Bitcoin")

# Verify a range of blocks
result = verifier.verify_chain(start=0, end=999)
print(f"{result.blocks_verified} blocks, {result.inputs_verified} inputs, OK={result.ok}")

# Verify a single block (UTXO must be built up to height-1)
block_result = verifier.verify_block(170)
print(f"Block 170: {block_result.input_count} inputs, OK={block_result.ok}")
```

### Parse local block files

```python
from pathlib import Path
from itertools import islice
from bitcoin_script.blockchain.parser import BlockFileParser

parser = BlockFileParser(Path.home() / "Library/Application Support/Bitcoin")

for block in islice(parser, 10):
    print(block.GetHash()[::-1].hex())
```

## Prerequisites

Install Bitcoin Core and sync the blockchain:

```sh
brew install bitcoin
bitcoind -daemon
bitcoin-cli getblockchaininfo  # wait for sync
```

The block files are stored at `~/Library/Application Support/Bitcoin/blocks/` (macOS) or `~/.bitcoin/blocks/` (Linux).
