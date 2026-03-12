# blockchain

Real Bitcoin blockchain data access: downloading, parsing, and validation from genesis.

- `downloader.py` — `BlockchainDownloader` acquires blocks via Bitcoin Core RPC or reads from a local data directory. Supports downloading a range of block heights.
- `parser.py` — `BlockFileParser` reads Bitcoin Core's `.blk` dat files (4-byte magic `0xF9BEB4D9` + 4-byte size + raw block, repeated) and yields `Block` model objects.
- `utxo.py` — `UTXOSet` tracks unspent transaction outputs in a dict keyed by `OutPoint`. Supports add, spend, get, and contains operations for chain validation.
- `validation.py` — Consensus rule enforcement: proof-of-work, prev-hash linkage, Merkle root integrity, script verification for each input, value conservation, and block subsidy calculation (50 BTC halving every 210,000 blocks).
