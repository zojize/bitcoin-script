# blockchain

Real Bitcoin blockchain data access: downloading, parsing, and validation from genesis.

- `downloader.py` — `BlockchainDownloader` acquires blocks via Bitcoin Core RPC or reads from a local data directory. Supports downloading a range of block heights.
- `parser.py` — `BlockFileParser` reads Bitcoin Core's `.blk` dat files (4-byte magic `0xF9BEB4D9` + 4-byte size + raw block, repeated) and yields `Block` model objects.
- `utxo.py` — `UTXOSet` tracks unspent transaction outputs in a dict keyed by `OutPoint`. Supports add, spend, get, and contains operations for chain validation.
- `validation.py` — Consensus rule enforcement: proof-of-work, prev-hash linkage, Merkle root integrity, script verification for each input, value conservation, and block subsidy calculation (50 BTC halving every 210,000 blocks).

## Prerequisites

Install Bitcoin Core via Homebrew (macOS) or from [bitcoincore.org](https://bitcoincore.org/en/download/):

```bash
brew install bitcoin
```

## Running a mainnet node

1. **Configure RPC credentials** — create or edit your `bitcoin.conf`
   (`~/Library/Application Support/Bitcoin/bitcoin.conf` on macOS,
   `~/.bitcoin/bitcoin.conf` on Linux):

   ```ini
   server=1
   rpcuser=<your-username>
   rpcpassword=<your-password>
   ```

2. **Start the node**:

   ```bash
   bitcoind -daemon
   ```

3. **Monitor sync progress** — the initial block download (IBD) syncs the full
   blockchain and can take several hours to days depending on your hardware and
   connection:

   ```bash
   bitcoin-cli getblockchaininfo
   ```

   Look for `"verificationprogress"` approaching `1.0`. You can start fetching
   blocks that have already been downloaded even while IBD is in progress.

4. **Stop the node** when you're done:

   ```bash
   bitcoin-cli stop
   ```

   This gracefully shuts down `bitcoind`. If you configured custom RPC
   credentials, pass them explicitly:

   ```bash
   bitcoin-cli -rpcuser=<your-username> -rpcpassword=<your-password> stop
   ```

## Quick start

Fetch the mainnet genesis block from a running Bitcoin Core node:

```python
from bitcoin_script.blockchain.downloader import BlockchainDownloader

dl = BlockchainDownloader.from_url("http://user:pass@127.0.0.1:8332")

# Genesis block as a decoded dict
genesis = dl.get_block(0, verbosity=1)
print(genesis["hash"])      # 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
print(genesis["tx"][0])     # coinbase txid

# Raw serialised block hex
raw_hex = dl.get_block_raw(0)

# Download a range of blocks
blocks = dl.download_blocks(start_height=0, end_height=9)
for b in blocks:
    print(f"Block {b['height']}: {b['hash']}")
```

Replace `user:pass` with your `rpcuser` / `rpcpassword` from `bitcoin.conf`.

There is also a runnable demo script at `scripts/demo_downloader.py`.
Without `BITCOIN_RPC_URL` set it spins up a temporary regtest node automatically:

```bash
# Regtest (no mainnet node required)
uv run python scripts/demo_downloader.py

# Mainnet
BITCOIN_RPC_URL=http://user:pass@127.0.0.1:8332 uv run python scripts/demo_downloader.py
```
