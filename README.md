# Bitcoin Script

Bitcoin Script interpreter and formal verification toolkit. The K Framework semantics implement **full BIP 341/342 Taproot/Tapscript support** including Schnorr signatures, key-path and script-path spending, OP_CHECKSIGADD, OP_SUCCESS opcodes, and signature validation weight budgets. The semantics pass **all 1,222 of Bitcoin Core's `script_tests.json` vectors** (including SegWit and Taproot), plus **174 of 214 transaction vectors**, and have been **benchmarked on 300,000+ real mainnet inputs** across all consensus eras — including 80,000+ taproot transactions — with zero errors.

## What this does

The project defines Bitcoin Script's semantics in the [K Framework](https://kframework.org/), compiles them to an LLVM backend, and uses that to verify real Bitcoin transactions. Every script execution — scriptSig, scriptPubKey, witness, P2SH redeem — is run through the formal semantics.

### Mainnet verification

```sh
# Verify the first 1000 blocks of Bitcoin mainnet
uv run bitcoin-script verify --end 1000

# Verify a single block (e.g. block 170: first real transaction)
uv run bitcoin-script verify --block 170
```

Requires a synced Bitcoin Core node (for local `.blk` files). See [Setup](#setup) below.

### Test vector coverage

| Test suite | Passing | Total | Notes |
|-----------|---------|-------|-------|
| script_tests.json (standard) | 1,109 | 1,109 | All opcodes, flags, edge cases |
| script_tests.json (witness) | 113 | 113 | SegWit + Taproot (P2WSH/P2WPKH/P2TR) |
| tx_valid.json | 115 | 121 | Real transaction verification |
| tx_invalid.json | 59 | 93 | Invalid transaction rejection (9 BADTX, 25 xfailed) |
| Tapscript opcodes | 9 | 9 | CHECKSIGADD, disabled CHECKMULTISIG, OP_SUCCESS |
| Taproot coverage | 26 | 26 | Key-path sigs, control blocks, annex, Schnorr verify |
| Sigops weight budget | 7 | 7 | BIP 342 resource accounting |
| Mainnet benchmark | 300,836 inputs | 300,836 | All eras including taproot — zero errors |

## Project structure

```text
src/bitcoin_script/
    cli.py            # Typer CLI (verify command)
    blockchain/       # Block parsing, UTXO tracking, chain verification
      parser.py       # Read Bitcoin Core .blk files
      utxo.py         # SQLite-backed UTXO set
      flags.py        # Consensus flag activation schedule
      verifier.py     # ChainVerifier: block-by-block K verification
      downloader.py   # RPC-based block fetching
    k_semantics/      # K Framework formal semantics
      semantics.py    # Python wrapper: KBitcoinScript
      kdist/
        plugin.py     # Build targets (source, plugin, llvm)
        plugin/       # blockchain-k-plugin (crypto hooks: ECDSA, SHA256, etc.)
        script-semantics/
          script-semantics.k  # Config, phases, witness, P2SH
          script-sig.k        # CHECKSIG, CHECKMULTISIG
          script-flow.k       # IF/ELSE/ENDIF, NOP, CLTV/CSV
          script-crypto.k     # DER validation, sighash, ECDSA
          script-num.k        # CScriptNum encoding
          script-arith.k      # Arithmetic opcodes
          script-stack.k      # Stack manipulation
          script-decode.k     # Byte-level script decoder
          script-syntax.k     # OpCode declarations
    engine/           # Python interpreter (stubbed)

tests/
    test_k_semantics/ # K Framework tests
    test_blockchain/  # Block parser, UTXO, flag schedule tests
    test_engine/      # Python engine tests

scripts/
    demo_verify.py    # Mainnet verification demo
    demo_parser.py    # Block file parsing demo
    demo_downloader.py # RPC download demo
```

## Setup

Requires Python 3.14+ and [uv](https://docs.astral.sh/uv/).

```sh
uv sync
```

### K Framework

```sh
# Install K Framework
bash <(curl https://kframework.org/install)
kup install k

# Install native dependencies (macOS)
brew install cmake boost openssl libsecp256k1 gmp mpfr crypto++

# Build K semantics
git submodule update --init --recursive
uv run kdist build bitcoin-script-semantics.llvm
```

### Bitcoin Core (for mainnet verification)

```sh
brew install bitcoin
bitcoind -daemon    # start node, wait for sync
```

## CLI

```sh
# Verify mainnet blocks (requires synced Bitcoin Core)
uv run bitcoin-script verify --end 1000
uv run bitcoin-script verify --block 170
uv run bitcoin-script verify --start 500 --end 999

# Resume from checkpoint (UTXO state persisted in utxo.db)
uv run bitcoin-script verify --end 50000 --db chain.db
```

## Development

```sh
uv run pytest                    # unit tests (no K required)
uv run pytest -m k               # K Framework tests
uv run pytest -m mainnet         # mainnet verification tests
uv run ruff check src/ && uv run ruff format src/
uv run pyright src/
uv run kdist build --force       # rebuild K semantics after .k changes
```

## Benchmark

K Framework verification benchmarked on **300,836 real mainnet inputs** spanning all consensus eras from genesis through Taproot.

| Era | Inputs | K median | K P95 |
|-----|--------|----------|-------|
| pre-P2SH | 286 | 0.69ms | 1.81ms |
| P2SH | 8,840 | 0.70ms | 1.14ms |
| DERSIG | 59,509 | 0.68ms | 1.21ms |
| CLTV | 42,192 | 0.75ms | 1.52ms |
| CSV | 39,381 | 0.76ms | 1.43ms |
| SegWit | 70,132 | 0.82ms | 1.37ms |
| **Taproot** | **80,496** | **0.79ms** | **1.34ms** |

Zero errors across all 300,836 inputs including 80,496 taproot transactions (key-path + script-path). Throughput: ~1,300 inputs/sec single-core via FFI.

### Running the benchmark

```sh
# Extract dataset from esplora API (no node required, includes taproot)
uv run bitcoin-script benchmark extract --source api

# Or from local Bitcoin Core block files (requires synced node)
uv run bitcoin-script benchmark extract --blocks-dir ~/.bitcoin

# Run the benchmark
uv run bitcoin-script benchmark run --k-only

# Generate a summary report
uv run bitcoin-script benchmark report
```

K verification uses direct FFI to the compiled LLVM interpreter (`interpreter.dylib` from the `llvm-lib` kdist target) via ctypes.

## Architecture

The K semantics define Bitcoin Script execution as a term-rewriting system:

1. **Decoder** (`script-decode.k`): reads raw script bytes into K opcode terms
2. **Execution**: each opcode has rewriting rules that modify the configuration (stack, altstack, exec-guard stack, flags, phase)
3. **Phases**: scriptSig → scriptPubKey → P2SH redeem → witness-v0 → witness-v1 (tapscript)
4. **Verification**: sighash computed in Python, passed to K; ECDSA/Schnorr verification via blockchain-k-plugin C++ hooks
5. **Resource accounting**: `<sigopsWeight>` cell tracks BIP 342 signature validation budget (analogous to KEVM's gas model)

The `ChainVerifier` orchestrates block-by-block verification:
1. Load blocks from `.blk` files, order by prev-hash chain linkage
2. For each non-coinbase input: look up UTXO, compute sighash, invoke K
3. Update UTXO set (spend inputs, add outputs)
4. Checkpoint progress to SQLite for resume
