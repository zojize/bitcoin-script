# Bitcoin Script

Bitcoin Script interpreter and formal verification toolkit. The K Framework semantics pass **all 1,217 of Bitcoin Core's `script_tests.json` vectors** (including full SegWit), plus **174 of 214 transaction vectors** (including OP_CODESEPARATOR), and have been used to **formally verify 129,000+ mainnet blocks** with zero errors.

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
| script_tests.json (witness) | 108 | 113 | SegWit P2WSH/P2WPKH/P2SH-wrapped (5 taproot xfailed) |
| tx_valid.json | 115 | 121 | Real transaction verification |
| tx_invalid.json | 59 | 93 | Invalid transaction rejection (9 BADTX, 25 CONST_SCRIPTCODE xfailed) |
| Mainnet blocks 0-129,379 | 581,000+ inputs | 581,000+ inputs | Zero errors |

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

## Architecture

The K semantics define Bitcoin Script execution as a term-rewriting system:

1. **Decoder** (`script-decode.k`): reads raw script bytes into K opcode terms
2. **Execution**: each opcode has rewriting rules that modify the configuration (stack, altstack, exec-guard stack, flags, phase)
3. **Phases**: scriptSig → scriptPubKey → P2SH redeem → witness-v0
4. **Verification**: sighash computed in Python, passed to K; ECDSA verification via blockchain-k-plugin C++ hooks

The `ChainVerifier` orchestrates block-by-block verification:
1. Load blocks from `.blk` files, order by prev-hash chain linkage
2. For each non-coinbase input: look up UTXO, compute sighash, invoke K
3. Update UTXO set (spend inputs, add outputs)
4. Checkpoint progress to SQLite for resume
