# Bitcoin Script

A fully-typed Bitcoin Script interpreter in Python, with plans for formal verification via the [K Framework](https://kframework.org/) and real blockchain validation from genesis.

## Goals

1. **Python interpreter** — Stack-based VM executing all standard Bitcoin Script opcodes, supporting P2PKH, P2SH, P2WPKH, and P2WSH script types.
2. **Blockchain verification** — Download and validate the Bitcoin blockchain from the genesis block, maintaining a UTXO set and enforcing consensus rules.
3. **Formal semantics** — Define Bitcoin Script semantics in K and use [pyk](https://github.com/runtimeverification/pyk) to cross-verify against the Python implementation.

## Project Structure

```text
src/bitcoin_script/
    opcodes/        # Opcode enum and category groupings
    model/          # Transaction, Script, Block data structures
    engine/         # Stack VM, interpreter loop, opcode handlers
    script_types/   # P2PKH/P2SH/P2WPKH/P2WSH classification
    crypto/         # Hashing, ECDSA verification, DER parsing
    blockchain/     # Block downloading, parsing, UTXO, validation
    k_semantics/    # K Framework formal semantics (P2PK, P2PKH, multisig)
```

## Setup

Requires Python 3.14+ and [uv](https://docs.astral.sh/uv/).

```sh
uv sync
```

### K Framework

The formal K semantics require the [K Framework](https://kframework.org/) and native dependencies for the crypto plugin.

#### Install K Framework

Install [kup](https://github.com/runtimeverification/kup) (the K package manager), then install K:

```sh
bash <(curl https://kframework.org/install)
kup install k
```

#### Install native dependencies

The [blockchain-k-plugin](https://github.com/runtimeverification/blockchain-k-plugin) needs several C/C++ libraries for cryptographic operations.

**macOS (Homebrew):**

```sh
brew install cmake boost openssl libsecp256k1 gmp mpfr crypto++
```

**Ubuntu/Debian:**

```sh
sudo apt-get install -y \
  clang cmake pkg-config \
  libboost-test-dev libcrypto++-dev libsecp256k1-dev \
  libssl-dev libyaml-dev libgmp-dev libmpfr-dev \
  llvm-dev
```

#### Initialize submodules, build, and test

```sh
git submodule update --init --recursive
uv run kdist build bitcoin-script-semantics.llvm
uv run pytest -m k -v
```

## Development

```sh
uv run pytest              # run tests (excludes K tests by default)
uv run pytest -m k         # run K Framework tests
uv run ruff check src/     # linting
uv run ruff format src/    # formatting
uv run pyright src/        # type checking
```
