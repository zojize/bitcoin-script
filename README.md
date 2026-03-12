# Bitcoin Script

A fully-typed Bitcoin Script interpreter in Python, with plans for formal verification via the [K Framework](https://kframework.org/) and real blockchain validation from genesis.

## Goals

1. **Python interpreter** — Stack-based VM executing all standard Bitcoin Script opcodes, supporting P2PKH, P2SH, P2WPKH, and P2WSH script types.
2. **Blockchain verification** — Download and validate the Bitcoin blockchain from the genesis block, maintaining a UTXO set and enforcing consensus rules.
3. **Formal semantics** — Define Bitcoin Script semantics in K and use [pyk](https://github.com/runtimeverification/pyk) to cross-verify against the Python implementation.

## Project Structure

```
src/bitcoin_script/
    opcodes/        # Opcode enum and category groupings
    model/          # Transaction, Script, Block data structures
    engine/         # Stack VM, interpreter loop, opcode handlers
    script_types/   # P2PKH/P2SH/P2WPKH/P2WSH classification
    crypto/         # Hashing, ECDSA verification, DER parsing
    blockchain/     # Block downloading, parsing, UTXO, validation
    k_semantics/    # K Framework integration (future)
```

## Setup

Requires Python 3.13+ and [uv](https://docs.astral.sh/uv/).

```sh
uv sync
```

## Development

```sh
uv run pytest              # run tests
uv run mypy src/           # type checking
uv run ruff check src/     # linting
```
