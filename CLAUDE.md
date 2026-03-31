# Bitcoin Script

Bitcoin Script interpreter and formal verification toolkit. Two parallel implementations: a Python engine and a K Framework formal semantics, both validated against Bitcoin Core's official test vectors.

## Folder structure

```text
src/bitcoin_script/
  engine/           # Python script interpreter (engine.py, operations.py, stack.py)
  blockchain/       # Block downloader, parser, UTXO tracking, validation
  k_semantics/      # K Framework integration
    semantics.py    # Python wrapper: ScriptDist (locates artifacts), KBitcoinScript (runs scripts)
    kdist/
      plugin.py     # kdist build targets (source, plugin, llvm, llvm-lib)
      script-semantics/
        script-semantics.k  # Core semantics: config, decoder, opcodes, phase transitions
        script-syntax.k     # OpCode sort declarations
        script-num.k        # CScriptNum arithmetic helpers
        script-arith.k      # Arithmetic opcode rules
        script-stack.k      # Stack manipulation opcode rules
        script-crypto.k     # Hash opcode rules (SHA256, HASH160, etc.)
        script.k            # Top-level module imports
  cli.py            # Typer CLI entry point

tests/
  test_engine/      # Python engine unit tests
  test_blockchain/  # Downloader/parser/validation tests
  test_k_semantics/ # K semantics tests (marked with @pytest.mark.k)
    conftest.py     # Session fixtures: ScriptDist, KBitcoinScript, vector downloader
    script_helpers.py       # OPCODES dict, hex encoding helpers
    bitcoin_core_vectors.py # Bitcoin Core ASM parser, xfail classifier
    test_script_vectors.py  # Parametrized Bitcoin Core script_tests.json (534 pass, 575 xfail)
    test_tx_vectors.py      # Bitcoin Core tx_valid/tx_invalid (all skipped, needs tx deser)
    test_*.py               # Unit tests per opcode category
```

## Tech stack

- **Python 3.14**, managed with `uv`
- **K Framework** (`pyk` library) for formal semantics, compiled to LLVM backend
- **blockchain-k-plugin** for crypto hooks (SHA256, RIPEMD160, ECDSA)
- **pytest** for testing, **ruff** for linting/formatting, **pyright** for type checking
- **just** as task runner (`justfile`); all tools run via `uv run`

## Key commands

```sh
just test          # Run tests (excludes rpc and k markers)
just test-k        # Run K Framework tests only
just test-all      # Run all tests
just fix           # Auto-fix lint + format
just check         # Lint + format + typecheck (no fix)
kdist build --force  # Rebuild K semantics after .k file changes
```

## Code preferences

- Python target: 3.14. Use `from __future__ import annotations`.
- Formatting and linting: ruff. Exclude `kdist/plugin/deps` from all tools.
- K semantics `.k` files: conditional execution (IF/ELSE/ENDIF) is enforced centrally via `#guardExec(OP)` wrappers in the decoder. Individual opcode execution rules do NOT need `#allTrue(EX)` guards. Flow control opcodes (IF, NOTIF, ELSE, ENDIF) and OP_INVALIDOPCODE are emitted directly by the decoder without wrapping.
- Scripts are passed as raw bytes via config variables `$SCRIPTSIG` and `$SCRIPTPUBKEY`, never as ASM text.
- Multi-phase execution: scriptSig -> scriptPubKey -> (optional) P2SH redeem, controlled by a `Phase` sort.
- `_rebuild_if_stale()` in `semantics.py` auto-rebuilds when `.k` sources change, but explicit `kdist build --force` is more reliable during development.

## Testing

- `pytest.mark.k` — requires K Framework and compiled definition. Run with `just test-k`.
- `pytest.mark.rpc` — requires running Bitcoin Core node. Excluded by default.
- Default `pytest` excludes both `k` and `rpc` markers.
- K test fixtures are session-scoped (`_dist`, `k`, `k_hex` in conftest.py).
- Bitcoin Core test vectors are downloaded on first run to `tests/test_k_semantics/data/` (gitignored).
- `classify_vector()` in `bitcoin_core_vectors.py` returns xfail reasons for unimplemented features (sig ops, CLTV/CSV, disabled opcodes, etc.).
