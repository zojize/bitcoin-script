# Bitcoin Script

Bitcoin Script interpreter and formal verification toolkit. The K Framework semantics pass all 1,217 of Bitcoin Core's script_tests.json vectors (including SegWit) and have verified 100,000+ mainnet blocks with zero errors.

## Folder structure

```text
src/bitcoin_script/
  cli.py              # Typer CLI: `bitcoin-script verify` command
  blockchain/         # Block parsing, UTXO tracking, chain verification
    verifier.py       # ChainVerifier: block-by-block K verification
    parser.py         # BlockFileParser: read .blk files
    utxo.py           # SQLite-backed UTXO set
    flags.py          # Consensus flag activation schedule (P2SH → SegWit)
    downloader.py     # RPC-based block fetching
  k_semantics/        # K Framework integration
    semantics.py      # Python wrapper: ScriptDist, KBitcoinScript
    kdist/
      plugin.py       # kdist build targets (source, plugin, llvm, llvm-lib)
      plugin/         # blockchain-k-plugin submodule (forked: zojize/blockchain-k-plugin)
      script-semantics/
        script-semantics.k  # Config, phases, witness program detection, P2SH/SegWit
        script-sig.k        # CHECKSIG, CHECKMULTISIG with encoding validation
        script-flow.k       # IF/ELSE/ENDIF, NOP, CLTV/CSV, MINIMALIF
        script-crypto.k     # DER validation, sighash lookup, ECDSA, LOW_S
        script-num.k        # CScriptNum encoding/decoding
        script-arith.k      # Arithmetic opcodes
        script-stack.k      # Stack manipulation opcodes
        script-decode.k     # Byte-level script decoder
        script-syntax.k     # OpCode sort declarations
        script.k            # Top-level module imports
  engine/             # Python interpreter (stubbed, not used for verification)

tests/
  test_k_semantics/   # K semantics tests (marked @pytest.mark.k)
    test_script_vectors.py  # Bitcoin Core script_tests.json (1,217 passing, 5 taproot xfail)
    test_tx_vectors.py      # Bitcoin Core tx_valid/tx_invalid (133 passing, 81 xfail)
    tx_sighash.py           # Sighash computation for real transactions
    conftest.py             # Session fixtures, sighash for test vectors
    bitcoin_core_vectors.py # ASM parser, xfail classifier
  test_blockchain/   # UTXO, flags, parser, verifier tests
  test_engine/       # Python engine unit tests

scripts/
  demo_verify.py     # Mainnet verification demo
  demo_parser.py     # Block file parsing demo
  demo_downloader.py # RPC download demo
```

## Tech stack

- **Python 3.14**, managed with `uv`
- **K Framework** (`pyk` library) for formal semantics, compiled to LLVM backend
- **blockchain-k-plugin** (forked) for crypto hooks (SHA256, SHA1, RIPEMD160, ECDSA)
- **pytest** for testing, **ruff** for linting/formatting, **pyright** for type checking
- **Typer** for CLI
- **just** as task runner (`justfile`); all tools run via `uv run`

## Key commands

```sh
just test                    # Run tests (excludes rpc, k, mainnet markers)
just test-k                  # Run K Framework tests only
just test-all                # Run all tests
just fix                     # Auto-fix lint + format
just check                   # Lint + format + typecheck (no fix)
kdist build --force          # Rebuild K semantics after .k file changes
uv run bitcoin-script verify --end 1000  # Verify mainnet blocks via CLI
```

## Code preferences

- Python target: 3.14. Use `from __future__ import annotations`.
- Formatting and linting: ruff. Exclude `kdist/plugin/deps` from all tools.
- K semantics `.k` files: conditional execution (IF/ELSE/ENDIF) is enforced centrally via `#guardExec(OP)` wrappers in the decoder. Individual opcode execution rules do NOT need `#allTrue(EX)` guards. Flow control opcodes (IF, NOTIF, ELSE, ENDIF) and OP_INVALIDOPCODE are emitted directly by the decoder without wrapping.
- Scripts are passed as raw bytes via config variables `$SCRIPTSIG` and `$SCRIPTPUBKEY`, never as ASM text.
- Multi-phase execution: scriptSig -> scriptPubKey -> (optional) P2SH redeem -> (optional) witness-v0, controlled by a `Phase` sort.
- `_rebuild_if_stale()` in `semantics.py` auto-rebuilds when `.k` sources change, but explicit `kdist build --force` is more reliable during development.
- K rule overlap: the LLVM backend requires non-overlapping rules. Use helper functions (e.g. `#msEncOK`) and explicit exclusion conditions to prevent ambiguous matching.

## Testing

- `pytest.mark.k` — requires K Framework and compiled definition. Run with `just test-k`.
- `pytest.mark.rpc` — requires running Bitcoin Core node. Excluded by default.
- `pytest.mark.mainnet` — requires Bitcoin Core mainnet block files + K Framework. Excluded by default.
- Default `pytest` excludes `k`, `rpc`, and `mainnet` markers.
- K test fixtures are session-scoped (`_dist`, `k`, `k_hex` in conftest.py).
- Bitcoin Core test vectors are downloaded on first run to `tests/test_k_semantics/data/` (gitignored).
- `classify_vector()` in `bitcoin_core_vectors.py` returns xfail reasons for unimplemented features.
- tx_valid/tx_invalid use "excluded flags" format: all flags active minus the listed ones.

## Consensus flags implemented

P2SH, DERSIG, STRICTENC, LOW_S, NULLDUMMY, SIGPUSHONLY, MINIMALDATA, DISCOURAGE_UPGRADABLE_NOPS, CLEANSTACK, CHECKLOCKTIMEVERIFY, CHECKSEQUENCEVERIFY, WITNESS, DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, MINIMALIF, NULLFAIL, WITNESS_PUBKEYTYPE.

## Known gaps

- **CONST_SCRIPTCODE**: enforced — prohibits OP_CODESEPARATOR in base (non-witness) phases.
- **Taproot (BIP 341/342)**: not implemented (5 test vectors xfailed).
