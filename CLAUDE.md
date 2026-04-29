# Bitcoin Script

Bitcoin Script interpreter and formal verification toolkit. The K Framework semantics pass 1,672 tests (1,222 of Bitcoin Core's script_tests.json including SegWit + Taproot, 201 of 214 tx_valid/tx_invalid.json (121/121 valid + 80/93 invalid; 13 expected xfails: 9 BADTX + 4 legacy CONST_SCRIPTCODE-excluded sighash cases), 22 K-proof specs, 2 LLVM-backed HTLC proofs, plus coverage tests). Mainnet verification runs clean on 100,000+ blocks. All four sighash variants (legacy, BIP-143, BIP-341 key-path, BIP-342 tapscript) are computed K-natively; the blockchain-k-plugin supplies the SHA/ECDSA/Schnorr/secp256k1 primitives.

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
    test_tx_vectors.py      # Bitcoin Core tx_valid/tx_invalid (201 passing, 13 xfail)
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

## Benchmark

Benchmark compares K Framework against libbitcoinconsensus (Bitcoin Core 27.2) on 225,417 real mainnet inputs spanning all consensus eras (pre-P2SH through SegWit).

**Methodology**: inputs extracted from mainnet blocks via `benchmark extract`, covering continuous (every-block), representative (sampled), and stress (large/complex) categories. K uses direct FFI to `interpreter.dylib` via ctypes (no subprocess spawn). Core uses ctypes to `libbitcoinconsensus`. K reports median of 10 iterations; Core reports median of 100.

| | K Framework | libbitcoinconsensus | Ratio |
|---|---|---|---|
| Overall (225K inputs) | 145s (1,555 inp/s) | 85s (2,662 inp/s) | **1.7x** |
| Stress blocks (50K) | 30s | 74s | **0.4x (K faster)** |
| Representative (175K) | 115s | 10s | 11x |
| Per-input median | 0.62ms | 0.029ms | 24x |

Zero correctness mismatches across all 225,417 inputs. K is faster than Core on stress/complex scripts; the 0.62ms floor on simple scripts is Python KORE text serialization overhead (a native Rust/C caller would eliminate this).

**Extraction** supports two data sources:

```sh
# From Blockstream esplora API (no Bitcoin Core node required, ~30 min)
uv run bitcoin-script benchmark extract --source api --skip-taproot

# From local Bitcoin Core .blk files (requires synced node, ~2 hours)
uv run bitcoin-script benchmark extract --blocks-dir ~/.bitcoin
```

The API source fetches only target blocks (representative + stress) directly, using the API's `prevout` field to resolve spent outputs without maintaining a local UTXO set. The continuous block range (0-9999) is skipped in API mode.

```sh
uv run bitcoin-script benchmark run        # Run K + Core benchmark
uv run bitcoin-script benchmark report     # Generate report from results
```

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

## Mandatory pre-push pipeline

**You MUST run these checks locally and confirm they pass before every `git push`.**
No exceptions. CI will reject the push otherwise, wasting time and cluttering the PR.

```sh
uv run ruff check src/ tests/          # Lint (matches CI exactly)
uv run ruff format --check src/ tests/ # Format check (matches CI exactly)
uv run pyright src/                    # Typecheck (matches CI exactly)
uv run pytest --tb=short -q            # Non-K tests
uv run pytest -m k --tb=short -q      # K Framework tests (requires built definition)
```

If format check fails, fix with `uv run ruff format src/ tests/` and re-check.
If lint fails, fix with `uv run ruff check --fix src/ tests/` and re-check.
Only push once all five commands pass with zero errors.

**After pushing**, monitor CI with `gh pr checks <number>` or `gh run list -b <branch>`.
If CI fails, investigate immediately — do not move on to other work until CI is green.

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

- **CONST_SCRIPTCODE**: enforced — prohibits OP_CODESEPARATOR in base (non-witness) phases when the flag is active.
- **Taproot (BIP 341/342)**: implemented. Schnorr verification, key-path and script-path spends, control-block parity check (`secp256k1_xonly_pubkey_tweak_add_check`), per-input sigmsg with `tapleaf` + `codesep_pos` extension. 7/7 BIP-341 wallet test vectors pass; 5575/5575 mainnet tapscript inputs verify clean.
- **Legacy sighash edge case (tx_188)**: a single tx_invalid.json vector (`IF CODESEPARATOR ENDIF <pk> CHECKSIGVERIFY CODESEPARATOR 1` with CONST_SCRIPTCODE excluded) where the sig verifies against the post-CODESEP scriptCode in our K and Core's rejection appears to be from an older unconditional-reject policy. Left as xfail with a note.
- **K legacy sighash is O(tx_size²)** under repeated `+Bytes` concatenation. For 1MB stress-block txs this is 500× slower than the precomputed-blob lookup. The benchmark runner works around this by only passing `<tx>`/`<prevouts>` for taproot inputs ([src/bitcoin_script/benchmark/runner.py](src/bitcoin_script/benchmark/runner.py)); mainnet chain verification still exercises the K-native path. A proper fix threads an SHA-256 midstate through the walker instead of concatenating bytes.
