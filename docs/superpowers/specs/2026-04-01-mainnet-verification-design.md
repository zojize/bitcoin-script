# Mainnet Script Verification via K Framework

**Date:** 2026-04-01
**Status:** Design

## Goal

Verify every script execution (scriptSig + scriptPubKey + witness) for every transaction input on Bitcoin mainnet from genesis to the taproot activation (block 709,632), using the K Framework formal semantics as the sole execution engine.

## Scope

**In scope:** Script verification for every non-coinbase input, UTXO tracking, sighash computation, flag activation schedule, parallel K invocations, single-block verification API.

**Out of scope:** Proof-of-work, merkle root, timestamps, block size limits, sigops counting, value conservation, coinbase maturity. We trust the chain structure and focus exclusively on script correctness.

## Architecture

```
BlockFileParser ──► Block ──► Transaction ──► Input
                                                │
                                    UTXO lookup (SQLite)
                                                │
                                  ┌─────────────┼─────────────┐
                                  │             │             │
                          scriptPubKey      sighash       witness
                            + amount        blob           blob
                                  │             │             │
                                  └─────────────┼─────────────┘
                                                │
                                   KBitcoinScript.verify_script()
                                                │
                                   Update UTXO set (batch commit)
```

## Components

### 1. UTXOSet (SQLite-backed)

**Location:** `src/bitcoin_script/blockchain/utxo.py`

Replace the existing stub with a SQLite-backed implementation.

**Schema:**
```sql
CREATE TABLE utxos (
    txid     BLOB NOT NULL,
    vout     INTEGER NOT NULL,
    script   BLOB NOT NULL,
    amount   INTEGER NOT NULL,
    PRIMARY KEY (txid, vout)
);
```

**Interface:**
```python
class UTXOSet:
    def __init__(self, db_path: str | Path): ...
    def add(self, txid: bytes, vout: int, script: bytes, amount: int) -> None: ...
    def spend(self, txid: bytes, vout: int) -> tuple[bytes, int]: ...
        # Returns (scriptPubKey, amount). Raises KeyError if not found.
    def get(self, txid: bytes, vout: int) -> tuple[bytes, int] | None: ...
    def commit(self) -> None: ...  # Flush pending changes to disk
    def size(self) -> int: ...
    def checkpoint_height(self) -> int: ...  # Last committed block height
    def set_checkpoint_height(self, height: int) -> None: ...
```

Batch writes within a transaction per block for performance. Commit after each block (or every N blocks for speed).

### 2. SighashComputer

**Location:** `src/bitcoin_script/blockchain/sighash.py` (new file)

Compute legacy (pre-SegWit) and BIP-143 (SegWit) sighash for real transactions.

**Interface:**
```python
def compute_sighash_blob(
    tx: CTransaction,
    input_index: int,
    script_pubkey: bytes,
    amount: int,
    flags: int,
    witness_script: bytes | None = None,
) -> bytes:
    """Compute sighash blob for all standard hashtypes.

    Returns concatenated (1-byte hashtype + 32-byte sighash) entries.
    Detects whether to use legacy or BIP-143 based on the script type and flags.
    """
```

This promotes and generalizes the logic currently in `tests/test_k_semantics/conftest.py`. Key differences from the test harness version:
- Works with real `CTransaction` objects (not synthetic crediting/spending txs)
- Handles `OP_CODESEPARATOR` subscript truncation (FindAndDelete for legacy)
- Determines witness vs legacy based on actual script type and flag activation

### 3. FlagSchedule

**Location:** `src/bitcoin_script/blockchain/flags.py` (new file)

Maps block height and timestamp to the set of active verification flags.

```python
def flags_for_block(height: int, timestamp: int) -> int:
    """Return the bitmask of active SCRIPT_VERIFY_* flags at this block."""
```

**Activation schedule (mainnet):**

| Flag | Activation | Condition |
|------|-----------|-----------|
| P2SH | BIP 16 | `timestamp >= 1333238400` (Apr 1 2012) |
| DERSIG | BIP 66 | `height >= 363725` |
| CHECKLOCKTIMEVERIFY | BIP 65 | `height >= 388381` |
| CHECKSEQUENCEVERIFY | BIP 112 | `height >= 419328` |
| WITNESS | BIP 141 | `height >= 481824` |
| NULLDUMMY | BIP 147 | `height >= 481824` (activated with SegWit) |
| NULLFAIL | — | `height >= 481824` (policy, enforced with SegWit) |
| LOW_S | BIP 62 rule 5 | `height >= 363725` (enforced with DERSIG) |
| STRICTENC | — | `height >= 363725` |
| CLEANSTACK | — | `height >= 481824` |
| SIGPUSHONLY | BIP 62 rule 2 | `height >= 481824` |
| MINIMALDATA | BIP 62 rule 3-4 | `height >= 481824` |
| MINIMALIF | — | `height >= 481824` (witness v0 only) |
| WITNESS_PUBKEYTYPE | — | `height >= 481824` (witness v0 only) |

Note: Some flags (STRICTENC, LOW_S, CLEANSTACK) were policy-only before SegWit but became consensus-enforced at SegWit activation. The exact activation details need cross-referencing with Bitcoin Core's `GetBlockScriptFlags()`.

### 4. ChainVerifier

**Location:** `src/bitcoin_script/blockchain/verifier.py` (new file)

Orchestrates block-by-block verification.

**Interface:**
```python
class ChainVerifier:
    def __init__(
        self,
        blocks_dir: Path,         # Bitcoin Core blocks/ directory
        utxo_db_path: Path,       # SQLite database path
        k: KBitcoinScript,        # K execution engine
        max_workers: int = 1,     # Parallel K invocations
    ): ...

    def verify_chain(self, start: int = 0, end: int | None = None) -> VerifyResult: ...
        """Verify blocks from start to end (inclusive). Resumes from UTXO checkpoint."""

    def verify_block(self, height: int) -> BlockResult: ...
        """Verify a single block at the given height.
        Requires UTXO set to be populated up to height-1.
        Useful for demos and debugging."""

    def verify_block_raw(self, block: CBlock, height: int, timestamp: int) -> BlockResult: ...
        """Verify a block object directly, without reading from disk.
        Caller provides the block, height, and timestamp.
        Requires UTXO set to be populated up to height-1."""
```

**`verify_block` flow:**
1. Parse block from .blk files at the given height
2. Determine flags via `flags_for_block(height, block.nTime)`
3. For each transaction:
   - Coinbase: add outputs to UTXO set, skip verification
   - Non-coinbase: for each input:
     a. Look up referenced UTXO → `(scriptPubKey, amount)`
     b. Extract witness data from `tx.wit` if present
     c. Compute sighash blob
     d. Call `KBitcoinScript.verify_script()`
     e. Assert success
   - After all inputs verified: spend UTXOs, add new outputs
4. Commit UTXO changes
5. Return `BlockResult` with stats (inputs verified, time elapsed, errors)

**Parallelization:** For non-coinbase inputs within a block, K invocations are independent (they don't modify the UTXO set, they only read it). Use `ProcessPoolExecutor` to dispatch `verify_script()` calls in parallel. UTXO updates happen sequentially after all inputs in a transaction are verified.

### 5. Single-Block Verification API

For demo and debugging, `ChainVerifier.verify_block(height)` provides a simple way to verify one specific block. This requires the UTXO set to be built up to that point. For blocks near genesis, this is fast; for later blocks, the caller must either:
- Run `verify_chain(0, height - 1)` first to build UTXO state, or
- Load a pre-built UTXO checkpoint

`verify_block_raw(block, height, timestamp)` provides an even lower-level API for callers who already have the block object.

### 6. CLI Integration

**Location:** `src/bitcoin_script/cli.py`

Fill in the existing `validate` command stub:

```
bitcoin-script validate [--blocks-dir PATH] [--db PATH] [--start N] [--end N] [--workers N]
bitcoin-script validate --block N [--blocks-dir PATH] [--db PATH]
```

The `--block N` flag verifies a single block (demo mode).

## Identified Gaps (Blockers)

These are features missing from the K semantics or Python infrastructure that must be implemented before mainnet verification can succeed.

### Critical

| Gap | Description | Affects |
|-----|-------------|---------|
| **Real-transaction sighash** | Current sighash code uses synthetic crediting/spending txs. Need to compute sighash against actual `CTransaction` with real inputs, outputs, and the correct input index. | All non-trivial transactions |
| **FindAndDelete / OP_CODESEPARATOR** | Legacy sighash must remove the signature being verified from the subscript before hashing. `OP_CODESEPARATOR` truncates the subscript. Currently `OP_CODESEPARATOR` is a NOP. | Pre-SegWit transactions with CODESEPARATOR (rare but exists on mainnet) |
| **UTXO set** | Currently stubbed. Need SQLite implementation. | Everything |
| **Flag activation schedule** | No mapping from height/timestamp to flags. | Correct enforcement of consensus rules per era |

### Medium

| Gap | Description | Affects |
|-----|-------------|---------|
| **SIG_NULLFAIL** | Still in `_FLAG_ERRORS` xfail list. Need to investigate and fix remaining edge cases. | Post-SegWit transactions (block 481,824+) |
| **Witness deserialization** | Need to verify `python-bitcoinlib` correctly deserializes witness data from real blocks and exposes it on `CTransaction.wit`. | SegWit transactions |
| **CONST_SCRIPTCODE** | Flag `CONST_SCRIPTCODE` enforcement not implemented. Prevents `OP_CODESEPARATOR` in witness v0 scripts. | SegWit transactions using CODESEPARATOR |

### Low (may not appear on mainnet pre-taproot)

| Gap | Description | Affects |
|-----|-------------|---------|
| **Non-standard transactions** | Some early mainnet transactions use unusual patterns (bare multisig, OP_RETURN data, non-standard push encodings). These should work with current K semantics but may surface edge cases. | Early chain |
| **Large scripts** | Some mainnet transactions have large scripts (up to 10KB). K invocation time may increase. | Performance |

## Testing Strategy

1. **Unit tests:** UTXOSet CRUD, FlagSchedule correctness, SighashComputer against known vectors
2. **Integration:** Verify first 100 blocks of mainnet (genesis through early chain) — no signatures, just basic script execution
3. **Regression:** Bitcoin Core's `tx_valid.json` / `tx_invalid.json` vectors (currently skipped in test_tx_vectors.py)
4. **Milestone blocks:** Verify specific blocks at each soft fork activation boundary
5. **Full chain:** Run `verify_chain(0, 709632)` end-to-end

## Implementation Order

1. **UTXOSet** (SQLite) — unblocks everything
2. **FlagSchedule** — needed to pass correct flags
3. **SighashComputer** (real transactions) — needed for any signature verification
4. **ChainVerifier** (single-threaded, single-block API) — end-to-end wiring
5. **Verify genesis through block ~200** — no signatures in early blocks, validates basic flow
6. **FindAndDelete / OP_CODESEPARATOR** — needed for pre-SegWit era
7. **SIG_NULLFAIL** — needed for post-SegWit era
8. **Parallel K invocations** — performance
9. **CLI integration** — user-facing command
10. **Full chain run** — the goal
