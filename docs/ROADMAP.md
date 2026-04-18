# Roadmap

Tracks open work after the benchmark audit. Grouped by priority.

---

## P0 — Formalize sighash in K (match KEVM's architectural level)

**Why:** The README claims "full BIP 341/342 Taproot/Tapscript support," but BIP-341 *is* the sighash specification. Keeping sighash as Python-precomputed input means the K semantics formalize Script *execution* only, not tx-level verification. KEVM's precedent (`#hashTxData`, `#sender`, `#blockHeaderHash` all in K rules, with only primitive crypto as C hooks) is the target.

**Boundary we want:**
- C hook (via `blockchain-k-plugin`): SHA-256, RIPEMD-160, ECDSA, Schnorr, tagged-hash primitive — already exist.
- K rules: all byte-level composition (sighash serialization, hashtype dispatch, tagged-hash construction, BIP-143/341 precomputed-hash cache).

### Foundation — DONE

Three commits on `feat/tapscript`:

1. [2e9f1dd](https://github.com/zojize/bitcoin-script/commit/2e9f1dd) — Config cells `<tx>`, `<prevouts>`, `<inputIndex>` added; Python wrapper accepts `tx`/`prevouts`/`input_index` kwargs.
2. [a99a3b3](https://github.com/zojize/bitcoin-script/commit/a99a3b3) — `SCRIPT-TX` module with tx wire-format primitives: `#readUInt32LE`, `#readUInt64LE`, `#readCompactSize`, `#compactSizeBytes`; tx-level accessors `#txVersion`, `#txLocktime`, `#txHasWitness`, `#txVinOffset`, `#txVinCount`, `#txVin0Offset`, `#txVinAt`, `#txVinOutpoint`, `#txVinSequence`, `#txVoutCount`, `#txVoutAt`, `#txVoutAmount`, `#txVoutScript`, `#txVoutSerialized`; walkers `#skipVins` / `#skipVouts`.
3. [557b584](https://github.com/zojize/bitcoin-script/commit/557b584) — `SCRIPT-SIGHASH` module with `#taggedHash` (BIP-340), `#doubleSha256`, and a `#sighashK(BLOB, HT, CSI)` stub that currently delegates to the existing blob lookup. Imported into `SCRIPT-SEMANTICS`.

All 1,649 K tests + 9 prover specs still pass. No observable behavior change yet — the CHECKSIG rules still use `lookupSighash` against the precomputed blob.

### BIP-143 (SegWit v0) — DONE

Five more commits landed the full K-side sighash for witness-v0 CHECKSIG / CHECKMULTISIG, with CODESEPARATOR tracking:

- [8de68cc](https://github.com/zojize/bitcoin-script/commit/8de68cc) — `#bip143HashPrevouts` / `#bip143HashSequence` / `#bip143HashOutputs` + three concat walkers.
- [54b48f7](https://github.com/zojize/bitcoin-script/commit/54b48f7) — `<scriptCode>` + `<amount>` config cells, witness-v0 phase-entry initialization, `#bip143Sighash` full sigmsg assembly.
- [202da8c](https://github.com/zojize/bitcoin-script/commit/202da8c) — `#ecdsaSighash` dispatcher + CHECKSIG / multisig rule updates; fixed a latent `#vinLen`/`#voutLen` offset bug in SCRIPT-TX; threaded tx/amount/input_index through `test_script_vectors.py::test_witness_vector` + `ChainVerifier`.
- [7947d48](https://github.com/zojize/bitcoin-script/commit/7947d48) — CODESEP scriptCode tracking via `<pendingCodesepTail>` + decoder `#setCodesepTail` emission.
- [2d25a63](https://github.com/zojize/bitcoin-script/commit/2d25a63) — retired witness-v0 entries from `_compute_sighash_blob` and threaded tx/amount/input_index through the benchmark runner.

### BIP-143 task checklist

- [x] **Extend K config** — `<tx>$TX:Bytes</tx>`, `<prevouts>$PREVOUTS:Bytes</prevouts>`, `<inputIndex>$INPUTINDEX:Int</inputIndex>`, plus `<amount>`, `<scriptCode>`, `<pendingCodesepTail>`.
- [x] **Tx wire-format primitives in K** — `SCRIPT-TX` module with compactSize + fixed-width LE readers and per-vin / per-vout accessors.
- [x] **Tagged hash primitive** — `#taggedHash(Tag, Message)` in `SCRIPT-SIGHASH` using the existing `Sha256raw` hook.
- [x] **BIP-143 sighash** (SegWit v0)
    - [x] `#bip143HashPrevouts(tx, hashtype)` — concat all vin outpoints, double-SHA-256 when not ANYONECANPAY, 32-byte zeros otherwise.
    - [x] `#bip143HashSequence(tx, hashtype)` — zeros when ANYONECANPAY / SINGLE / NONE, else concat all sequences + double-SHA-256.
    - [x] `#bip143HashOutputs(tx, inputIdx, hashtype)` — full tx outputs hash for ALL; single matching output for SINGLE; zeros for NONE / SINGLE-out-of-bounds.
    - [x] `#bip143ScriptCode` derivation — materialized as the `<scriptCode>` cell populated at witness-v0 phase entry (P2WPKH canonical template / P2WSH witness script) and updated on OP_CODESEPARATOR.
    - [x] `#bip143Sighash(tx, inputIdx, scriptCode, amount, hashtype)` — full sigmsg assembly + double-SHA-256.
    - [x] Switch the witness-v0 CHECKSIG / CHECKMULTISIG rules in `script-sig.k` to use `#bip143Sighash` (via `#ecdsaSighash` dispatcher) instead of `lookupSighash`.
    - [x] Drop `witness-v0` entries from the precomputed blob in `verifier.py::_compute_sighash_blob` and thread tx/amount through benchmark + test callers.
    - Mainnet smoke: 1,000/1,000 random witness-v0 inputs from benchmark-dataset-v3.msgpack verified via K-side BIP-143 with zero failures.
- [ ] **BIP-341 key-path sighash** (Taproot)
    - [ ] Five precomputed hashes: `#sha_prevouts`, `#sha_amounts`, `#sha_scriptpubkeys`, `#sha_sequences`, `#sha_outputs` (single SHA-256, not double).
    - [ ] `#bip341Sighash(tx, prevouts, inputIdx, annex, hashtype)` — BIP-341 sigmsg with spend type (0 / 1 for annex), wrapped with `#taggedHash("TapSighash", ...)`.
    - [ ] Switch the key-path CHECKSIG path in `script-semantics.k` (`#taprootVerify`) to use `#bip341Sighash`.
- [ ] **BIP-342 script-path sighash** (Tapscript)
    - [ ] `#tapleafHash(leafVersion, script)` = `#taggedHash("TapLeaf", leaf_version || compact_size(script) || script)`.
    - [ ] `#bip342Sighash(tx, prevouts, inputIdx, annex, hashtype, tapleafHash, keyVersion, codesepPos)` extending BIP-341 with tapscript-specific fields.
    - [ ] Switch tapscript CHECKSIG / CHECKSIGADD rules in `script-sig.k` to use `#bip342Sighash`.
- [ ] **Legacy sighash** (pre-SegWit)
    - [ ] Hashtype dispatch: `SIGHASH_ALL`, `SIGHASH_NONE`, `SIGHASH_SINGLE`, each × `SIGHASH_ANYONECANPAY`.
    - [ ] `OP_CODESEPARATOR` subscript slicing (legacy semantics: drop all bytes up to and including the last executed codesep — different from BIP-143).
    - [ ] Special cases: `SIGHASH_SINGLE` with `vin > vout` returns `0x01` hash.
    - [ ] Double-SHA-256 over the serialized modified tx.
- [ ] **Test vectors**
    - [ ] Cross-check every K sighash rule against Bitcoin Core's `script_tests.json` + `tx_valid.json` + BIP-341 test vectors at `bip-0341/wallet-test-vectors.json`.
    - [ ] Add a standalone `sighash_test.py` fixture that computes K sighash and compares byte-for-byte to `python-bitcointx`'s reference.
- [ ] **Rerun benchmark** — once BIP-341 + BIP-342 + legacy all land, re-run the full mainnet benchmark to quantify the K/Core ratio shift. BIP-143 alone didn't regress the 113 script_tests witness vectors; 1,000 mainnet witness-v0 smoke test is clean.

### Expected performance impact

K's rewrite engine is ~10-100× slower than C for byte-serialization work. Taproot K timing will likely grow from ~0.54ms (current, sighash-excluded) to 1.5-5ms (sighash-included in K rules). Overall K/Core ratio could shift from 1.82× to 3-5×. That's the *honest* number.

### Open design questions

1. Should tx serialization/deserialization also move into K (like KEVM's `#rlpEncode`)? Probably yes for symmetry, but lower priority — the benchmark already passes serialized bytes.
2. Do we want a `TRANSACTION` sort separate from `SCRIPT`, with sighash rules in a transaction-semantics module? KEVM splits `evm.md` and `serialization.md` this way.

---

## P1 — Benchmark audit followups

Items flagged by the external audit of commit `e457812` that aren't solved by the sighash work above.

### Reproducibility

- [ ] **Commit v3 artifacts** — currently saved locally at `.claude/worktrees/feat-tapscript/benchmark-{dataset-v3.msgpack,results-combined-v3.json}` but not in the tree. Options: (a) commit directly, (b) use git-lfs, (c) attach as GitHub release asset and link from README. Dataset is 274MB, results are 90MB.
- [ ] **Update README input/block counts** — current README says "300,836 inputs (74 blocks)." Actual v3 extraction: 288,185 inputs from 72 blocks (one API 404, a couple yielded zero inputs). Fix the headline number.

### Doc consistency

- [ ] **CLAUDE.md taproot status** — the "Known gaps" section still says "Taproot (BIP 341/342): not implemented." Either remove or replace with the real remaining gaps (post-sighash-formalization, probably just "legacy sighash OP_CODESEPARATOR edge cases" or similar).
- [ ] **Tx-vector claim** — `tests/test_k_semantics/bitcoin_core_vectors.py:212` xfails any vector with the TAPROOT flag, so the headline "174 of 214 tx vectors" excludes taproot entirely. Either remove the xfail (verify what actually passes with TAPROOT enabled) or change the headline to "174/214 non-taproot tx vectors" until the xfail is revisited post-sighash-formalization.

### Methodology hygiene

- [ ] **Throughput label** — `report.py` computes `1/mean` and labels it as throughput alongside medians. Rename to "mean throughput (inp/s)" or report both `1/mean` and `1/median` so readers don't conflate.
- [ ] **Run variance** — current numbers are single-run. Run the full benchmark 3× and report mean ± stdev per era so readers can bound noise. Takes ~6hr on the M4 Pro remote; can be a cron job.
- [ ] **API extraction skips** — `api_extractor.py:270-278` silently catches exceptions and continues. Bubble skipped blocks up to the final log summary (and to the dataset header) so 74-vs-78 discrepancies are self-explanatory.
- [ ] **`stress_count` default** — CLI default is 20 but `KNOWN_STRESS_BLOCKS` has 10 entries. Either rename the default to `len(KNOWN_STRESS_BLOCKS)` or drop the slicing — current silent truncation is a footgun.

### Runner polish

- [ ] **Default iter counts** — `k_iterations=1` + `core_iterations=100` is asymmetric. Change default to match (e.g. both 30) and keep the override flags.
- [ ] **P95 is single-shot at k=1** — either raise the default (see above) or document that P95 at k=1 is really "P95 of single-shot per-input samples," not "P95 of typical per-input latency."

---

## P2 — Nice to have

- [ ] **Core no-op baseline** — measure Core's overhead on a trivial script (e.g., `OP_1`) so we can report `core_script_exec` = `core_elapsed - core_overhead`. Gives a "pure rewrite engine vs pure C interpreter" comparison independent of tx-setup cost.
- [ ] **K runtime reuse across inputs** — current FFI path calls `kore_pattern_parse` fresh each input. Check if parsed patterns can be reused across inputs with different `$SCRIPT`/`$TX` config values; could shave the 0.5ms floor.
- [ ] **Haskell backend benchmark** — the `haskell` kdist target exists; no perf numbers for it yet. Useful context for the proof vs execution tradeoff.
- [ ] **Representative sampling by activity** — `select_representative_heights` picks evenly-spaced blocks regardless of tx volume. Weighted sampling (e.g. by tx count or sigop count from Blockstream's API) would make "300K real mainnet inputs" more honest vs "300K inputs from 70 blocks with undersampled early eras."

---

## Done (v3 audit round)

- [x] v3 dataset schema with per-tx prevout arrays (commit `9f9f4c2`)
- [x] `verify_script_with_spent_outputs` path in runner for taproot Core verification
- [x] First apples-to-apples K+Core run including taproot (288,185 inputs, zero mismatches)
- [x] Confirmed the 349ms taproot outlier was single-shot noise (same input at K=30: 0.51ms)
- [x] P2TR keypath/scriptpath breakdown (8,483 + 5,575 = 14,058)
