# K Framework Proof Specs

K claims mechanically verified by `kprove` (Haskell backend).

## Proven claims (71 total)

**arithmetic-spec.k** (3) — symbolic, all valid CScriptNum inputs:
- OP_1ADD(N) == N+1, OP_NEGATE(N) == -N, OP_ADD(A,B) == A+B

**symbolic-spec.k** (5) — symbolic opcode properties:
- OP_EQUAL succeeds iff N==5, OP_NOT maps nonzero to 0
- OP_WITHIN correct for any A/MIN/MAX, SUB+NOT implements equality

**timelock-spec.k** (4) — concrete CLTV execution:
- pass/NOP/fail-early/fail-final-sequence

**htlc-spec.k** (2) — concrete HTLC timeout path:
- succeed after expiry, fail before expiry

**branch-spec.k** (2) — IF/ELSE/ENDIF branch selection:
- truthy takes IF branch, falsy takes ELSE branch

**phase-spec.k** (3) — scriptSig -> scriptPubKey state passing:
- single value match, mismatch, multiple values across phases

**limits-spec.k** (4) — consensus rule enforcement:
- CLEANSTACK, SIGPUSHONLY, small script succeeds

**scriptnum-spec.k** (4) — CScriptNum encoding at boundaries:
- zero, 1+(-1)=0, 127+1=128 boundary, negate encoding

**csv-spec.k** (4) — concrete CSV (BIP 112) execution:
- pass/NOP/fail-early/fail-old-version (mirrors timelock-spec for relative locks)

**stack-ops-spec.k** (6) — symbolic stack manipulation:
- SWAP, ROT, OVER, NIP, TUCK correct for any byte values
- TOALTSTACK~>FROMALTSTACK roundtrip preserves value

**disabled-ops-spec.k** (3) — disabled opcodes always fail:
- OP_CAT fails in live branch, OP_CAT fails in dead IF branch
- OP_RETURN halts execution

**arithmetic-extended-spec.k** (5) — symbolic extended arithmetic:
- OP_SUB, OP_ABS (positive and negative), OP_MIN, OP_MAX correct for all valid inputs

**equalverify-spec.k** (2) — concrete OP_EQUALVERIFY:
- matching values pass, mismatched values produce EQUALVERIFY error

**guardexec-spec.k** (2) — dead branch opcode skipping:
- OP_ADD in dead IF branch skipped (would crash), OP_RESERVED in dead branch skipped

**historical-bugs-spec.k** (8) — before/after flag activation:
- MINIMALDATA: non-minimal zero accepted/rejected
- NULLDUMMY: non-null dummy accepted/rejected
- CLEANSTACK: extra stack items accepted/rejected
- DISCOURAGE_UPGRADABLE_NOPS: NOP1 accepted/rejected

**minimaldata-push-spec.k** (3) — push-level MINIMALDATA enforcement:
- PUSHDATA1 for 1-byte value accepted without flag, rejected with flag
- PUSHBYTES_1 (minimal encoding) accepted even with MINIMALDATA flag

**op-return-spec.k** (3) — OP_RETURN execution context:
- OP_RETURN in live branch halts with error
- OP_RETURN in dead IF branch skipped (unlike disabled ops — uses #guardExec)
- OP_RETURN in scriptSig aborts before scriptPubKey executes

**invalid-op-spec.k** (3) — disabled arithmetic opcodes always fail:
- OP_MUL (0x95) fails in live branch, OP_LSHIFT (0x98) fails in live branch
- OP_MUL fails even in dead IF branch (bare OP_INVALIDOPCODE bypasses guard)

**depth-spec.k** (4) — OP_IFDUP and OP_DEPTH stack behavior:
- OP_IFDUP duplicates truthy top, leaves falsy top unchanged
- OP_DEPTH on empty stack pushes 0 (b""), on two items pushes 2 (b"\x02")

## LLVM-verified claims (booster_prove.py)

HTLC hash path claims need SHA256 hook evaluation, which the Haskell
backend can't provide. These are proved via LLVM execution instead:
extract the initial config, run through `llvm_interpret`, verify the
final state matches the expected output.

## Running proofs

```sh
uv run kdist build bitcoin-script-semantics.haskell  # one-time
just test-prove                                       # all specs via pytest
just prove htlc-spec                                  # single spec via examples/justfile
```

## Architecture

- `script.k` — LLVM execution entry point (no lemmas)
- `script-verification.k` — Haskell proof entry point (imports lemmas)
- `lemmas.k` — 12 simplification rules for symbolic CScriptNum reasoning
