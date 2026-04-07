# K Framework Proof Specs

K claims mechanically verified by `kprove` (Haskell backend).

## Proven claims (34 total)

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

**historical-bugs-spec.k** (7+1) — before/after flag activation:
- MINIMALDATA: non-minimal zero accepted/rejected
- NULLDUMMY: non-null dummy accepted/rejected
- CLEANSTACK: extra stack items accepted/rejected
- DISCOURAGE_UPGRADABLE_NOPS: NOP1 accepted/rejected
- (1 claim needs booster for `#isMinimalNum` byte evaluation)

## Blocked on booster integration

HTLC hash path, P2PKH end-to-end, and MINIMALDATA rejection need
concrete evaluation of KRYPTO hooks / byte operations via
kore-rpc-booster with `--llvm-backend-library`.

## Running proofs

```sh
uv run kdist build bitcoin-script-semantics.haskell  # one-time
just test-prove                                       # all specs via pytest
just prove htlc-spec                                  # single spec via examples/justfile
```

## Architecture

- `script.k` — LLVM execution entry point (no lemmas)
- `script-verification.k` — Haskell proof entry point (imports lemmas)
- `lemmas.k` — 7 simplification rules for symbolic CScriptNum reasoning
