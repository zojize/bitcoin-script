# K Framework Proof Specs

K claims mechanically verified by `kprove` (Haskell backend).

## Proven claims (27 total)

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

## Blocked

HTLC hash path and P2PKH end-to-end need SHA256/HASH160/ECDSA
which are C++ hooks unavailable in the Haskell backend.

## TODO: planned specs

**P2SH phase transition**: saved stack restore, redeem script execution

**Script size limits**: scripts > 10000 bytes rejected

**Opcode count limits**: 201+ non-push opcodes rejected

**Haskell-native crypto hooks**: would unblock P2PKH, P2SH, HTLC
hash path proofs — the most valuable remaining specs.

## Running proofs

```sh
uv run kdist build bitcoin-script-semantics.haskell  # one-time
cd examples
just prove-all          # all 8 spec files
just prove htlc-spec    # single spec
```

## Architecture

- `script.k` — LLVM execution entry point (no lemmas)
- `script-verification.k` — Haskell proof entry point (imports lemmas)
- `lemmas.k` — 7 simplification rules for symbolic CScriptNum reasoning
