# K Framework Proof Specs

K claims mechanically verified by `kprove` (Haskell backend).

## Proven claims (14 total)

**arithmetic-spec.k** (3 claims) — symbolic, for ALL valid CScriptNum inputs:
- `1add-correct`: OP_1ADD(N) == N+1
- `negate-correct`: OP_NEGATE(N) == -N
- `add-correct`: OP_ADD(A, B) == A+B

**symbolic-spec.k** (5 claims) — symbolic opcode properties:
- `equals-5-pass`: OP_EQUAL succeeds when N == 5
- `not-nonzero-is-false`: OP_NOT maps any nonzero to 0
- `within-true/false`: OP_WITHIN correct for any A, MIN, MAX
- `sub-not-equal`: SUB + NOT implements equality (A == B -> 1)

**timelock-spec.k** (4 claims) — concrete CLTV execution:
- `cltv-pass-block-height`: passes when nLockTime >= threshold
- `cltv-nop-without-flag`: NOP when flag not set
- `cltv-fail-too-early`: fails when nLockTime < threshold
- `cltv-fail-final-sequence`: fails when nSequence is final

**htlc-spec.k** (2 claims) — concrete HTLC timeout path:
- `timeout-path-after-expiry`: succeeds when nLockTime >= timeout
- `timeout-path-before-expiry`: fails when nLockTime < timeout

## Blocked

HTLC hash path claims need SHA256/HASH160 which are C++ hooks
(blockchain-k-plugin) unavailable in the Haskell backend.

## TODO: planned specs

Following patterns from [KEVM specs](https://github.com/runtimeverification/evm-semantics/tree/master/tests/specs):

**CScriptNum encoding correctness** (like KEVM's merkle-spec):
- `intToScriptNumAbs` produces minimal encoding for all ranges
- Encoding is injective (different integers -> different bytes)
- Roundtrip: decode(encode(N)) == N for edge cases (0, -1, 128, -128, max)

**Phase transition correctness** (like KEVM's storage-spec):
- scriptSig stack is correctly passed to scriptPubKey phase
- P2SH: saved stack is restored, redeem script is popped and executed
- Witness: witness stack items are pushed correctly

**Script template completeness** (like KEVM's ERC20 approve success/revert):
- "Check equals N" script: accepts N, rejects everything else (two-sided)
- P2PKH: fails before CHECKSIG when pubkey hash mismatches (needs HASH160 hook)

**Opcode composition** (like KEVM's functional specs):
- DUP + EQUALVERIFY == check top two equal
- IF/ELSE/ENDIF: exactly one branch executes for any truthy/falsy input

**Resource limits** (like KEVM's gas specs):
- opCount increments correctly per non-push opcode
- Scripts exceeding 201 ops fail
- Scripts exceeding 10000 bytes fail

**Prerequisite for more specs**: Haskell-native crypto hooks (SHA256,
HASH160, RIPEMD160) would unblock P2PKH, P2SH, and HTLC hash path proofs.

## Running proofs

```sh
uv run kdist build bitcoin-script-semantics.haskell  # one-time
cd examples
just prove-all          # all specs
just prove htlc-spec    # single spec
```

## Architecture

- `script.k` — LLVM execution entry point (no lemmas)
- `script-verification.k` — Haskell proof entry point (imports lemmas)
- `lemmas.k` — 7 simplification rules for symbolic CScriptNum reasoning
