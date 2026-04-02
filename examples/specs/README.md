# K Framework Proof Specs

K claims that can be mechanically verified by `kprove` (Haskell backend).

## What proves today

**p2pkh-spec.k** — 3 claims, all proven:

- OP_DUP duplicates top stack element
- EQUALVERIFY passes on equal values
- EQUALVERIFY fails on different values

**timelock-spec.k** — 2 claims, all proven:

- CLTV passes when nLockTime >= threshold
- CLTV is a NOP when the flag is not set

## What's blocked

**arithmetic-spec.k** and **htlc-spec.k** document correct properties but
the Haskell prover gets stuck on byte-level reasoning. The root cause:

Our semantics use K's built-in `Int2Bytes`, `Bytes2Int`, `substrBytes` for
all byte manipulation. The Haskell prover can't simplify symbolic
expressions like `substrBytes(Int2Bytes(5, X, BE), 0, 1)` without
explicit `[simplification]` rules.

## What's needed: byte simplification lemmas

Following KEVM's approach (`kevm-pyk/.../lemmas/bytes-simplification.k`),
we need ~50-100 simplification lemmas. Key ones:

```k
// lengthBytes
rule lengthBytes(Int2Bytes(N, _, _)) => N [simplification]
rule lengthBytes(A +Bytes B) => lengthBytes(A) +Int lengthBytes(B) [simplification]
rule lengthBytes(.Bytes) => 0 [simplification]

// Bytes2Int / Int2Bytes roundtrip
rule Bytes2Int(Int2Bytes(N, V, E), E, Unsigned) => V modInt (1 <<Int (8 *Int N))
  requires 0 <=Int V [simplification]

// substrBytes over concatenation
rule substrBytes(A +Bytes _B, 0, N) => A
  requires lengthBytes(A) ==Int N [simplification]
rule substrBytes(_A +Bytes B, N, N +Int lengthBytes(B)) => B
  requires lengthBytes(_A) ==Int N [simplification]

// CScriptNum roundtrip
rule scriptNumToInt(intToScriptNum(N)) => N
  requires N >=Int -2147483647 andBool N <=Int 2147483647 [simplification]
```

These would go in a `lemmas.k` module imported by spec files. KEVM has
~300 such lemmas; we'd need a subset focused on our byte patterns.

This is the single biggest enabler for non-trivial proofs — things like
"OP_ADD is commutative for all valid inputs" or "this HTLC has exactly
two spending paths for any preimage."

## Running proofs

```sh
# Build Haskell backend (one-time)
uv run kdist build bitcoin-script-semantics.haskell

# Prove specs
cd examples
just prove-all                # all passing specs
just prove p2pkh-spec         # single spec
```
