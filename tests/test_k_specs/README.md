# K Framework Proof Specs

K claims mechanically verified by `kprove` (Haskell backend).

## Proven claims (71 total)

Each claim is listed with: *what it proves* and **what it rules out** — the class
of K rule bugs that would cause the claim to fail.

---

### arithmetic-spec.k (3)

Symbolic arithmetic over arbitrary CScriptNum inputs `N`, `A`, `B`:

- **OP_1ADD(N) == N+1** — *rules out* an off-by-one in the ADD1 rewrite rule, or accidental
  CScriptNum overflow that truncates the result.
- **OP_NEGATE(N) == -N** — *rules out* sign-bit confusion in the CScriptNum negation
  encoding (e.g., not flipping the high bit correctly).
- **OP_ADD(A, B) == A+B** — *rules out* the ADD rule operating on the wrong stack depth,
  or producing an unencoded raw integer instead of a CScriptNum.

---

### symbolic-spec.k (5)

- **OP_EQUAL succeeds iff N==5** — *rules out* EQUAL using byte-identity instead of
  CScriptNum-value comparison, or failing to normalise the pushed constant.
- **OP_NOT maps nonzero to 0** — *rules out* NOT treating any nonzero byte string as
  false (only the all-zero / empty encoding is false).
- **OP_WITHIN correct for any A/MIN/MAX** — *rules out* off-by-one on either bound of
  the inclusive-left / exclusive-right interval check.
- **SUB+NOT implements equality** — *rules out* symbolic composition bugs where two
  correct rules produce a wrong result when chained.
- **OP_EQUAL on equal stacks** — *rules out* byte-length mismatch treated as a value
  mismatch when the CScriptNum encodings are canonical.

---

### timelock-spec.k (4)

Concrete CLTV (BIP 65) execution with fixed `nLockTime` values:

- **pass** — *rules out* a K rule that rejects a valid CLTV spend.
- **NOP** (CLTV flag absent) — *rules out* CLTV executing when the flag is disabled; it
  must behave as a NOP.
- **fail-early** (lock not reached) — *rules out* a K rule that allows spending before
  the locktime, the canonical safety property.
- **fail-final-sequence** (nSequence = 0xFFFFFFFF) — *rules out* missing the BIP 65
  rule that rejects a final sequence even when the locktime passes.

---

### htlc-spec.k (4: 2 Haskell + 2 LLVM)

Formal proof that an HTLC has exactly two spending paths:

- **hash-path-correct-preimage** — *rules out* the hash path accepting any input that
  does not SHA256-hash to the committed digest.
- **hash-path-wrong-preimage** — *rules out* the hash path succeeding with a wrong
  preimage (weak collision resistance of the SHA256 hook).
- **timeout-path-after-expiry** — *rules out* the timeout path rejecting a valid
  post-expiry spend (CLTV must pass when `nLockTime >= timeout`).
- **timeout-path-before-expiry** — *rules out* the timeout path allowing an early spend,
  the primary HTLC safety invariant.

---

### branch-spec.k (2)

- **truthy takes IF branch** — *rules out* the IF rule consuming the condition but
  executing the wrong branch, or leaving the condition on the stack.
- **falsy takes ELSE branch** — *rules out* the IF rule entering the ELSE branch when
  the condition is truthy (branch inversion).

---

### phase-spec.k (3)

scriptSig → scriptPubKey state passing:

- **single value match** — *rules out* the phase-transition rule dropping the saved
  stack or reinitialising it to empty.
- **mismatch** — *rules out* a broken phase boundary where the scriptSig's final stack
  is compared to the wrong scriptPubKey items.
- **multiple values across phases** — *rules out* the saved-stack ordering being
  reversed at the phase boundary.

---

### limits-spec.k (4)

Consensus resource rule enforcement:

- **CLEANSTACK** — *rules out* CLEANSTACK accepting a successful script whose stack
  has more than one item at the end.
- **SIGPUSHONLY** — *rules out* SIGPUSHONLY allowing a non-push opcode in scriptSig.
- **small script succeeds** — *rules out* spurious resource-limit rejections for
  scripts well within all bounds.
- **opcount limit** — *rules out* omitting the opcode counter increment, allowing an
  unbounded loop to pass.

---

### scriptnum-spec.k (5)

CScriptNum encoding at canonical boundaries:

- **zero** — *rules out* encoding 0 as a non-empty byte string (must be `b""`).
- **1+(-1)=0** — *rules out* the addition rule keeping a non-canonical zero byte in
  the result.
- **127+1=128 boundary** — *rules out* missing the sign-extension byte when the result
  is 128 (the canonical two-byte form `b"\x80\x00"`).
- **negate encoding** — *rules out* negate forgetting to flip the high sign bit in the
  final byte.
- **round-trip** — *rules out* encode(decode(x)) ≠ x for any valid CScriptNum.

---

### csv-spec.k (4)

Concrete CSV (BIP 112) execution (mirrors timelock-spec for relative locks):

- **pass** — *rules out* a K rule that rejects a valid CSV spend.
- **NOP** (CSV flag absent) — *rules out* CSV executing when the flag is off.
- **fail-early** — *rules out* a K rule that allows relative-lock bypass.
- **fail-old-version** (tx version < 2) — *rules out* missing the BIP 68 requirement
  that CSV only enforces for transactions with `nVersion >= 2`.

---

### stack-ops-spec.k (7)

Symbolic stack manipulation for arbitrary byte values `A`, `B`, `C`:

- **SWAP** — *rules out* SWAP operating on a fixed offset or the wrong depth.
- **ROT** — *rules out* ROT rotating in the wrong direction (A,B,C → C,A,B vs A,B,C → B,C,A).
- **OVER** — *rules out* OVER copying the wrong element or consuming the original.
- **NIP** — *rules out* NIP removing the top instead of the second item.
- **TUCK** — *rules out* TUCK inserting the copy below the wrong element.
- **TOALTSTACK→FROMALTSTACK roundtrip** — *rules out* the altstack losing the value
  across the round-trip, or swapping main/alt stack identity.
- **2DUP** — *rules out* 2DUP duplicating only one item or reversing the copy order.

---

### disabled-ops-spec.k (3)

Disabled opcodes must always halt:

- **OP_CAT in live branch** — *rules out* OP_CAT executing when it should be rejected
  as a disabled opcode.
- **OP_CAT in dead IF branch** — *rules out* the disabled-opcode check being guarded
  by the exec-stack (disabled ops must fail even when skipped, unlike OP_RETURN).
- **OP_RETURN halts execution** — *rules out* OP_RETURN being treated as a NOP, or
  leaving a truthy residue on the stack.

---

### arithmetic-extended-spec.k (5)

Symbolic extended arithmetic for arbitrary valid CScriptNum inputs:

- **OP_SUB(A,B) == A-B** — *rules out* reversed operand order.
- **OP_ABS(positive N) == N** — *rules out* ABS negating a positive number.
- **OP_ABS(negative N) == -N** — *rules out* ABS failing to flip the sign bit.
- **OP_MIN** — *rules out* MIN returning the larger operand.
- **OP_MAX** — *rules out* MAX returning the smaller operand.

---

### equalverify-spec.k (2)

- **matching values pass** — *rules out* EQUALVERIFY failing on genuinely equal values.
- **mismatched values produce EQUALVERIFY error** — *rules out* EQUALVERIFY pushing
  false instead of halting with an error, which would allow a script to recover from
  a failed equality check.

---

### guardexec-spec.k (2)

Dead-branch opcode skipping:

- **OP_ADD in dead IF branch skipped** — *rules out* the guard-exec mechanism failing
  to wrap OP_ADD; executing OP_ADD on an empty stack would cause a stack-underflow
  error rather than silent skip.
- **OP_RESERVED in dead branch skipped** — *rules out* OP_RESERVED (0x50) being
  decoded as OP_INVALIDOPCODE instead of being properly wrapped by the guard, which
  would wrongly abort even dead branches.

---

### historical-bugs-spec.k (8)

Flag-gated behavior: before and after activation of four flags:

- **MINIMALDATA accepted/rejected** — *rules out* MINIMALDATA enforcement being
  unconditional (it must only fire when the flag is set).
- **NULLDUMMY accepted/rejected** — *rules out* the NULLDUMMY check ignoring the
  flag, causing spurious failures on pre-flag transactions.
- **CLEANSTACK accepted/rejected** — *rules out* CLEANSTACK enforcement activating
  before the flag.
- **DISCOURAGE_UPGRADABLE_NOPS accepted/rejected** — *rules out* NOP1–NOP10 being
  treated as errors regardless of the flag, breaking pre-activation transactions.

---

### minimaldata-push-spec.k (3)

Push-level MINIMALDATA enforcement:

- **PUSHDATA1 for 1-byte value rejected with flag** — *rules out* the minimal-push
  check ignoring non-minimal PUSHDATA1 encodings when the flag is active.
- **PUSHDATA1 accepted without flag** — *rules out* MINIMALDATA enforced without flag.
- **PUSHBYTES_1 (minimal encoding) accepted with flag** — *rules out* the minimal-push
  check incorrectly rejecting the canonical 1-byte push even when the flag is set.

---

### op-return-spec.k (3)

OP_RETURN execution context:

- **live branch halts with error** — *rules out* OP_RETURN behaving as a NOP in a
  live branch.
- **dead IF branch skipped** — *rules out* OP_RETURN in a false-branch halting
  execution (unlike disabled opcodes, OP_RETURN is guarded by #guardExec).
- **scriptSig abort** — *rules out* OP_RETURN in the scriptSig phase not preventing
  scriptPubKey execution from starting.

---

### invalid-op-spec.k (3)

Disabled arithmetic opcodes fail unconditionally:

- **OP_MUL (0x95) in live branch** — *rules out* the decoder emitting OP_MUL wrapped
  in #guardExec (which would let it pass in dead branches); disabled ops must use
  bare OP_INVALIDOPCODE.
- **OP_LSHIFT (0x98) in live branch** — same check for a different disabled byte.
- **OP_MUL in dead IF branch** — *rules out* OP_MUL being mistakenly treated as a
  guardExec-wrapped opcode and silently skipped in dead branches.

---

### depth-spec.k (4)

OP_IFDUP and OP_DEPTH:

- **OP_IFDUP duplicates truthy top** — *rules out* IFDUP always duplicating or never
  duplicating.
- **OP_IFDUP leaves falsy top unchanged** — *rules out* IFDUP consuming the top
  element when the value is false.
- **OP_DEPTH on empty stack pushes 0** — *rules out* DEPTH pushing 1 (off-by-one
  counting the depth cell versus the List size).
- **OP_DEPTH on two-item stack pushes 2** — *rules out* DEPTH not iterating the full
  List, or double-counting the altstack.

---

## LLVM-verified claims (booster_prove.py)

HTLC hash path claims need SHA256 hook evaluation. The Haskell backend builds
an LLVM library at haskell/llvm-library/ for kore-rpc-booster to delegate
concrete hook evaluation. Wiring this into pyk's APRProver is TODO.

---

## Next 10 claims to add

The following would meaningfully extend the proof catalog to cover Taproot and
tapscript correctness, and to close the residual gaps noted by reviewers:

1. **tapscript-empty-pubkey-spec.k** — prove that `0 CHECKSIG` in `witness-v1`
   always halts with error `TAPSCRIPT_EMPTY_PUBKEY`, ruling out the rule silently
   pushing 0 (which would let the script continue).

2. **checksigadd-spec.k** — symbolic `OP_CHECKSIGADD` with empty sig: prove it
   pushes `N` unchanged (no budget cost, no error). Rules out CHECKSIGADD treating
   an empty sig as a failed verification and decrementing N.

3. **op-success-spec.k** — prove that any `OP_SUCCESS` opcode byte in a tapscript
   causes the script to succeed unconditionally (ext_flag=1 spend passes even if
   the rest of the script would fail). Rules out OP_SUCCESS opcodes being decoded
   as OP_INVALIDOPCODE.

4. **sigops-budget-exhausted-spec.k** — prove that 51 CHECKSIG-equivalent ops
   (budget = 50 * 50 = 2500 weight; 51 * 50 = 2550 > 2500) in a single tapscript
   halts with `TAPSCRIPT_VALIDATION_WEIGHT`. Rules out the budget cell not being
   decremented per verify.

5. **p2tr-keypath-spec.k** — concrete key-path P2TR spend with a valid Schnorr
   signature proves success. Rules out the BIP-341 output-key-validation step
   (secp256k1_xonly_pubkey_tweak_add_check) being bypassed.

6. **leaf-version-success-spec.k** — a script-path spend with an unrecognised leaf
   version byte (not 0xC0) must succeed unconditionally (OP_SUCCESS for unknown
   leaf versions). Rules out the decoder rejecting unknown leaf versions.

7. **annex-stripping-spec.k** — prove that a witness stack whose last non-script
   item starts with 0x50 (annex prefix) is stripped before execution, and the
   annex hash is folded into the BIP-341 sigmsg. Rules out the annex being left
   on the execution stack or ignored in the sighash.

8. **witness-stack-limit-spec.k** — a tapscript execution that builds > 1,000 stack
   items must halt with a stack-size error. Rules out the stack size check being
   absent in witness-v1 mode.

9. **nullfail-tapscript-absent-spec.k** — in tapscript, a failed CHECKSIG with a
   non-empty sig must halt with `SCHNORR_SIG` (not `NULLFAIL`), because NULLFAIL
   does not apply in tapscript. Rules out the NULLFAIL check firing in witness-v1.

10. **codesep-pos-spec.k** — symbolic proof that after an OP_CODESEPARATOR at byte
    offset `P` in a tapscript, the BIP-342 sigmsg's `codesep_pos` field equals `P`
    (not 0xFFFFFFFF). Rules out the codesep_pos cell not being updated on
    OP_CODESEPARATOR execution.

---

## Running proofs

```sh
uv run kdist build bitcoin-script-semantics.haskell  # one-time
just test-prove                                       # all specs via pytest
just prove htlc-spec                                  # single spec via examples/justfile
```

## Architecture

- `script.k` — LLVM execution entry point (no lemmas)
- `script-verification.k` — Haskell proof entry point (imports lemmas)
- `lemmas.k` — 14 simplification rules for symbolic CScriptNum reasoning
