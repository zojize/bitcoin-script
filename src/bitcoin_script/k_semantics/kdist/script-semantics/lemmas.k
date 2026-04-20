// Simplification lemmas for the K Haskell backend prover.
//
// These enable symbolic reasoning about CScriptNum encoding — needed for
// proofs over all valid inputs (e.g. "OP_ADD(A,B) == A+B for any A,B").
//
// Concrete byte-level proofs (timelock, htlc) don't need these — the
// Haskell backend evaluates byte literals natively.

module LEMMAS
  imports SCRIPT-NUM
  imports SCRIPT-SIGHASH
  imports BITCOIN-SIGHASH
  imports INT
  imports BYTES
  imports BOOL

  // =========================================================================
  // CScriptNum roundtrip: the key lemma for arithmetic proofs
  // =========================================================================

  // scriptNumToInt(intToScriptNum(N)) == N for all valid N
  rule scriptNumToInt(intToScriptNum(N)) => N
    requires N >=Int -2147483647 andBool N <=Int 2147483647 [simplification]

  // intToScriptNum always produces valid-length output
  rule validNumFlags(intToScriptNum(N), _F) => true
    requires N >=Int -2147483647 andBool N <=Int 2147483647 [simplification]

  // Also valid for negated values
  rule validNumFlags(intToScriptNum(0 -Int N), _F) => true
    requires N >=Int -2147483647 andBool N <=Int 2147483647 [simplification]

  // =========================================================================
  // Range preservation under negation
  // =========================================================================

  rule (0 -Int N) >=Int -2147483647 => true
    requires N <=Int 2147483647 [simplification, smt-lemma]

  rule (0 -Int N) <=Int 2147483647 => true
    requires N >=Int -2147483647 [simplification, smt-lemma]

  // =========================================================================
  // Sign of negation (needed for intToScriptNum branch selection)
  // =========================================================================

  rule (0 -Int N) >Int 0 => true
    requires N <Int 0 [simplification, smt-lemma]

  rule (0 -Int N) <Int 0 => true
    requires N >Int 0 [simplification, smt-lemma]

  // =========================================================================
  // absInt simplification
  // =========================================================================

  rule absInt(N) => N requires N >=Int 0 [simplification]
  rule absInt(N) => 0 -Int N requires N <Int 0 [simplification]

  rule absInt(N) >=Int 0 => true
    requires N >=Int -2147483647 [simplification, smt-lemma]

  rule absInt(N) <=Int 2147483647 => true
    requires N >=Int -2147483647 andBool N <=Int 2147483647 [simplification, smt-lemma]

  // =========================================================================
  // intToScriptNum is injective
  // =========================================================================

  rule { intToScriptNum(A) #Equals intToScriptNum(B) } => { A #Equals B } [simplification]

  // =========================================================================
  // #boolToBytes simplification (needed when OP_NOT / OP_NUMEQUAL / OP_LESSTHAN /
  // OP_WITHIN / OP_BOOLAND / OP_BOOLOR etc. are symbolically executed by the
  // Haskell backend — function-rule evaluation doesn't fire on symbolic Bools).
  // The conditional form allows the prover to case-split on a symbolic Bool
  // that the path condition already implies is true or false.
  // =========================================================================

  rule #boolToBytes(B:Bool) => intToScriptNum(1)
    requires B                         [simplification]
  rule #boolToBytes(B:Bool) => intToScriptNum(0)
    requires notBool B                 [simplification]

  // =========================================================================
  // Bitcoin-sighash-plugin equivalence lemmas.
  //
  // Each bulk SHA-256 streaming hook (BitcoinXStream) performs the same
  // field-by-field SHA256_Update sequence as its pure-K walker
  // (#streamXPure). The LLVM backend calls the hook directly for speed;
  // the Haskell prover unfolds the hook into the pure walker via these
  // [simplification] rules so symbolic inputs can be reasoned about
  // inductively.
  //
  // Asserted, not derived — the trust boundary is: we trust that the C
  // implementation of each hook matches its documented behavior. Cross-
  // checked by test_tx_vectors (any divergence would make sighash
  // mismatch Bitcoin Core's expected values and the test fails).
  // =========================================================================

  rule [bitcoin-outpoints-stream-equiv]:
    BitcoinOutpointsStream(S, TX, O, N) =>
      #streamOutpointsPure(S, TX, O, N)
    [simplification]

  rule [bitcoin-sequences-stream-equiv]:
    BitcoinSequencesStream(S, TX, O, N) =>
      #streamSequencesPure(S, TX, O, N)
    [simplification]

  rule [bitcoin-vouts-stream-equiv]:
    BitcoinVoutsStream(S, TX, O, N) =>
      #streamVoutsPure(S, TX, O, N)
    [simplification]

  rule [bitcoin-prevout-amounts-stream-equiv]:
    BitcoinPrevoutAmountsStream(S, P, N) =>
      #streamPrevoutAmountsPure(S, P, 0, N)
    [simplification]

  rule [bitcoin-prevout-scripts-stream-equiv]:
    BitcoinPrevoutScriptsStream(S, P, N) =>
      #streamPrevoutScriptsPure(S, P, 0, N)
    [simplification]

  // The legacy vins / vouts block hooks emit a compactSize(n) prefix and
  // then walk through the respective records with the per-record legacy
  // modifications (target-vin scriptCode, SIGHASH_SINGLE placeholders,
  // zeroed sequences for NONE/SINGLE). The pure-K variants are the
  // #streamLegacyVinsBlockPure / #streamLegacyVoutsBlockPure rules.
  // Their equivalence requires the prover to reason about the
  // compact-size byte layout; uses of these hooks in proofs are rare
  // (sighash itself is opaque to the prover today), so stating the
  // lemma as a single unfold is sufficient for future work.
  rule [bitcoin-legacy-vins-block-stream-equiv]:
    BitcoinLegacyVinsBlockStream(S, TX, O, N, IDX, SC, HT) =>
      #streamLegacyVins(Sha256Update(S, #bip143CompactSize(N)),
                        TX, O, 0, N, IDX, SC, HT)
    [simplification]

  rule [bitcoin-legacy-vouts-block-stream-equiv]:
    BitcoinLegacyVoutsBlockStream(S, TX, O, N, IDX, HT) =>
      #streamLegacyVouts(Sha256Update(S, #bip143CompactSize(N)),
                         TX, O, 0, N, IDX, HT)
    [simplification]

endmodule
