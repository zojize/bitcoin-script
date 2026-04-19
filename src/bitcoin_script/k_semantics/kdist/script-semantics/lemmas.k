// Simplification lemmas for the K Haskell backend prover.
//
// These enable symbolic reasoning about CScriptNum encoding — needed for
// proofs over all valid inputs (e.g. "OP_ADD(A,B) == A+B for any A,B").
//
// Concrete byte-level proofs (timelock, htlc) don't need these — the
// Haskell backend evaluates byte literals natively.

module LEMMAS
  imports SCRIPT-NUM
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

endmodule
