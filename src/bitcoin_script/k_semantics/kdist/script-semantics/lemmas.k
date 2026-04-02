// Simplification lemmas for the K Haskell backend prover.
//
// These rules allow kprove to simplify symbolic expressions involving
// byte operations (Int2Bytes, Bytes2Int, substrBytes, lengthBytes)
// and CScriptNum encoding (intToScriptNum, scriptNumToInt).
//
// Without these, the prover gets stuck on byte-level reasoning.
// Modeled after KEVM's lemmas/bytes-simplification.k.

module LEMMAS
  imports SCRIPT-NUM
  imports INT
  imports BYTES
  imports BOOL

  // =========================================================================
  // lengthBytes simplifications
  // =========================================================================

  rule lengthBytes(.Bytes) => 0 [simplification]

  rule lengthBytes(Int2Bytes(N, _V:Int, _E:Endianness)) => N
    requires N >=Int 0 [simplification]

  rule lengthBytes(A +Bytes B) => lengthBytes(A) +Int lengthBytes(B) [simplification]

  rule 0 <=Int lengthBytes(_) => true [simplification, smt-lemma]

  // =========================================================================
  // Int2Bytes / Bytes2Int roundtrip
  // =========================================================================

  rule Bytes2Int(Int2Bytes(N, V, BE), BE, Unsigned) => V modInt (1 <<Int (8 *Int N))
    requires N >Int 0 andBool V >=Int 0 [simplification]

  rule Bytes2Int(Int2Bytes(N, V, LE), LE, Unsigned) => V modInt (1 <<Int (8 *Int N))
    requires N >Int 0 andBool V >=Int 0 [simplification]

  // When value fits in N bytes, modInt is identity
  rule V modInt (1 <<Int (8 *Int N)) => V
    requires V >=Int 0 andBool V <Int (1 <<Int (8 *Int N)) [simplification]

  // =========================================================================
  // substrBytes over concatenation
  // =========================================================================

  // Take prefix: substrBytes(A +Bytes B, 0, len(A)) => A
  rule substrBytes(A +Bytes _B, 0, N) => A
    requires lengthBytes(A) ==Int N [simplification]

  // Take suffix: substrBytes(A +Bytes B, len(A), len(A) + len(B)) => B
  rule substrBytes(A +Bytes B, S, S +Int lengthBytes(B)) => B
    requires lengthBytes(A) ==Int S [simplification]

  // =========================================================================
  // Bitwise operations on small values
  // =========================================================================

  rule V &Int 128 ==Int 0 => true
    requires V >=Int 0 andBool V <Int 128 [simplification]

  rule V &Int 128 =/=Int 0 => true
    requires V >=Int 128 andBool V <Int 256 [simplification]

  rule V &Int 127 => V
    requires V >=Int 0 andBool V <Int 128 [simplification]

  rule V &Int 127 => V -Int 128
    requires V >=Int 128 andBool V <Int 256 [simplification]

  // =========================================================================
  // CScriptNum roundtrip: scriptNumToInt(intToScriptNum(N)) == N
  //
  // This is the key lemma that enables arithmetic proofs.
  // =========================================================================

  rule scriptNumToInt(intToScriptNum(N)) => N
    requires N >=Int -2147483647 andBool N <=Int 2147483647 [simplification]

  // =========================================================================
  // validNum / validNumFlags on intToScriptNum output
  //
  // intToScriptNum always produces valid (<= 4 byte) output for inputs
  // in the CScriptNum range.
  // =========================================================================

  rule validNum(intToScriptNum(N)) => true
    requires N >=Int -2147483647 andBool N <=Int 2147483647 [simplification]

  rule validNumFlags(intToScriptNum(N), _F) => true
    requires N >=Int -2147483647 andBool N <=Int 2147483647 [simplification]

  // #isMinimalNum is always true for intToScriptNum output (it produces minimal encoding)
  rule #isMinimalNum(intToScriptNum(N)) => true
    requires N >=Int -2147483647 andBool N <=Int 2147483647 [simplification]

  // =========================================================================
  // lengthBytes on intToScriptNum output
  // =========================================================================

  rule lengthBytes(intToScriptNum(N)) <=Int 4 => true
    requires N >=Int -2147483647 andBool N <=Int 2147483647 [simplification]

  // =========================================================================
  // Arithmetic identities
  // =========================================================================

  rule 0 -Int (0 -Int N) => N [simplification]

  rule absInt(absInt(N)) => absInt(N) [simplification]

  // =========================================================================
  // intToScriptNum is injective (needed for term equality reasoning)
  // =========================================================================

  rule { intToScriptNum(A) #Equals intToScriptNum(B) } => { A #Equals B } [simplification]

  // =========================================================================
  // Range preservation: negation stays in CScriptNum range
  // =========================================================================

  rule (0 -Int N) >=Int -2147483647 => true
    requires N <=Int 2147483647 [simplification, smt-lemma]

  rule (0 -Int N) <=Int 2147483647 => true
    requires N >=Int -2147483647 [simplification, smt-lemma]

  // validNumFlags on intToScriptNum of negation
  rule validNumFlags(intToScriptNum(0 -Int N), _F) => true
    requires N >=Int -2147483647 andBool N <=Int 2147483647 [simplification]

  // validNum on intToScriptNum of negation
  rule validNum(intToScriptNum(0 -Int N)) => true
    requires N >=Int -2147483647 andBool N <=Int 2147483647 [simplification]

endmodule
