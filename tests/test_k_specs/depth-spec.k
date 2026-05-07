// Formal proofs of OP_IFDUP and OP_DEPTH correct stack behavior.
//
// OP_IFDUP (0x73): duplicates the top element only if it is truthy;
//   falsy top (empty bytes, zero, negative-zero) is left unchanged.
//
// OP_DEPTH (0x74): pushes the current stack size as a CScriptNum onto
//   the stack. Empty stack → 0 (b""), two items → 2 (b"\x02"), etc.

module DEPTH-SPEC
  imports SCRIPT-VERIFICATION

  // =========================================================================
  // OP_IFDUP with a truthy top: top element is duplicated.
  //
  // Script: OP_1 OP_IFDUP = b"\x51\x73"
  // OP_1 pushes b"\x01" (truthy) → OP_IFDUP duplicates it.
  // Final stack: [b"\x01", b"\x01"]
  // =========================================================================

  claim [ifdup-truthy-duplicates]:
      <k> #init => .K </k>
      <stack> .List => ListItem(b"\x01") ListItem(b"\x01") </stack>
      <altstack> .List </altstack>
      <exec> .List </exec>
      <phase> scriptSig => done </phase>
      <error> "" => "" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> b"" </scriptSigBytes>
      <scriptPubKeyBytes> b"\x51\x73" </scriptPubKeyBytes> // OP_1 OP_IFDUP
      <witness> .Bytes </witness>
      <savedStack> .List </savedStack>
      <opCount> 0 => ?_ </opCount>
      <flags> 0 </flags>
      <txVersion> 1 </txVersion>
      <nLockTime> 0 </nLockTime>
      <nSequence> 4294967295 </nSequence>
      <witnessUsed> false </witnessUsed>
      <p2shRedeemBytes> .Bytes </p2shRedeemBytes>
      <codesepIdx> 0 </codesepIdx>

  // =========================================================================
  // OP_IFDUP with a falsy top: top element is left unchanged.
  //
  // Script: OP_0 OP_IFDUP = b"\x00\x73"
  // OP_0 pushes b"" (empty bytes = 0 = falsy) → OP_IFDUP does nothing.
  // Final stack: [b""]
  // =========================================================================

  claim [ifdup-falsy-unchanged]:
      <k> #init => .K </k>
      <stack> .List => ListItem(b"") </stack>
      <altstack> .List </altstack>
      <exec> .List </exec>
      <phase> scriptSig => done </phase>
      <error> "" => "" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> b"" </scriptSigBytes>
      <scriptPubKeyBytes> b"\x00\x73" </scriptPubKeyBytes> // OP_0 OP_IFDUP
      <witness> .Bytes </witness>
      <savedStack> .List </savedStack>
      <opCount> 0 => ?_ </opCount>
      <flags> 0 </flags>
      <txVersion> 1 </txVersion>
      <nLockTime> 0 </nLockTime>
      <nSequence> 4294967295 </nSequence>
      <witnessUsed> false </witnessUsed>
      <p2shRedeemBytes> .Bytes </p2shRedeemBytes>
      <codesepIdx> 0 </codesepIdx>

  // =========================================================================
  // OP_DEPTH on an empty stack: pushes 0 (encoded as b"", empty bytes).
  //
  // Script: OP_DEPTH = b"\x74"
  // Stack before: [] (size 0) → OP_DEPTH pushes intToScriptNum(0) = b""
  // Final stack: [b""]
  // =========================================================================

  claim [depth-empty-stack]:
      <k> #init => .K </k>
      <stack> .List => ListItem(b"") </stack>
      <altstack> .List </altstack>
      <exec> .List </exec>
      <phase> scriptSig => done </phase>
      <error> "" => "" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> b"" </scriptSigBytes>
      <scriptPubKeyBytes> b"\x74" </scriptPubKeyBytes> // OP_DEPTH
      <witness> .Bytes </witness>
      <savedStack> .List </savedStack>
      <opCount> 0 => ?_ </opCount>
      <flags> 0 </flags>
      <txVersion> 1 </txVersion>
      <nLockTime> 0 </nLockTime>
      <nSequence> 4294967295 </nSequence>
      <witnessUsed> false </witnessUsed>
      <p2shRedeemBytes> .Bytes </p2shRedeemBytes>
      <codesepIdx> 0 </codesepIdx>

  // =========================================================================
  // OP_DEPTH with two items: pushes 2 (encoded as b"\x02").
  //
  // Script: OP_1 OP_1 OP_DEPTH = b"\x51\x51\x74"
  // Stack before OP_DEPTH: [b"\x01", b"\x01"] (size 2)
  // OP_DEPTH pushes intToScriptNum(2) = b"\x02"
  // Final stack: [b"\x02", b"\x01", b"\x01"]
  // =========================================================================

  claim [depth-two-items]:
      <k> #init => .K </k>
      <stack> .List => ListItem(b"\x02") ListItem(b"\x01") ListItem(b"\x01") </stack>
      <altstack> .List </altstack>
      <exec> .List </exec>
      <phase> scriptSig => done </phase>
      <error> "" => "" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> b"" </scriptSigBytes>
      <scriptPubKeyBytes> b"\x51\x51\x74" </scriptPubKeyBytes> // OP_1 OP_1 OP_DEPTH
      <witness> .Bytes </witness>
      <savedStack> .List </savedStack>
      <opCount> 0 => ?_ </opCount>
      <flags> 0 </flags>
      <txVersion> 1 </txVersion>
      <nLockTime> 0 </nLockTime>
      <nSequence> 4294967295 </nSequence>
      <witnessUsed> false </witnessUsed>
      <p2shRedeemBytes> .Bytes </p2shRedeemBytes>
      <codesepIdx> 0 </codesepIdx>

endmodule