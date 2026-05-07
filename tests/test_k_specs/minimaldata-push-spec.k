// Formal proofs of push-level MINIMALDATA enforcement.
//
// The MINIMALDATA flag (64) requires that data pushes use the smallest
// possible opcode. PUSHDATA1 (opcode 76) for a 1-byte value is non-minimal
// — the correct encoding is PUSHBYTES_1 (opcode 1 = length of data).
//
// These claims prove:
//   1. PUSHDATA1 for a 1-byte value is accepted without the flag
//   2. PUSHDATA1 for a 1-byte value is rejected with the flag
//   3. PUSHBYTES_1 for the same value is accepted even with the flag

module MINIMALDATA-PUSH-SPEC
  imports SCRIPT-VERIFICATION

  // =========================================================================
  // Script: PUSHDATA1 <01> <2a>  (b"\x4c\x01\x2a")
  // Pushes 0x2a (42) via PUSHDATA1 — non-minimal for a 1-byte value.
  // Without MINIMALDATA: accepted, stack = [0x2a]
  // =========================================================================

  claim [pushdata1-non-minimal-accepted-without-flag]:
      <k> #init => .K </k>
      <stack> .List => ListItem(b"\x2a") </stack>
      <altstack> .List </altstack>
      <exec> .List </exec>
      <phase> scriptSig => done </phase>
      <error> "" => "" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> b"" </scriptSigBytes>
      <scriptPubKeyBytes> b"\x4c\x01\x2a" </scriptPubKeyBytes> // PUSHDATA1 1 0x2a
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
  // Same script with MINIMALDATA flag (64): rejected.
  // PUSHDATA1 for a 1-byte non-special value is non-minimal;
  // the decoder emits OP_PUSHDATA(76, b"\x2a") and the execution rule
  // checks #isMinimalPush(76, b"\x2a") => false => MINIMALDATA error.
  // =========================================================================

  claim [pushdata1-non-minimal-rejected-with-flag]:
      <k> #init => .K </k>
      <stack> .List => ?_ </stack>
      <altstack> .List </altstack>
      <exec> .List => ?_ </exec>
      <phase> scriptSig => ?_ </phase>
      <error> "" => "MINIMALDATA" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> b"" </scriptSigBytes>
      <scriptPubKeyBytes> b"\x4c\x01\x2a" </scriptPubKeyBytes> // PUSHDATA1 1 0x2a
      <witness> .Bytes </witness>
      <savedStack> .List </savedStack>
      <opCount> 0 => ?_ </opCount>
      <flags> 64 </flags>
      <txVersion> 1 </txVersion>
      <nLockTime> 0 </nLockTime>
      <nSequence> 4294967295 </nSequence>
      <witnessUsed> false </witnessUsed>
      <p2shRedeemBytes> .Bytes </p2shRedeemBytes>
      <codesepIdx> 0 </codesepIdx>

  // =========================================================================
  // Script: PUSHBYTES_1 <2a>  (b"\x01\x2a")
  // Pushes 0x2a via the minimal PUSHBYTES_1 opcode.
  // With MINIMALDATA flag (64): accepted — #isMinimalPush(1, b"\x2a") = true.
  // =========================================================================

  claim [pushbytes1-minimal-accepted-with-flag]:
      <k> #init => .K </k>
      <stack> .List => ListItem(b"\x2a") </stack>
      <altstack> .List </altstack>
      <exec> .List </exec>
      <phase> scriptSig => done </phase>
      <error> "" => "" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> b"" </scriptSigBytes>
      <scriptPubKeyBytes> b"\x01\x2a" </scriptPubKeyBytes> // PUSHBYTES_1 0x2a
      <witness> .Bytes </witness>
      <savedStack> .List </savedStack>
      <opCount> 0 => ?_ </opCount>
      <flags> 64 </flags>
      <txVersion> 1 </txVersion>
      <nLockTime> 0 </nLockTime>
      <nSequence> 4294967295 </nSequence>
      <witnessUsed> false </witnessUsed>
      <p2shRedeemBytes> .Bytes </p2shRedeemBytes>
      <codesepIdx> 0 </codesepIdx>

endmodule