// CScriptNum encoding correctness at boundary values.
//
// intToScriptNum encodes integers as variable-length LE sign-magnitude.
// These claims verify the encoding is correct at tricky boundaries
// where byte width changes or sign padding is needed.
//
// Each claim pushes a concrete integer and verifies the stack contains
// the expected byte encoding.

module SCRIPTNUM-SPEC
  imports SCRIPT-VERIFICATION

  // 0 encodes as empty bytes (OP_0 pushes b"")
  // Script: OP_0 = b"\x00"
  claim [encode-zero]:
      <k> #init => .K </k>
      <stack> .List => ListItem(b"") </stack>
      <altstack> .List </altstack>
      <exec> .List </exec>
      <phase> scriptSig => done </phase>
      <error> "" => "" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> b"" </scriptSigBytes>
      <scriptPubKeyBytes> b"\x00" </scriptPubKeyBytes> // OP_0
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

  // 1 + (-1) = 0. Tests that OP_1NEGATE is correctly handled and
  // that adding 1 + (-1) produces 0 (encoded as empty bytes).
  // Script: OP_1(51) OP_1NEGATE(4f) OP_ADD(93) = b"\x51\x4f\x93"
  claim [one-plus-neg-one-is-zero]:
      <k> #init => .K </k>
      <stack> .List => ListItem(b"") </stack>
      <altstack> .List </altstack>
      <exec> .List </exec>
      <phase> scriptSig => done </phase>
      <error> "" => "" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> b"" </scriptSigBytes>
      <scriptPubKeyBytes> b"\x51\x4f\x93" </scriptPubKeyBytes> // OP_1 OP_1NEGATE ADD
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

  // 127 + 1 = 128. Tests the 1-byte to 2-byte boundary.
  // 127 = b"\x7f" (1 byte), 128 = b"\x80\x00" (2 bytes, sign pad needed)
  // Script: push1(01) 7f(=127) OP_1ADD(8b) push2(02) 80 00(=128) OP_EQUAL(87)
  // = b"\x01\x7f\x8b\x02\x80\x00\x87"
  claim [boundary-127-plus-1]:
      <k> #init => .K </k>
      <stack> .List => ListItem(b"\x01") </stack>
      <altstack> .List </altstack>
      <exec> .List </exec>
      <phase> scriptSig => done </phase>
      <error> "" => "" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> b"" </scriptSigBytes>
      <scriptPubKeyBytes> b"\x01\x7f\x8b\x02\x80\x00\x87" </scriptPubKeyBytes> // <127> 1ADD <128> EQUAL
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

  // NEGATE(1) = -1. Checks sign bit encoding.
  // -1 = b"\x81" (0x01 with sign bit set)
  // Script: OP_1(51) OP_NEGATE(8f) push1(01) 81(=-1) OP_EQUAL(87)
  // = b"\x51\x8f\x01\x81\x87"
  claim [negate-one-is-minus-one]:
      <k> #init => .K </k>
      <stack> .List => ListItem(b"\x01") </stack>
      <altstack> .List </altstack>
      <exec> .List </exec>
      <phase> scriptSig => done </phase>
      <error> "" => "" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> b"" </scriptSigBytes>
      <scriptPubKeyBytes> b"\x51\x8f\x01\x81\x87" </scriptPubKeyBytes> // OP_1 NEGATE <-1> EQUAL
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
