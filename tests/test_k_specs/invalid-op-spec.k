// Formal proofs that specific arithmetic disabled opcodes always fail.
//
// OP_MUL (0x95), OP_LSHIFT (0x98), and related opcodes (OP_DIV, OP_MOD,
// OP_RSHIFT) were disabled post-genesis due to non-determinism concerns.
// The decoder emits bare OP_INVALIDOPCODE (not #guardExec(OP_INVALIDOPCODE)),
// so these fail even inside dead IF/ELSE branches — unlike OP_RETURN which
// is wrapped in #guardExec and can be skipped.
//
// Compare with disabled-ops-spec.k which proves OP_CAT behaves the same way.

module INVALID-OP-SPEC
  imports SCRIPT-VERIFICATION

  // =========================================================================
  // OP_MUL (0x95 = 149) in a live branch fails immediately.
  // =========================================================================

  claim [mul-disabled-in-live-branch]:
      <k> #init => .K </k>
      <stack> .List => ?_ </stack>
      <altstack> .List </altstack>
      <exec> .List => ?_ </exec>
      <phase> scriptSig => ?_ </phase>
      <error> "" => "DISABLED_OPCODE" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> b"" </scriptSigBytes>
      <scriptPubKeyBytes> b"\x95" </scriptPubKeyBytes> // OP_MUL
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
  // OP_LSHIFT (0x98 = 152) in a live branch fails immediately.
  // =========================================================================

  claim [lshift-disabled-in-live-branch]:
      <k> #init => .K </k>
      <stack> .List => ?_ </stack>
      <altstack> .List </altstack>
      <exec> .List => ?_ </exec>
      <phase> scriptSig => ?_ </phase>
      <error> "" => "DISABLED_OPCODE" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> b"" </scriptSigBytes>
      <scriptPubKeyBytes> b"\x98" </scriptPubKeyBytes> // OP_LSHIFT
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
  // OP_MUL in a dead IF branch still fails — OP_INVALIDOPCODE bypasses
  // the execution guard entirely.
  //
  // Script: OP_0 IF OP_MUL ENDIF OP_1 = b"\x00\x63\x95\x68\x51"
  // The IF condition is false, but the decoder emits bare OP_INVALIDOPCODE
  // (not wrapped in #guardExec), so it fires unconditionally before OP_1.
  // =========================================================================

  claim [mul-disabled-in-dead-branch]:
      <k> #init => .K </k>
      <stack> .List => ?_ </stack>
      <altstack> .List </altstack>
      <exec> .List => ?_ </exec>
      <phase> scriptSig => ?_ </phase>
      <error> "" => "DISABLED_OPCODE" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> b"" </scriptSigBytes>
      <scriptPubKeyBytes> b"\x00\x63\x95\x68\x51" </scriptPubKeyBytes> // OP_0 IF OP_MUL ENDIF OP_1
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