// Formal proofs that #guardExec correctly skips opcodes in dead IF branches.
//
// Unlike disabled opcodes (which bypass #guardExec and always fail),
// regular opcodes wrapped in #guardExec are silently discarded when
// the exec stack indicates a dead branch. This proves that:
// 1. OP_ADD in a dead branch doesn't execute (which would crash on empty stack)
// 2. OP_RESERVED in a dead branch doesn't fire BAD_OPCODE

module GUARDEXEC-SPEC
  imports SCRIPT-VERIFICATION

  // Claim 1: OP_ADD in dead IF branch is skipped via #guardExec
  // Script: OP_0 IF OP_ADD ELSE OP_TRUE ENDIF = b"\x00\x63\x93\x67\x51\x68"
  // OP_0 pushes false, so IF takes the ELSE branch. OP_ADD in the dead
  // branch would fail (stack underflow) if executed, but #guardExec
  // discards it. The ELSE branch pushes OP_TRUE (b"\x01").
  claim [dead-branch-skips-add]:
      <k> #init => .K </k>
      <stack> .List => ListItem(b"\x01") </stack>
      <altstack> .List </altstack>
      <exec> .List </exec>
      <phase> scriptSig => done </phase>
      <error> "" => "" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> .Bytes </scriptSigBytes>
      <scriptPubKeyBytes> b"\x00\x63\x93\x67\x51\x68" </scriptPubKeyBytes> // OP_0 IF OP_ADD ELSE OP_TRUE ENDIF
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

  // Claim 2: OP_RESERVED (0x50) in dead IF branch is skipped via #guardExec
  // Script: OP_0 IF OP_RESERVED ELSE OP_TRUE ENDIF = b"\x00\x63\x50\x67\x51\x68"
  // OP_RESERVED is decoded as #guardExec(OP_RESERVED_OP), which is discarded
  // in the dead branch. If it executed, it would produce BAD_OPCODE.
  claim [dead-branch-skips-reserved]:
      <k> #init => .K </k>
      <stack> .List => ListItem(b"\x01") </stack>
      <altstack> .List </altstack>
      <exec> .List </exec>
      <phase> scriptSig => done </phase>
      <error> "" => "" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> .Bytes </scriptSigBytes>
      <scriptPubKeyBytes> b"\x00\x63\x50\x67\x51\x68" </scriptPubKeyBytes> // OP_0 IF OP_RESERVED ELSE OP_TRUE ENDIF
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
