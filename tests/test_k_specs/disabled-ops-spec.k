// Formal proofs that disabled opcodes always fail, even in dead branches.
//
// The decoder emits OP_INVALIDOPCODE directly (not via #guardExec) for
// disabled opcodes like OP_CAT, OP_SUBSTR, etc. This means they fire
// the DISABLED_OPCODE error regardless of the IF/ELSE execution context.
//
// OP_RETURN is also tested here: it immediately halts execution.

module DISABLED-OPS-SPEC
  imports SCRIPT-VERIFICATION

  // Claim 1: OP_CAT (0x7e) in a live branch produces DISABLED_OPCODE
  claim [cat-fails-in-live-branch]:
      <k> #init => .K </k>
      <stack> .List => ?_ </stack>
      <altstack> .List </altstack>
      <exec> .List => ?_ </exec>
      <phase> scriptSig => ?_ </phase>
      <error> "" => "DISABLED_OPCODE" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> .Bytes </scriptSigBytes>
      <scriptPubKeyBytes> b"\x7e" </scriptPubKeyBytes> // OP_CAT
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

  // Claim 2: OP_CAT (0x7e) in a dead IF branch STILL produces DISABLED_OPCODE
  // Script: OP_0 IF OP_CAT ENDIF = b"\x00\x63\x7e\x68"
  // The IF condition is false, but OP_CAT is emitted as OP_INVALIDOPCODE
  // by the decoder (not wrapped in #guardExec), so it fires unconditionally.
  claim [cat-fails-in-dead-branch]:
      <k> #init => .K </k>
      <stack> .List => ?_ </stack>
      <altstack> .List </altstack>
      <exec> .List => ?_ </exec>
      <phase> scriptSig => ?_ </phase>
      <error> "" => "DISABLED_OPCODE" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> .Bytes </scriptSigBytes>
      <scriptPubKeyBytes> b"\x00\x63\x7e\x68" </scriptPubKeyBytes> // OP_0 IF OP_CAT ENDIF
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

  // Claim 3: OP_RETURN (0x6a) immediately halts with OP_RETURN error
  claim [return-halts-execution]:
      <k> #init => .K </k>
      <stack> .List => ?_ </stack>
      <altstack> .List </altstack>
      <exec> .List => ?_ </exec>
      <phase> scriptSig => ?_ </phase>
      <error> "" => "OP_RETURN" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> .Bytes </scriptSigBytes>
      <scriptPubKeyBytes> b"\x6a" </scriptPubKeyBytes> // OP_RETURN
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
