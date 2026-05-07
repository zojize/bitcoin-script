// Formal proofs of OP_RETURN behavior in different execution contexts.
//
// OP_RETURN (0x6a) is encoded by the decoder as #guardExec(OP_RETURN),
// so it respects the execution guard: it halts execution in live branches
// but is silently skipped when inside a dead IF branch.
//
// This contrasts with disabled opcodes (OP_CAT, OP_MUL, etc.) which are
// decoded as bare OP_INVALIDOPCODE — bypassing the guard and failing even
// in dead branches (see disabled-ops-spec.k and invalid-op-spec.k).

module OP-RETURN-SPEC
  imports SCRIPT-VERIFICATION

  // =========================================================================
  // OP_RETURN in a live branch always halts with OP_RETURN error.
  //
  // Script: OP_1 OP_RETURN = b"\x51\x6a"
  // OP_1 succeeds, then OP_RETURN immediately aborts execution.
  // =========================================================================

  claim [op-return-after-push-fails]:
      <k> #init => .K </k>
      <stack> .List => ?_ </stack>
      <altstack> .List </altstack>
      <exec> .List => ?_ </exec>
      <phase> scriptSig => ?_ </phase>
      <error> "" => "OP_RETURN" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> b"" </scriptSigBytes>
      <scriptPubKeyBytes> b"\x51\x6a" </scriptPubKeyBytes> // OP_1 OP_RETURN
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
  // OP_RETURN inside a dead IF branch is skipped entirely.
  //
  // Script: OP_0 IF OP_RETURN ENDIF OP_1 = b"\x00\x63\x6a\x68\x51"
  // OP_0 is falsy → IF branch is dead → #guardExec(OP_RETURN) is discarded.
  // OP_ENDIF restores live execution; OP_1 pushes truthy value → success.
  // =========================================================================

  claim [op-return-in-dead-branch-skipped]:
      <k> #init => .K </k>
      <stack> .List => ListItem(b"\x01") </stack>
      <altstack> .List </altstack>
      <exec> .List </exec>
      <phase> scriptSig => done </phase>
      <error> "" => "" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> b"" </scriptSigBytes>
      <scriptPubKeyBytes> b"\x00\x63\x6a\x68\x51" </scriptPubKeyBytes> // OP_0 IF OP_RETURN ENDIF OP_1
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
  // OP_RETURN in scriptSig halts before scriptPubKey executes.
  //
  // scriptSig: OP_RETURN = b"\x6a"
  // scriptPubKey: OP_1 = b"\x51"
  // Without SIGPUSHONLY flag (flags=0), OP_RETURN is a valid scriptSig opcode
  // but immediately aborts execution with OP_RETURN error.
  // =========================================================================

  claim [op-return-in-scriptsig-fails]:
      <k> #init => .K </k>
      <stack> .List => ?_ </stack>
      <altstack> .List </altstack>
      <exec> .List => ?_ </exec>
      <phase> scriptSig => ?_ </phase>
      <error> "" => "OP_RETURN" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> b"\x6a" </scriptSigBytes> // OP_RETURN
      <scriptPubKeyBytes> b"\x51" </scriptPubKeyBytes> // OP_1 (never reached)
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