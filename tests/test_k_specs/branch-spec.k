// IF/ELSE/ENDIF: exactly one branch executes depending on input.
//
// Script: OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF = b"\x63\x52\x67\x53\x68"
// Truthy input -> pushes 2, falsy input -> pushes 3.

module BRANCH-SPEC
  imports SCRIPT-VERIFICATION

  // Truthy input (OP_TRUE in scriptSig): IF branch executes, result is 2
  claim [if-true-takes-if-branch]:
      <k> #init => .K </k>
      <stack> .List => ListItem(b"\x02") </stack>
      <altstack> .List </altstack>
      <exec> .List </exec>
      <phase> scriptSig => done </phase>
      <error> "" => "" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> b"\x51" </scriptSigBytes> // OP_TRUE
      <scriptPubKeyBytes> b"\x63\x52\x67\x53\x68" </scriptPubKeyBytes> // IF OP_2 ELSE OP_3 ENDIF
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

  // Falsy input (OP_FALSE in scriptSig): ELSE branch executes, result is 3
  claim [if-false-takes-else-branch]:
      <k> #init => .K </k>
      <stack> .List => ListItem(b"\x03") </stack>
      <altstack> .List </altstack>
      <exec> .List </exec>
      <phase> scriptSig => done </phase>
      <error> "" => "" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> b"\x00" </scriptSigBytes> // OP_FALSE
      <scriptPubKeyBytes> b"\x63\x52\x67\x53\x68" </scriptPubKeyBytes> // IF OP_2 ELSE OP_3 ENDIF
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
