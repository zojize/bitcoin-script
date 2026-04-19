// Formal proofs about OP_EQUALVERIFY behavior.
//
// OP_EQUALVERIFY pops two values: if equal, execution continues;
// if not equal, execution fails with "EQUALVERIFY" error.

module EQUALVERIFY-SPEC
  imports SCRIPT-VERIFICATION

  // Claim 1: EQUALVERIFY passes when both values match
  // scriptSig pushes 5 (OP_5=0x55), scriptPubKey pushes 5 then EQUALVERIFY then TRUE
  // OP_5 OP_5 EQUALVERIFY OP_TRUE: the two 5s match, EQUALVERIFY pops both,
  // then OP_TRUE pushes b"\x01" as the final truthy stack value.
  claim [equalverify-match]:
      <k> #init => .K </k>
      <stack> .List => ListItem(b"\x01") </stack>
      <altstack> .List </altstack>
      <exec> .List </exec>
      <phase> scriptSig => done </phase>
      <error> "" => "" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> b"\x55" </scriptSigBytes> // OP_5
      <scriptPubKeyBytes> b"\x55\x88\x51" </scriptPubKeyBytes> // OP_5 EQUALVERIFY OP_TRUE
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

  // Claim 2: EQUALVERIFY fails when values differ
  // scriptSig pushes 3 (OP_3=0x53), scriptPubKey pushes 5 then EQUALVERIFY
  // 3 != 5, so EQUALVERIFY fires the "EQUALVERIFY" error.
  claim [equalverify-mismatch]:
      <k> #init => .K </k>
      <stack> .List => ?_ </stack>
      <altstack> .List </altstack>
      <exec> .List => ?_ </exec>
      <phase> scriptSig => ?_ </phase>
      <error> "" => "EQUALVERIFY" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> b"\x53" </scriptSigBytes> // OP_3
      <scriptPubKeyBytes> b"\x55\x88\x51" </scriptPubKeyBytes> // OP_5 EQUALVERIFY OP_TRUE
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
