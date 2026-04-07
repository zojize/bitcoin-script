// Phase transition: scriptSig stack is correctly passed to scriptPubKey.
//
// Proves that values pushed during scriptSig execution are available
// to scriptPubKey, and that the two-phase execution model works.

module PHASE-SPEC
  imports SCRIPT-VERIFICATION

  // scriptSig pushes 5, scriptPubKey checks == 5: succeeds
  // scriptSig = OP_5 = b"\x55"
  // scriptPubKey = OP_5 OP_EQUAL = b"\x55\x87"
  claim [sig-passes-stack-to-pubkey-match]:
      <k> #init => .K </k>
      <stack> .List => ListItem(b"\x01") </stack>
      <altstack> .List </altstack>
      <exec> .List </exec>
      <phase> scriptSig => done </phase>
      <error> "" => "" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> b"\x55" </scriptSigBytes> // OP_5
      <scriptPubKeyBytes> b"\x55\x87" </scriptPubKeyBytes> // OP_5 EQUAL
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

  // scriptSig pushes 3, scriptPubKey checks == 5: fails (stack top is falsy)
  claim [sig-passes-stack-to-pubkey-mismatch]:
      <k> #init => .K </k>
      <stack> .List => ListItem(b"") </stack>
      <altstack> .List </altstack>
      <exec> .List </exec>
      <phase> scriptSig => done </phase>
      <error> "" => "" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> b"\x53" </scriptSigBytes> // OP_3
      <scriptPubKeyBytes> b"\x55\x87" </scriptPubKeyBytes> // OP_5 EQUAL
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

  // scriptSig pushes two values (5, 3), scriptPubKey does OP_ADD OP_8 OP_EQUAL
  // 5 + 3 = 8: succeeds
  // scriptSig = OP_5 OP_3 = b"\x55\x53"
  // scriptPubKey = OP_ADD OP_8 OP_EQUAL = b"\x93\x58\x87"
  claim [sig-passes-multiple-values]:
      <k> #init => .K </k>
      <stack> .List => ListItem(b"\x01") </stack>
      <altstack> .List </altstack>
      <exec> .List </exec>
      <phase> scriptSig => done </phase>
      <error> "" => "" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> b"\x55\x53" </scriptSigBytes> // OP_5 OP_3
      <scriptPubKeyBytes> b"\x93\x58\x87" </scriptPubKeyBytes> // ADD OP_8 EQUAL
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
