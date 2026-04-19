// Formal proofs about OP_CHECKSEQUENCEVERIFY (CSV) behavior.
//
// Mirrors timelock-spec.k structure but for relative timelocks (BIP 112).
// CSV enforces that the input has been confirmed for at least N blocks/time.

module CSV-SPEC
  imports SCRIPT-VERIFICATION

  // All claims use: <10> OP_CHECKSEQUENCEVERIFY OP_DROP OP_TRUE
  // = 0x01 0x0a 0xb2 0x75 0x51 = b"\x01\x0a\xb2\x75\x51"

  // Claim 1: CSV passes when nSequence >= threshold (txVersion=2, flags=1024)
  // nSequence=20 satisfies the relative locktime of 10 blocks.
  claim [csv-pass-relative-blocks]:
      <k> #init => .K </k>
      <stack> .List => ListItem(b"\x01") </stack>
      <altstack> .List </altstack>
      <exec> .List </exec>
      <phase> scriptSig => done </phase>
      <error> "" => "" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> .Bytes </scriptSigBytes>
      <scriptPubKeyBytes> b"\x01\x0a\xb2\x75\x51" </scriptPubKeyBytes> // <10> CSV DROP TRUE
      <witness> .Bytes </witness>
      <savedStack> .List </savedStack>
      <opCount> 0 => ?_ </opCount>
      <flags> 1024 </flags>
      <txVersion> 2 </txVersion>
      <nLockTime> 0 </nLockTime>
      <nSequence> 20 </nSequence>
      <witnessUsed> false </witnessUsed>
      <p2shRedeemBytes> .Bytes </p2shRedeemBytes>
      <codesepIdx> 0 </codesepIdx>

  // Claim 2: CSV is a NOP when the CHECKSEQUENCEVERIFY flag is not set
  claim [csv-nop-without-flag]:
      <k> #init => .K </k>
      <stack> .List => ListItem(b"\x01") </stack>
      <altstack> .List </altstack>
      <exec> .List </exec>
      <phase> scriptSig => done </phase>
      <error> "" => "" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> .Bytes </scriptSigBytes>
      <scriptPubKeyBytes> b"\x01\x0a\xb2\x75\x51" </scriptPubKeyBytes> // <10> CSV DROP TRUE
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

  // Claim 3: CSV fails when nSequence < threshold
  // nSequence=5 does not satisfy the relative locktime of 10 blocks.
  claim [csv-fail-too-early]:
      <k> #init => .K </k>
      <stack> .List => ?_ </stack>
      <altstack> .List </altstack>
      <exec> .List => ?_ </exec>
      <phase> scriptSig => ?_ </phase>
      <error> "" => "UNSATISFIED_LOCKTIME" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> .Bytes </scriptSigBytes>
      <scriptPubKeyBytes> b"\x01\x0a\xb2\x75\x51" </scriptPubKeyBytes> // <10> CSV DROP TRUE
      <witness> .Bytes </witness>
      <savedStack> .List </savedStack>
      <opCount> 0 => ?_ </opCount>
      <flags> 1024 </flags>
      <txVersion> 2 </txVersion>
      <nLockTime> 0 </nLockTime>
      <nSequence> 5 </nSequence>
      <witnessUsed> false </witnessUsed>
      <p2shRedeemBytes> .Bytes </p2shRedeemBytes>
      <codesepIdx> 0 </codesepIdx>

  // Claim 4: CSV fails when txVersion < 2
  // Even though nSequence satisfies the threshold, CSV requires version >= 2.
  claim [csv-fail-old-version]:
      <k> #init => .K </k>
      <stack> .List => ?_ </stack>
      <altstack> .List </altstack>
      <exec> .List => ?_ </exec>
      <phase> scriptSig => ?_ </phase>
      <error> "" => "UNSATISFIED_LOCKTIME" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> .Bytes </scriptSigBytes>
      <scriptPubKeyBytes> b"\x01\x0a\xb2\x75\x51" </scriptPubKeyBytes> // <10> CSV DROP TRUE
      <witness> .Bytes </witness>
      <savedStack> .List </savedStack>
      <opCount> 0 => ?_ </opCount>
      <flags> 1024 </flags>
      <txVersion> 1 </txVersion>
      <nLockTime> 0 </nLockTime>
      <nSequence> 20 </nSequence>
      <witnessUsed> false </witnessUsed>
      <p2shRedeemBytes> .Bytes </p2shRedeemBytes>
      <codesepIdx> 0 </codesepIdx>

endmodule
