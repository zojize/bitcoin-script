// Formal proofs about OP_CHECKLOCKTIMEVERIFY (CLTV) behavior.

module TIMELOCK-SPEC
  imports SCRIPT-VERIFICATION

  // All claims use: <100> OP_CHECKLOCKTIMEVERIFY OP_DROP OP_TRUE
  // = 0x01 0x64 0xb1 0x75 0x51 = b"\x01\x64\xb1\x75\x51"

  // Claim 1: CLTV passes when nLockTime >= threshold
  claim [cltv-pass-block-height]:
      <k> #init => .K </k>
      <stack> .List => ListItem(b"\x01") </stack>
      <altstack> .List </altstack>
      <exec> .List </exec>
      <phase> scriptSig => done </phase>
      <error> "" => "" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> .Bytes </scriptSigBytes>
      <scriptPubKeyBytes> b"\x01\x64\xb1\x75\x51" </scriptPubKeyBytes> // <100> CHECKLOCKTIMEVERIFY DROP TRUE
      <witness> .Bytes </witness>
      <savedStack> .List </savedStack>
      <opCount> 0 => ?_ </opCount>
      <flags> 512 </flags>
      <txVersion> 1 </txVersion>
      <nLockTime> 200 </nLockTime>
      <nSequence> 4294967294 </nSequence>
      <witnessUsed> false </witnessUsed>
      <p2shRedeemBytes> .Bytes </p2shRedeemBytes>
      <codesepIdx> 0 </codesepIdx>

  // Claim 2: CLTV is a NOP when flag is not set
  claim [cltv-nop-without-flag]:
      <k> #init => .K </k>
      <stack> .List => ListItem(b"\x01") </stack>
      <altstack> .List </altstack>
      <exec> .List </exec>
      <phase> scriptSig => done </phase>
      <error> "" => "" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> .Bytes </scriptSigBytes>
      <scriptPubKeyBytes> b"\x01\x64\xb1\x75\x51" </scriptPubKeyBytes> // <100> CHECKLOCKTIMEVERIFY DROP TRUE
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

  // Claim 3: CLTV fails when nLockTime < threshold
  claim [cltv-fail-too-early]:
      <k> #init => .K </k>
      <stack> .List => ?_ </stack>
      <altstack> .List </altstack>
      <exec> .List => ?_ </exec>
      <phase> scriptSig => ?_ </phase>
      <error> "" => "UNSATISFIED_LOCKTIME" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> .Bytes </scriptSigBytes>
      <scriptPubKeyBytes> b"\x01\x64\xb1\x75\x51" </scriptPubKeyBytes> // <100> CHECKLOCKTIMEVERIFY DROP TRUE
      <witness> .Bytes </witness>
      <savedStack> .List </savedStack>
      <opCount> 0 => ?_ </opCount>
      <flags> 512 </flags>
      <txVersion> 1 </txVersion>
      <nLockTime> 50 </nLockTime>
      <nSequence> 4294967294 </nSequence>
      <witnessUsed> false </witnessUsed>
      <p2shRedeemBytes> .Bytes </p2shRedeemBytes>
      <codesepIdx> 0 </codesepIdx>

  // Claim 4: CLTV fails when nSequence is final
  claim [cltv-fail-final-sequence]:
      <k> #init => .K </k>
      <stack> .List => ?_ </stack>
      <altstack> .List </altstack>
      <exec> .List => ?_ </exec>
      <phase> scriptSig => ?_ </phase>
      <error> "" => "UNSATISFIED_LOCKTIME" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> .Bytes </scriptSigBytes>
      <scriptPubKeyBytes> b"\x01\x64\xb1\x75\x51" </scriptPubKeyBytes> // <100> CHECKLOCKTIMEVERIFY DROP TRUE
      <witness> .Bytes </witness>
      <savedStack> .List </savedStack>
      <opCount> 0 => ?_ </opCount>
      <flags> 512 </flags>
      <txVersion> 1 </txVersion>
      <nLockTime> 200 </nLockTime>
      <nSequence> 4294967295 </nSequence>
      <witnessUsed> false </witnessUsed>
      <p2shRedeemBytes> .Bytes </p2shRedeemBytes>
      <codesepIdx> 0 </codesepIdx>

endmodule
