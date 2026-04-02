// Formal proofs about OP_CHECKLOCKTIMEVERIFY (CLTV) behavior.

module TIMELOCK-SPEC
  imports SCRIPT-SEMANTICS
  imports SCRIPT-SIG
  imports SCRIPT-FLOW
  imports SCRIPT-ARITH
  imports SCRIPT-STACK
  imports SCRIPT-DECODE

  // All claims use: <100> OP_CHECKLOCKTIMEVERIFY OP_DROP OP_TRUE
  // = 0x01 0x64 0xb1 0x75 0x51 = Int2Bytes(5, 5984318801, BE)

  // Claim 1: CLTV passes when nLockTime >= threshold
  claim [cltv-pass-block-height]:
      <k> #init => .K </k>
      <stack> .List => ListItem(Int2Bytes(1, 1, BE)) </stack>
      <altstack> .List </altstack>
      <exec> .List </exec>
      <phase> scriptSig => done </phase>
      <error> "" => "" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> .Bytes </scriptSigBytes>
      <scriptPubKeyBytes> Int2Bytes(5, 5984318801, BE) </scriptPubKeyBytes>
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
      <stack> .List => ListItem(Int2Bytes(1, 1, BE)) </stack>
      <altstack> .List </altstack>
      <exec> .List </exec>
      <phase> scriptSig => done </phase>
      <error> "" => "" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> .Bytes </scriptSigBytes>
      <scriptPubKeyBytes> Int2Bytes(5, 5984318801, BE) </scriptPubKeyBytes>
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

  // TODO: Error path claims (cltv-fail-too-early, cltv-fail-final-sequence)
  // require additional lemmas about Int2Bytes/substrBytes to prove.
  // They execute correctly via LLVM backend but the Haskell prover
  // gets stuck on byte-level reasoning without these lemmas.

endmodule
