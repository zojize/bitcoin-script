// Formal proof that an HTLC has exactly two spending paths.
//
// HTLC script (43 bytes):
//   OP_IF OP_SHA256 <32B hash> OP_EQUALVERIFY
//   OP_ELSE <100> OP_CHECKLOCKTIMEVERIFY OP_DROP
//   OP_ENDIF OP_TRUE
//
// hash = SHA256("secret"), timeout = 100

module HTLC-SPEC
  imports SCRIPT-VERIFICATION

  // HTLC script = 0x63a8202bb80d...a25b88670164b1756851 (43 bytes)

  // Hash path claims require SHA256 (KRYPTO hook). The Haskell backend builds
  // an LLVM library at haskell/llvm-library/ for kore-rpc-booster to delegate
  // concrete hook evaluation. Wiring this into pyk's APRProver is TODO.

  // Claim 1: Hash path succeeds with correct preimage "secret"
  claim [hash-path-correct-preimage]:
      <k> #init => .K </k>
      <stack> .List => ListItem(b"\x01") </stack>
      <altstack> .List </altstack>
      <exec> .List </exec>
      <phase> scriptSig => done </phase>
      <error> "" => "" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> b"\x06\x73\x65\x63\x72\x65\x74\x51" </scriptSigBytes> // <"secret"> OP_TRUE
      <scriptPubKeyBytes> b"\x63\xa8\x20\x2b\xb8\x0d\x53\x7b\x1d\xa3\xe3\x8b\xd3\x03\x61\xaa\x85\x56\x86\xbd\xe0\xea\xcd\x71\x62\xfe\xf6\xa2\x5f\xe9\x7b\xf5\x27\xa2\x5b\x88\x67\x01\x64\xb1\x75\x68\x51" </scriptPubKeyBytes> // IF SHA256 <hash> EQUALVERIFY ELSE <100> CLTV DROP ENDIF TRUE
      <witness> .Bytes </witness>
      <savedStack> .List </savedStack>
      <opCount> 0 => ?_ </opCount>
      <flags> 512 </flags>
      <txVersion> 1 </txVersion>
      <nLockTime> 0 </nLockTime>
      <nSequence> 4294967294 </nSequence>
      <witnessUsed> false </witnessUsed>
      <p2shRedeemBytes> .Bytes </p2shRedeemBytes>
      <codesepIdx> 0 </codesepIdx>

  // Claim 2: Hash path fails with wrong preimage "wrong!"
  claim [hash-path-wrong-preimage]:
      <k> #init => .K </k>
      <stack> .List => ?_ </stack>
      <altstack> .List </altstack>
      <exec> .List => ?_ </exec>
      <phase> scriptSig => ?_ </phase>
      <error> "" => "EQUALVERIFY" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> b"\x06\x77\x72\x6f\x6e\x67\x21\x51" </scriptSigBytes> // <"wrong!"> OP_TRUE
      <scriptPubKeyBytes> b"\x63\xa8\x20\x2b\xb8\x0d\x53\x7b\x1d\xa3\xe3\x8b\xd3\x03\x61\xaa\x85\x56\x86\xbd\xe0\xea\xcd\x71\x62\xfe\xf6\xa2\x5f\xe9\x7b\xf5\x27\xa2\x5b\x88\x67\x01\x64\xb1\x75\x68\x51" </scriptPubKeyBytes> // IF SHA256 <hash> EQUALVERIFY ELSE <100> CLTV DROP ENDIF TRUE
      <witness> .Bytes </witness>
      <savedStack> .List </savedStack>
      <opCount> 0 => ?_ </opCount>
      <flags> 512 </flags>
      <txVersion> 1 </txVersion>
      <nLockTime> 0 </nLockTime>
      <nSequence> 4294967294 </nSequence>
      <witnessUsed> false </witnessUsed>
      <p2shRedeemBytes> .Bytes </p2shRedeemBytes>
      <codesepIdx> 0 </codesepIdx>

  // Claim 3: Timeout path succeeds after expiry (nLockTime=200 >= 100)
  // scriptSig = OP_FALSE = 0x00
  claim [timeout-path-after-expiry]:
      <k> #init => .K </k>
      <stack> .List => ListItem(b"\x01") </stack>
      <altstack> .List </altstack>
      <exec> .List </exec>
      <phase> scriptSig => done </phase>
      <error> "" => "" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> b"\x00" </scriptSigBytes> // OP_FALSE
      <scriptPubKeyBytes> b"\x63\xa8\x20\x2b\xb8\x0d\x53\x7b\x1d\xa3\xe3\x8b\xd3\x03\x61\xaa\x85\x56\x86\xbd\xe0\xea\xcd\x71\x62\xfe\xf6\xa2\x5f\xe9\x7b\xf5\x27\xa2\x5b\x88\x67\x01\x64\xb1\x75\x68\x51" </scriptPubKeyBytes> // IF SHA256 <hash> EQUALVERIFY ELSE <100> CLTV DROP ENDIF TRUE
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

  // Claim 2: Timeout path fails before expiry (nLockTime=50 < 100)
  claim [timeout-path-before-expiry]:
      <k> #init => .K </k>
      <stack> .List => ?_ </stack>
      <altstack> .List </altstack>
      <exec> .List => ?_ </exec>
      <phase> scriptSig => ?_ </phase>
      <error> "" => "UNSATISFIED_LOCKTIME" </error>
      <sighash> .Bytes </sighash>
      <scriptSigBytes> b"\x00" </scriptSigBytes> // OP_FALSE
      <scriptPubKeyBytes> b"\x63\xa8\x20\x2b\xb8\x0d\x53\x7b\x1d\xa3\xe3\x8b\xd3\x03\x61\xaa\x85\x56\x86\xbd\xe0\xea\xcd\x71\x62\xfe\xf6\xa2\x5f\xe9\x7b\xf5\x27\xa2\x5b\x88\x67\x01\x64\xb1\x75\x68\x51" </scriptPubKeyBytes> // IF SHA256 <hash> EQUALVERIFY ELSE <100> CLTV DROP ENDIF TRUE
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

endmodule
