requires "script-semantics.k"

// Signature verification opcodes: CHECKSIG, CHECKSIGVERIFY,
// CHECKMULTISIG, CHECKMULTISIGVERIFY, hash ops, and CODESEPARATOR.
module SCRIPT-SIG
  imports SCRIPT-SEMANTICS
  imports KRYPTO

  // =========================================================================
  // OP_CHECKSIG (extracts hashtype from sig, looks up sighash in blob)
  // =========================================================================

  // DERSIG/STRICTENC: invalid DER signature → SIG_DER error
  rule <k> OP_CHECKSIG => #fail("SIG_DER") ...</k>
       <stack> ListItem(_PK:Bytes) ListItem(SIG:Bytes) ST => ST </stack>
       <flags> F </flags>
    requires lengthBytes(SIG) >Int 0
     andBool (hasFlag(F, FLAG_DERSIG) orBool hasFlag(F, FLAG_STRICTENC))
     andBool notBool isValidDER(SIG)

  // STRICTENC: invalid hashtype → SIG_HASHTYPE error
  rule <k> OP_CHECKSIG => #fail("SIG_HASHTYPE") ...</k>
       <stack> ListItem(_PK:Bytes) ListItem(SIG:Bytes) ST => ST </stack>
       <flags> F </flags>
    requires lengthBytes(SIG) >Int 0
     andBool hasFlag(F, FLAG_STRICTENC)
     andBool isValidDER(SIG)
     andBool notBool validHashType(sigHashType(SIG))

  // STRICTENC: invalid pubkey format → PUBKEYTYPE error
  rule <k> OP_CHECKSIG => #fail("PUBKEYTYPE") ...</k>
       <stack> ListItem(PK:Bytes) ListItem(SIG:Bytes) ST => ST </stack>
       <flags> F </flags>
    requires lengthBytes(SIG) >Int 0
     andBool hasFlag(F, FLAG_STRICTENC)
     andBool isValidDER(SIG)
     andBool validHashType(sigHashType(SIG))
     andBool notBool validPubKeyType(PK)

  // Empty signature: always pushes false (no sighash lookup needed)
  rule <k> OP_CHECKSIG => .K ...</k>
       <stack> ListItem(_PK:Bytes) ListItem(SIG:Bytes) ST
            => ListItem(intToScriptNum(0)) ST </stack>
    requires lengthBytes(SIG) ==Int 0

  // Non-empty signature: extract hashtype, look up sighash, verify
  rule <k> OP_CHECKSIG => .K ...</k>
       <stack> ListItem(PK:Bytes) ListItem(SIG:Bytes) ST
            => ListItem(intToScriptNum(1)) ST </stack>
       <sighash> SIGHASHBLOB </sighash>
    requires lengthBytes(SIG) >Int 0
     andBool ecdsaVerify(PK, SIG, lookupSighash(SIGHASHBLOB, sigHashType(SIG)))

  // Non-empty sig fails verification, no NULLFAIL: push 0
  rule <k> OP_CHECKSIG => .K ...</k>
       <stack> ListItem(PK:Bytes) ListItem(SIG:Bytes) ST
            => ListItem(intToScriptNum(0)) ST </stack>
       <sighash> SIGHASHBLOB </sighash>
       <flags> F </flags>
    requires lengthBytes(SIG) >Int 0
     andBool notBool ecdsaVerify(PK, SIG, lookupSighash(SIGHASHBLOB, sigHashType(SIG)))
     andBool notBool hasFlag(F, FLAG_NULLFAIL)

  // Non-empty sig fails verification, NULLFAIL set: script error
  rule <k> OP_CHECKSIG => #fail("NULLFAIL") ...</k>
       <stack> ListItem(PK:Bytes) ListItem(SIG:Bytes) ST => ST </stack>
       <sighash> SIGHASHBLOB </sighash>
       <flags> F </flags>
    requires lengthBytes(SIG) >Int 0
     andBool notBool ecdsaVerify(PK, SIG, lookupSighash(SIGHASHBLOB, sigHashType(SIG)))
     andBool hasFlag(F, FLAG_NULLFAIL)

  // =========================================================================
  // OP_CHECKMULTISIG
  // =========================================================================
  // Stack layout (top to bottom):
  //   N, pkN, ..., pk1, M, sigM, ..., sig1, dummy

  // (#collectPubKeys/#collectSigs/#verifyMultisig syntax declared in SCRIPT-SEMANTICS)

  // Step 1: Pop N from stack (CScriptNum), begin collecting pubkeys
  // PUBKEY_COUNT: N must be in [0, 20]. Also count N ops for OP_COUNT limit.
  rule <k> OP_CHECKMULTISIG => #countOps(scriptNumToInt(N)) ~> #collectPubKeys(scriptNumToInt(N), .List) ...</k>
       <stack> ListItem(N:Bytes) ST => ST </stack>
       <flags> FL </flags>
    requires validNumFlags(N, FL)
     andBool scriptNumToInt(N) >=Int 0
     andBool scriptNumToInt(N) <=Int 20

  rule <k> OP_CHECKMULTISIG => #fail("PUBKEY_COUNT") ...</k>
       <stack> ListItem(N:Bytes) ST => ST </stack>
       <flags> FL </flags>
    requires validNumFlags(N, FL)
     andBool (scriptNumToInt(N) <Int 0 orBool scriptNumToInt(N) >Int 20)

  // Step 2a: Pop one pubkey, prepend to collected list
  rule <k> #collectPubKeys(N, PKs) => #collectPubKeys(N -Int 1, ListItem(PK) PKs) ...</k>
       <stack> ListItem(PK) ST => ST </stack>
    requires N >Int 0

  // Step 2b: All N pubkeys collected; pop M (CScriptNum) and begin collecting sigs
  // SIG_COUNT: M must be in [0, size(PKs)]
  rule <k> #collectPubKeys(0, PKs) => #collectSigs(scriptNumToInt(M), PKs, .List) ...</k>
       <stack> ListItem(M:Bytes) ST => ST </stack>
       <flags> FL </flags>
    requires validNumFlags(M, FL)
     andBool scriptNumToInt(M) >=Int 0
     andBool scriptNumToInt(M) <=Int size(PKs)

  rule <k> #collectPubKeys(0, PKs) => #fail("SIG_COUNT") ...</k>
       <stack> ListItem(M:Bytes) ST => ST </stack>
       <flags> FL </flags>
    requires validNumFlags(M, FL)
     andBool (scriptNumToInt(M) <Int 0 orBool scriptNumToInt(M) >Int size(PKs))

  // Step 3a: Pop one sig, prepend to collected list
  rule <k> #collectSigs(M, PKs, Sigs) => #collectSigs(M -Int 1, PKs, ListItem(SIG) Sigs) ...</k>
       <stack> ListItem(SIG) ST => ST </stack>
    requires M >Int 0

  // Step 3b: All M sigs collected; pop dummy element, begin verification
  // NULLDUMMY: when flag set, dummy must be empty
  rule <k> #collectSigs(0, PKs, Sigs) => #verifyMultisig(PKs, Sigs) ...</k>
       <stack> ListItem(DUMMY:Bytes) ST => ST </stack>
       <flags> F </flags>
    requires notBool hasFlag(F, FLAG_NULLDUMMY) orBool lengthBytes(DUMMY) ==Int 0

  rule <k> #collectSigs(0, _, _) => #fail("NULLDUMMY") ...</k>
       <stack> ListItem(DUMMY:Bytes) ST => ST </stack>
       <flags> F </flags>
    requires hasFlag(F, FLAG_NULLDUMMY) andBool lengthBytes(DUMMY) >Int 0

  // Step 4a: All sigs verified (sigs list exhausted) — push true
  rule <k> #verifyMultisig(_, .List) => .K ...</k>
       <stack> ST => ListItem(intToScriptNum(1)) ST </stack>

  // Step 4b: Sigs remain but pubkeys exhausted — push false
  // NULLFAIL: remaining non-empty sigs cause script failure
  rule <k> #verifyMultisig(.List, ListItem(SIG:Bytes) _) => .K ...</k>
       <stack> ST => ListItem(intToScriptNum(0)) ST </stack>
       <flags> F </flags>
    requires notBool hasFlag(F, FLAG_NULLFAIL) orBool lengthBytes(SIG) ==Int 0

  rule <k> #verifyMultisig(.List, ListItem(SIG:Bytes) _) => #fail("NULLFAIL") ...</k>
       <flags> F </flags>
    requires hasFlag(F, FLAG_NULLFAIL) andBool lengthBytes(SIG) >Int 0

  // Step 4c: Empty sig in multisig — always fails to match, advance pubkey only
  rule <k> #verifyMultisig(ListItem(_PK:Bytes) PKs, ListItem(SIG:Bytes) Sigs)
        => #verifyMultisig(PKs, ListItem(SIG) Sigs) ...</k>
    requires lengthBytes(SIG) ==Int 0

  // Step 4d: Current sig matches current pubkey — advance both
  rule <k> #verifyMultisig(ListItem(PK:Bytes) PKs, ListItem(SIG:Bytes) Sigs)
        => #verifyMultisig(PKs, Sigs) ...</k>
       <sighash> SIGHASHBLOB </sighash>
    requires lengthBytes(SIG) >Int 0
     andBool ecdsaVerify(PK, SIG, lookupSighash(SIGHASHBLOB, sigHashType(SIG)))

  // Step 4e: Current sig does not match current pubkey — advance pubkey only
  rule <k> #verifyMultisig(ListItem(PK:Bytes) PKs, ListItem(SIG:Bytes) Sigs)
        => #verifyMultisig(PKs, ListItem(SIG) Sigs) ...</k>
       <sighash> SIGHASHBLOB </sighash>
    requires lengthBytes(SIG) >Int 0
     andBool notBool ecdsaVerify(PK, SIG, lookupSighash(SIGHASHBLOB, sigHashType(SIG)))

  // =========================================================================
  // Additional hash opcodes
  // =========================================================================

  // OP_RIPEMD160: RIPEMD160(data) — single hash
  rule <k> OP_RIPEMD160 => .K ...</k>
       <stack> ListItem(V:Bytes) ST => ListItem(RipEmd160raw(V)) ST </stack>

  // OP_SHA1: not implemented (no SHA1 hook in KRYPTO) — gets stuck

  // OP_SHA256: SHA256(data) — single hash
  rule <k> OP_SHA256 => .K ...</k>
       <stack> ListItem(V:Bytes) ST => ListItem(Sha256raw(V)) ST </stack>

  // OP_HASH256: SHA256(SHA256(data)) — double hash
  rule <k> OP_HASH256 => .K ...</k>
       <stack> ListItem(V:Bytes) ST => ListItem(Sha256raw(Sha256raw(V))) ST </stack>

  // OP_CODESEPARATOR: NOP for now
  rule <k> OP_CODESEPARATOR => .K ...</k>

  // =========================================================================
  // OP_CHECKSIGVERIFY: CHECKSIG then VERIFY
  // =========================================================================

  rule <k> OP_CHECKSIGVERIFY => .K ...</k>
       <stack> ListItem(PK:Bytes) ListItem(SIG:Bytes) ST => ST </stack>
       <sighash> SIGHASHBLOB </sighash>
    requires lengthBytes(SIG) >Int 0
     andBool ecdsaVerify(PK, SIG, lookupSighash(SIGHASHBLOB, sigHashType(SIG)))

  rule <k> OP_CHECKSIGVERIFY => #fail("CHECKSIGVERIFY") ...</k>
       <stack> ListItem(PK:Bytes) ListItem(SIG:Bytes) ST => ST </stack>
       <sighash> SIGHASHBLOB </sighash>
    requires lengthBytes(SIG) >Int 0
     andBool notBool ecdsaVerify(PK, SIG, lookupSighash(SIGHASHBLOB, sigHashType(SIG)))

  rule <k> OP_CHECKSIGVERIFY => #fail("CHECKSIGVERIFY") ...</k>
       <stack> ListItem(_PK:Bytes) ListItem(SIG:Bytes) ST => ST </stack>
    requires lengthBytes(SIG) ==Int 0

  // =========================================================================
  // OP_CHECKMULTISIGVERIFY: CHECKMULTISIG then VERIFY
  // =========================================================================

  // Reuse CHECKMULTISIG collection pipeline, then verify the result
  rule <k> OP_CHECKMULTISIGVERIFY
        => OP_CHECKMULTISIG ~> OP_VERIFY ...</k>

endmodule
