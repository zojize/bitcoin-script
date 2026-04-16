requires "script-semantics.k"

// Signature verification opcodes: CHECKSIG, CHECKSIGVERIFY,
// CHECKMULTISIG, CHECKMULTISIGVERIFY, hash ops, and CODESEPARATOR.
module SCRIPT-SIG
  imports SCRIPT-SEMANTICS
  imports KRYPTO

  // =========================================================================
  // OP_CHECKSIG (extracts hashtype from sig, looks up sighash in blob)
  // =========================================================================

  // TAPSCRIPT: empty pubkey (0 bytes) is explicitly invalid (BIP 342)
  rule <k> OP_CHECKSIG => #fail("TAPSCRIPT_EMPTY_PUBKEY") ...</k>
       <stack> ListItem(PK:Bytes) ListItem(_SIG:Bytes) ST => ST </stack>
       <phase> witness-v1 </phase>
    requires lengthBytes(PK) ==Int 0

  // =========================================================================
  // ECDSA OP_CHECKSIG (legacy + witness-v0 only, NOT tapscript/witness-v1)
  // =========================================================================

  // DERSIG/STRICTENC/LOW_S: invalid DER signature → SIG_DER error
  rule <k> OP_CHECKSIG => #fail("SIG_DER") ...</k>
       <stack> ListItem(_PK:Bytes) ListItem(SIG:Bytes) ST => ST </stack>
       <flags> F </flags>
       <phase> PH </phase>
    requires PH =/=K witness-v1
     andBool lengthBytes(SIG) >Int 0
     andBool (hasFlag(F, FLAG_DERSIG) orBool hasFlag(F, FLAG_STRICTENC) orBool hasFlag(F, FLAG_LOW_S))
     andBool notBool isValidDER(SIG)

  // LOW_S: high S value → SIG_HIGH_S error
  rule <k> OP_CHECKSIG => #fail("SIG_HIGH_S") ...</k>
       <stack> ListItem(_PK:Bytes) ListItem(SIG:Bytes) ST => ST </stack>
       <flags> F </flags>
       <phase> PH </phase>
    requires PH =/=K witness-v1
     andBool lengthBytes(SIG) >Int 0
     andBool hasFlag(F, FLAG_LOW_S)
     andBool isValidDER(SIG)
     andBool notBool isLowDerS(SIG)

  // STRICTENC: invalid hashtype → SIG_HASHTYPE error
  rule <k> OP_CHECKSIG => #fail("SIG_HASHTYPE") ...</k>
       <stack> ListItem(_PK:Bytes) ListItem(SIG:Bytes) ST => ST </stack>
       <flags> F </flags>
       <phase> PH </phase>
    requires PH =/=K witness-v1
     andBool lengthBytes(SIG) >Int 0
     andBool hasFlag(F, FLAG_STRICTENC)
     andBool isValidDER(SIG)
     andBool (notBool hasFlag(F, FLAG_LOW_S) orBool isLowDerS(SIG))
     andBool notBool validHashType(sigHashType(SIG))

  // STRICTENC: invalid pubkey format → PUBKEYTYPE error
  rule <k> OP_CHECKSIG => #fail("PUBKEYTYPE") ...</k>
       <stack> ListItem(PK:Bytes) ListItem(SIG:Bytes) ST => ST </stack>
       <flags> F </flags>
       <phase> PH </phase>
    requires PH =/=K witness-v1
     andBool lengthBytes(SIG) >Int 0
     andBool hasFlag(F, FLAG_STRICTENC)
     andBool isValidDER(SIG)
     andBool (notBool hasFlag(F, FLAG_LOW_S) orBool isLowDerS(SIG))
     andBool validHashType(sigHashType(SIG))
     andBool notBool validPubKeyType(PK)

  // WITNESS_PUBKEYTYPE: in witness v0, pubkey must be compressed
  rule <k> OP_CHECKSIG => #fail("WITNESS_PUBKEYTYPE") ...</k>
       <stack> ListItem(PK:Bytes) ListItem(SIG:Bytes) ST => ST </stack>
       <flags> F </flags>
       <phase> witness-v0 </phase>
    requires lengthBytes(SIG) >Int 0
     andBool hasFlag(F, FLAG_WITNESS_PUBKEYTYPE)
     andBool notBool #isCompressedPubKey(PK)

  // Empty signature in non-tapscript: pushes false
  rule <k> OP_CHECKSIG => .K ...</k>
       <stack> ListItem(_PK:Bytes) ListItem(SIG:Bytes) ST
            => ListItem(intToScriptNum(0)) ST </stack>
       <phase> PH </phase>
    requires PH =/=K witness-v1
     andBool lengthBytes(SIG) ==Int 0

  // Non-empty signature: extract hashtype, look up sighash, verify (ECDSA)
  rule <k> OP_CHECKSIG => .K ...</k>
       <stack> ListItem(PK:Bytes) ListItem(SIG:Bytes) ST
            => ListItem(intToScriptNum(1)) ST </stack>
       <sighash> SIGHASHBLOB </sighash>
       <codesepIdx> CSI </codesepIdx>
       <flags> F </flags>
       <phase> PH </phase>
    requires PH =/=K witness-v1
     andBool lengthBytes(SIG) >Int 0
     andBool notBool (PH ==K witness-v0 andBool hasFlag(F, FLAG_WITNESS_PUBKEYTYPE) andBool notBool #isCompressedPubKey(PK))
     andBool ecdsaVerify(PK, SIG, lookupSighash(SIGHASHBLOB, sigHashType(SIG), CSI))

  // Non-empty sig fails verification, no NULLFAIL: push 0
  rule <k> OP_CHECKSIG => .K ...</k>
       <stack> ListItem(PK:Bytes) ListItem(SIG:Bytes) ST
            => ListItem(intToScriptNum(0)) ST </stack>
       <sighash> SIGHASHBLOB </sighash>
       <codesepIdx> CSI </codesepIdx>
       <flags> F </flags>
       <phase> PH </phase>
    requires PH =/=K witness-v1
     andBool lengthBytes(SIG) >Int 0
     andBool notBool (PH ==K witness-v0 andBool hasFlag(F, FLAG_WITNESS_PUBKEYTYPE) andBool notBool #isCompressedPubKey(PK))
     andBool notBool ecdsaVerify(PK, SIG, lookupSighash(SIGHASHBLOB, sigHashType(SIG), CSI))
     andBool notBool hasFlag(F, FLAG_NULLFAIL)

  // Non-empty sig fails verification, NULLFAIL set: script error
  rule <k> OP_CHECKSIG => #fail("NULLFAIL") ...</k>
       <stack> ListItem(PK:Bytes) ListItem(SIG:Bytes) ST => ST </stack>
       <sighash> SIGHASHBLOB </sighash>
       <codesepIdx> CSI </codesepIdx>
       <flags> F </flags>
       <phase> PH </phase>
    requires PH =/=K witness-v1
     andBool lengthBytes(SIG) >Int 0
     andBool notBool (PH ==K witness-v0 andBool hasFlag(F, FLAG_WITNESS_PUBKEYTYPE) andBool notBool #isCompressedPubKey(PK))
     andBool notBool ecdsaVerify(PK, SIG, lookupSighash(SIGHASHBLOB, sigHashType(SIG), CSI))
     andBool hasFlag(F, FLAG_NULLFAIL)

  // =========================================================================
  // Tapscript OP_CHECKSIG (BIP 342 — Schnorr verification, witness-v1 only)
  // =========================================================================

  // Empty sig in tapscript: push 0 (no error, no NULLFAIL)
  rule <k> OP_CHECKSIG => .K ...</k>
       <stack> ListItem(PK:Bytes) ListItem(SIG:Bytes) ST
            => ListItem(intToScriptNum(0)) ST </stack>
       <phase> witness-v1 </phase>
    requires lengthBytes(PK) >Int 0
     andBool lengthBytes(SIG) ==Int 0

  // 32-byte pubkey: invalid Schnorr sig length (not 64 or 65)
  rule <k> OP_CHECKSIG => #fail("SCHNORR_SIG_SIZE") ...</k>
       <stack> ListItem(PK:Bytes) ListItem(SIG:Bytes) ST => ST </stack>
       <phase> witness-v1 </phase>
    requires lengthBytes(PK) ==Int 32
     andBool lengthBytes(SIG) >Int 0
     andBool lengthBytes(SIG) =/=Int 64
     andBool lengthBytes(SIG) =/=Int 65

  // 32-byte pubkey: 65-byte sig with hash type 0x00 is invalid
  rule <k> OP_CHECKSIG => #fail("SCHNORR_SIG_HASHTYPE") ...</k>
       <stack> ListItem(PK:Bytes) ListItem(SIG:Bytes) ST => ST </stack>
       <phase> witness-v1 </phase>
    requires lengthBytes(PK) ==Int 32
     andBool lengthBytes(SIG) ==Int 65
     andBool Bytes2Int(substrBytes(SIG, 64, 65), BE, Unsigned) ==Int 0

  // 32-byte pubkey: Schnorr verify succeeds → push 1
  rule <k> OP_CHECKSIG => .K ...</k>
       <stack> ListItem(PK:Bytes) ListItem(SIG:Bytes) ST
            => ListItem(intToScriptNum(1)) ST </stack>
       <sighash> SIGHASHBLOB </sighash>
       <codesepIdx> CSI </codesepIdx>
       <phase> witness-v1 </phase>
    requires lengthBytes(PK) ==Int 32
     andBool (lengthBytes(SIG) ==Int 64
       orBool (lengthBytes(SIG) ==Int 65
         andBool Bytes2Int(substrBytes(SIG, 64, 65), BE, Unsigned) =/=Int 0))
     andBool SchnorrVerify(
               PK,
               lookupSighash(SIGHASHBLOB, #tapSigHashType(SIG), CSI),
               #tapSigBody(SIG))

  // 32-byte pubkey: Schnorr verify fails → error (mandatory, no push-0 fallback)
  rule <k> OP_CHECKSIG => #fail("SCHNORR_SIG") ...</k>
       <stack> ListItem(PK:Bytes) ListItem(SIG:Bytes) ST => ST </stack>
       <sighash> SIGHASHBLOB </sighash>
       <codesepIdx> CSI </codesepIdx>
       <phase> witness-v1 </phase>
    requires lengthBytes(PK) ==Int 32
     andBool (lengthBytes(SIG) ==Int 64
       orBool (lengthBytes(SIG) ==Int 65
         andBool Bytes2Int(substrBytes(SIG, 64, 65), BE, Unsigned) =/=Int 0))
     andBool notBool SchnorrVerify(
               PK,
               lookupSighash(SIGHASHBLOB, #tapSigHashType(SIG), CSI),
               #tapSigBody(SIG))

  // Non-32-byte non-empty pubkey in tapscript: unknown key type → push 1
  // (future softfork compatibility, BIP 342)
  rule <k> OP_CHECKSIG => .K ...</k>
       <stack> ListItem(PK:Bytes) ListItem(SIG:Bytes) ST
            => ListItem(intToScriptNum(1)) ST </stack>
       <phase> witness-v1 </phase>
    requires lengthBytes(PK) >Int 0
     andBool lengthBytes(PK) =/=Int 32
     andBool lengthBytes(SIG) >Int 0

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

  // Step 2a: Pop one pubkey, append to collected list
  // Append preserves Bitcoin Core's iteration order (top-of-stack = first tried)
  rule <k> #collectPubKeys(N, PKs) => #collectPubKeys(N -Int 1, PKs ListItem(PK)) ...</k>
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

  // Step 3a: Pop one sig, append to collected list (same order as pubkeys)
  rule <k> #collectSigs(M, PKs, Sigs) => #collectSigs(M -Int 1, PKs, Sigs ListItem(SIG)) ...</k>
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

  // =========================================================================
  // Multisig encoding validation helpers
  // =========================================================================
  // #msEncOK: true if sig+pk encoding passes all flag-dependent checks.
  // Mirrors Bitcoin Core's CheckSignatureEncoding + CheckPubKeyEncoding.
  syntax Bool ::= #msEncOK(Bytes, Bytes, Int) [function, total]
  rule #msEncOK(SIG, PK, F) => true
    requires // DER check (triggered by DERSIG, STRICTENC, or LOW_S)
             (notBool (hasFlag(F, FLAG_DERSIG) orBool hasFlag(F, FLAG_STRICTENC) orBool hasFlag(F, FLAG_LOW_S))
              orBool isValidDER(SIG))
     // LOW_S check
     andBool (notBool hasFlag(F, FLAG_LOW_S) orBool isLowDerS(SIG))
     // Hashtype check (STRICTENC only)
     andBool (notBool hasFlag(F, FLAG_STRICTENC) orBool validHashType(sigHashType(SIG)))
     // Pubkey type check (STRICTENC only)
     andBool (notBool hasFlag(F, FLAG_STRICTENC) orBool validPubKeyType(PK))
  rule #msEncOK(_, _, _) => false [owise]

  // #msEncErr: returns the specific error string for the first failing check.
  // Check order matches Bitcoin Core: DER → LOW_S → hashtype → pubkeytype.
  syntax String ::= #msEncErr(Bytes, Bytes, Int) [function]
  rule #msEncErr(SIG, _PK, F) => "SIG_DER"
    requires (hasFlag(F, FLAG_DERSIG) orBool hasFlag(F, FLAG_STRICTENC) orBool hasFlag(F, FLAG_LOW_S))
     andBool notBool isValidDER(SIG)
  rule #msEncErr(SIG, _PK, F) => "SIG_HIGH_S"
    requires hasFlag(F, FLAG_LOW_S)
     andBool isValidDER(SIG)
     andBool notBool isLowDerS(SIG)
  rule #msEncErr(SIG, _PK, F) => "SIG_HASHTYPE"
    requires hasFlag(F, FLAG_STRICTENC)
     andBool (notBool (hasFlag(F, FLAG_DERSIG) orBool hasFlag(F, FLAG_LOW_S)) orBool isValidDER(SIG))
     andBool (notBool hasFlag(F, FLAG_LOW_S) orBool isLowDerS(SIG))
     andBool notBool validHashType(sigHashType(SIG))
  rule #msEncErr(_SIG, PK, F) => "PUBKEYTYPE"
    requires hasFlag(F, FLAG_STRICTENC)
     andBool notBool validPubKeyType(PK)

  // =========================================================================
  // Multisig NULLFAIL helper
  // =========================================================================
  // #hasNonEmptySig: true if any sig in the list is non-empty.
  // Used for NULLFAIL: all remaining sigs must be empty when multisig fails.
  syntax Bool ::= #hasNonEmptySig(List) [function, total]
  rule #hasNonEmptySig(.List) => false
  rule #hasNonEmptySig(ListItem(SIG:Bytes) _Rest) => true
    requires lengthBytes(SIG) >Int 0
  rule #hasNonEmptySig(ListItem(SIG:Bytes) Rest) => #hasNonEmptySig(Rest)
    requires lengthBytes(SIG) ==Int 0
  rule #hasNonEmptySig(_) => false [owise]

  // =========================================================================
  // Multisig verification (Step 4)
  // =========================================================================

  // Step 4a: All sigs verified (sigs list exhausted) — push true
  rule <k> #verifyMultisig(_, .List) => .K ...</k>
       <stack> ST => ListItem(intToScriptNum(1)) ST </stack>

  // Step 4b: Not enough pubkeys for remaining sigs — fail immediately
  // Mirrors Bitcoin Core's "nSigsCount > nKeysCount" early exit.
  // NULLFAIL: ANY remaining non-empty sig causes script failure.
  rule <k> #verifyMultisig(PKs, Sigs) => .K ...</k>
       <stack> ST => ListItem(intToScriptNum(0)) ST </stack>
       <flags> F </flags>
    requires size(Sigs) >Int 0
     andBool size(Sigs) >Int size(PKs)
     andBool (notBool hasFlag(F, FLAG_NULLFAIL) orBool notBool #hasNonEmptySig(Sigs))

  rule <k> #verifyMultisig(PKs, Sigs) => #fail("NULLFAIL") ...</k>
       <flags> F </flags>
    requires size(Sigs) >Int 0
     andBool size(Sigs) >Int size(PKs)
     andBool hasFlag(F, FLAG_NULLFAIL) andBool #hasNonEmptySig(Sigs)

  // Steps 4c-4f: Only fire when enough pubkeys remain for all sigs
  // (size(Sigs) <=Int size(PKs) where both are the REST after ListItem).
  // When more sigs than pks remain, step 4b (early exit) fires instead.
  // This matches Bitcoin Core's "nSigsCount > nKeysCount" check which fires
  // AFTER each iteration, preventing encoding checks on unreachable pubkeys.

  // Step 4c: Encoding check fails for current sig-pk pair → error
  rule <k> #verifyMultisig(ListItem(PK:Bytes) PKs, ListItem(SIG:Bytes) Sigs)
        => #fail(#msEncErr(SIG, PK, F)) ...</k>
       <flags> F </flags>
    requires size(Sigs) <=Int size(PKs)
     andBool lengthBytes(SIG) >Int 0
     andBool notBool #msEncOK(SIG, PK, F)

  // Step 4c': WITNESS_PUBKEYTYPE: in witness v0, pubkey must be compressed
  rule <k> #verifyMultisig(ListItem(PK:Bytes) _PKs, ListItem(SIG:Bytes) _Sigs)
        => #fail("WITNESS_PUBKEYTYPE") ...</k>
       <flags> F </flags>
       <phase> witness-v0 </phase>
    requires lengthBytes(SIG) >Int 0
     andBool #msEncOK(SIG, PK, F)
     andBool hasFlag(F, FLAG_WITNESS_PUBKEYTYPE)
     andBool notBool #isCompressedPubKey(PK)

  // Step 4d: Empty sig — check pubkey encoding (STRICTENC), advance pubkey
  rule <k> #verifyMultisig(ListItem(PK:Bytes) PKs, ListItem(SIG:Bytes) Sigs)
        => #verifyMultisig(PKs, ListItem(SIG) Sigs) ...</k>
       <flags> F </flags>
    requires size(Sigs) <=Int size(PKs)
     andBool lengthBytes(SIG) ==Int 0
     andBool (notBool hasFlag(F, FLAG_STRICTENC) orBool validPubKeyType(PK))

  rule <k> #verifyMultisig(ListItem(PK:Bytes) PKs, ListItem(SIG:Bytes) Sigs)
        => #fail("PUBKEYTYPE") ...</k>
       <flags> F </flags>
    requires size(Sigs) <=Int size(PKs)
     andBool lengthBytes(SIG) ==Int 0
     andBool hasFlag(F, FLAG_STRICTENC) andBool notBool validPubKeyType(PK)

  // Step 4e: Encoding OK, sig matches current pubkey — advance both
  rule <k> #verifyMultisig(ListItem(PK:Bytes) PKs, ListItem(SIG:Bytes) Sigs)
        => #verifyMultisig(PKs, Sigs) ...</k>
       <sighash> SIGHASHBLOB </sighash>
       <codesepIdx> CSI </codesepIdx>
       <flags> F </flags>
       <phase> PH </phase>
    requires size(Sigs) <=Int size(PKs)
     andBool lengthBytes(SIG) >Int 0
     andBool #msEncOK(SIG, PK, F)
     andBool notBool (PH ==K witness-v0 andBool hasFlag(F, FLAG_WITNESS_PUBKEYTYPE) andBool notBool #isCompressedPubKey(PK))
     andBool ecdsaVerify(PK, SIG, lookupSighash(SIGHASHBLOB, sigHashType(SIG), CSI))

  // Step 4f: Encoding OK, sig does not match — advance pubkey only
  rule <k> #verifyMultisig(ListItem(PK:Bytes) PKs, ListItem(SIG:Bytes) Sigs)
        => #verifyMultisig(PKs, ListItem(SIG) Sigs) ...</k>
       <sighash> SIGHASHBLOB </sighash>
       <codesepIdx> CSI </codesepIdx>
       <flags> F </flags>
       <phase> PH </phase>
    requires size(Sigs) <=Int size(PKs)
     andBool lengthBytes(SIG) >Int 0
     andBool #msEncOK(SIG, PK, F)
     andBool notBool (PH ==K witness-v0 andBool hasFlag(F, FLAG_WITNESS_PUBKEYTYPE) andBool notBool #isCompressedPubKey(PK))
     andBool notBool ecdsaVerify(PK, SIG, lookupSighash(SIGHASHBLOB, sigHashType(SIG), CSI))

  // =========================================================================
  // Additional hash opcodes
  // =========================================================================

  // OP_RIPEMD160: RIPEMD160(data) — single hash
  rule <k> OP_RIPEMD160 => .K ...</k>
       <stack> ListItem(V:Bytes) ST => ListItem(RipEmd160raw(V)) ST </stack>

  // OP_SHA1: SHA1(data) — single hash
  rule <k> OP_SHA1 => .K ...</k>
       <stack> ListItem(V:Bytes) ST => ListItem(Sha1raw(V)) ST </stack>

  // OP_SHA256: SHA256(data) — single hash
  rule <k> OP_SHA256 => .K ...</k>
       <stack> ListItem(V:Bytes) ST => ListItem(Sha256raw(V)) ST </stack>

  // OP_HASH256: SHA256(SHA256(data)) — double hash
  rule <k> OP_HASH256 => .K ...</k>
       <stack> ListItem(V:Bytes) ST => ListItem(Hash256raw(V)) ST </stack>

  // OP_CODESEPARATOR: forbidden in base (non-witness) phases when CONST_SCRIPTCODE is active
  // Allowed in witness-v0 (BIP 143) and witness-v1 (BIP 342 tapscript)
  rule <k> OP_CODESEPARATOR => #fail("CONST_SCRIPTCODE") ...</k>
       <phase> P </phase>
       <flags> F </flags>
    requires P =/=K witness-v0 andBool P =/=K witness-v1
     andBool hasFlag(F, FLAG_CONST_SCRIPTCODE)

  // OP_CODESEPARATOR: increment codesep counter for sighash subscript selection
  rule <k> OP_CODESEPARATOR => .K ...</k>
       <codesepIdx> N => N +Int 1 </codesepIdx>
       <phase> P </phase>
       <flags> F </flags>
    requires notBool (P =/=K witness-v0 andBool P =/=K witness-v1
              andBool hasFlag(F, FLAG_CONST_SCRIPTCODE))

  // =========================================================================
  // OP_CHECKSIGVERIFY: CHECKSIG then VERIFY
  // =========================================================================

  // Reuse CHECKSIG validation pipeline (DER, STRICTENC, LOW_S, NULLFAIL, etc.)
  rule <k> OP_CHECKSIGVERIFY
        => OP_CHECKSIG ~> OP_VERIFY ...</k>

  // =========================================================================
  // OP_CHECKMULTISIGVERIFY: CHECKMULTISIG then VERIFY
  // =========================================================================

  // Reuse CHECKMULTISIG collection pipeline, then verify the result
  rule <k> OP_CHECKMULTISIGVERIFY
        => OP_CHECKMULTISIG ~> OP_VERIFY ...</k>

endmodule
