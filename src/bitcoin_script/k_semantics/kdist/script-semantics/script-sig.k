requires "script-semantics.k"

// Signature verification opcodes: CHECKSIG, CHECKSIGVERIFY,
// CHECKMULTISIG, CHECKMULTISIGVERIFY, hash ops, and CODESEPARATOR.
module SCRIPT-SIG
  imports SCRIPT-SEMANTICS
  imports KRYPTO

  // BIP-342 tapscript Schnorr sighash dispatcher. Routes to #bip342Sighash
  // when <tx> is populated; otherwise falls back to the precomputed blob
  // for legacy test paths. Takes the annex (from witness), tapleaf hash,
  // codesep byte offset, and hashtype.
  syntax Bytes ::= #tapscriptSighash(Bytes, Bytes, Int, Bytes, Bytes, Int, Bytes, Int, Int) [function]
  // args: tx, prevouts, idx, annex, tapleaf, codesepPos, blob, ht, csi
  rule #tapscriptSighash(TX, PREVOUTS, IDX, ANNEX, TAPLEAF, CSP, _BLOB, HT, _CSI) =>
         #bip342Sighash(TX, PREVOUTS, IDX, ANNEX, HT, TAPLEAF, CSP)
    requires lengthBytes(TX) >Int 0
  rule #tapscriptSighash(TX, _PREVOUTS, _IDX, _ANNEX, _TAPLEAF, _CSP, BLOB, HT, CSI) =>
         lookupSighash(BLOB, HT, CSI)
    requires lengthBytes(TX) ==Int 0

  // Effective scriptCode for a legacy CHECKSIG. If <scriptCode> is
  // populated (a CODESEPARATOR has executed in this phase and updated
  // the slice), use it. Otherwise derive from the phase source: the
  // P2SH redeem script in p2sh-redeem phase, else the scriptPubKey.
  //
  // We avoid initializing <scriptCode> at phase entry (doing so would
  // force fresh existentials in every K proof claim that doesn't
  // mention the cell). Instead the cell is the "CODESEP override",
  // empty until an OP_CODESEPARATOR fires.
  syntax Bytes ::= #legacyScriptCodeOf(Phase, Phase, Bytes, Bytes, Bytes, Bytes) [function]
  // args: current <phase>, <scriptCodePhase>, <scriptCode>,
  //       <scriptSigBytes>, <scriptPubKeyBytes>, <p2shRedeemBytes>
  //
  // Bitcoin Core's legacy sighash uses scriptCode = CScript(pbegincodehash, pend)
  // where the begin pointer resets to the start of the currently-executing
  // script on phase entry (and advances on each OP_CODESEPARATOR).
  //
  // We encode this as: the override <scriptCode> applies ONLY if it was
  // set during the currently-executing phase (tracked in <scriptCodePhase>).
  // Otherwise the default for this phase is used:
  //   scriptSig     -> scriptSig bytes
  //   scriptPubKey  -> scriptPubKey bytes
  //   p2sh-redeem   -> p2sh redeem script bytes
  rule #legacyScriptCodeOf(PH, SCP, SC, _, _, _) => SC
    requires PH ==K SCP andBool lengthBytes(SC) >Int 0
  rule #legacyScriptCodeOf(scriptSig, SCP, SC, SIG, _, _) => SIG
    requires scriptSig =/=K SCP orBool lengthBytes(SC) ==Int 0
  rule #legacyScriptCodeOf(p2sh-redeem, SCP, SC, _, _, REDEEM) => REDEEM
    requires p2sh-redeem =/=K SCP orBool lengthBytes(SC) ==Int 0
  rule #legacyScriptCodeOf(PH, SCP, SC, _, SPK, _) => SPK
    requires PH =/=K scriptSig andBool PH =/=K p2sh-redeem
     andBool (PH =/=K SCP orBool lengthBytes(SC) ==Int 0)

  // ECDSA sighash dispatch used by CHECKSIG / CHECKMULTISIG.
  //
  //   phase == witness-v0, <tx> populated:
  //     -> #bip143Sighash(tx, inputIdx, scriptCode, amount, hashtype)
  //   any other (legacy) phase, <tx> populated:
  //     -> #legacySighash(tx, inputIdx,
  //                      #findAndDelete(legacyScriptCode, pushed(sig)), hashtype)
  //   any phase, <tx> empty (legacy crediting-tx test fixtures):
  //     -> lookupSighash(blob, hashtype, codesepIdx)
  //
  // For legacy, FindAndDelete(sig) is applied to scriptCode before
  // hashing (mirrors Bitcoin Core's EvalChecksig when CONST_SCRIPTCODE
  // is off — when on, Core errors on any nonempty match, a check not
  // yet wired up here). The BIP-143/341/342 paths do not apply
  // FindAndDelete.
  //
  // Extra args SPK + REDEEM give legacy the hooks needed to compute the
  // effective scriptCode without a phase-entry init rule.
  syntax Bytes ::= #ecdsaSighash(Phase, Phase, Bytes, Int, Bytes, Int, Bytes, Int, Int, Bytes, Bytes, Bytes, Bytes) [function]
  // args: current phase, scriptCodePhase, tx, inputIdx, <scriptCode>, amount,
  //       sighashBlob, hashtype, codesepIdx, SIG, <scriptSigBytes>,
  //       <scriptPubKeyBytes>, <p2shRedeemBytes>
  rule #ecdsaSighash(witness-v0, _SCP, TX, IDX, SC, AMT, _BLOB, HT, _CSI, _SIG, _SIGB, _SPK, _REDEEM) =>
         #bip143Sighash(TX, IDX, SC, AMT, HT)
    requires lengthBytes(TX) >Int 0
  rule #ecdsaSighash(witness-v0, _SCP, TX, _IDX, _SC, _AMT, BLOB, HT, CSI, _SIG, _SIGB, _SPK, _REDEEM) =>
         lookupSighash(BLOB, HT, CSI)
    requires lengthBytes(TX) ==Int 0
  rule #ecdsaSighash(PH, SCP, TX, IDX, SC, _AMT, _BLOB, HT, _CSI, SIG, SIGB, SPK, REDEEM) =>
         #legacySighash(TX, IDX,
           #findAndDelete(#legacyScriptCodeOf(PH, SCP, SC, SIGB, SPK, REDEEM), #pushed(SIG)),
           HT)
    requires PH =/=K witness-v0 andBool lengthBytes(TX) >Int 0
  rule #ecdsaSighash(PH, _SCP, TX, _IDX, _SC, _AMT, BLOB, HT, CSI, _SIG, _SIGB, _SPK, _REDEEM) =>
         lookupSighash(BLOB, HT, CSI)
    requires PH =/=K witness-v0 andBool lengthBytes(TX) ==Int 0

  // Multisig variant of ecdsaSighash: receives the scriptCode with ALL
  // collected sigs already stripped (MSSC) for legacy phases. witness-v0
  // ignores MSSC and uses the BIP-143 path (SC from <scriptCode> cell).
  syntax Bytes ::= #ecdsaSighashMulti(Phase, Bytes, Int, Bytes, Int, Bytes, Int, Int, Bytes) [function]
  // args: phase, tx, inputIdx, <scriptCode>, amount, sighashBlob, hashtype,
  //       codesepIdx, MSSC (pre-stripped multisig scriptCode for legacy)
  rule #ecdsaSighashMulti(witness-v0, TX, IDX, SC, AMT, _BLOB, HT, _CSI, _MSSC) =>
         #bip143Sighash(TX, IDX, SC, AMT, HT)
    requires lengthBytes(TX) >Int 0
  rule #ecdsaSighashMulti(witness-v0, TX, _IDX, _SC, _AMT, BLOB, HT, CSI, _MSSC) =>
         lookupSighash(BLOB, HT, CSI)
    requires lengthBytes(TX) ==Int 0
  rule #ecdsaSighashMulti(PH, TX, IDX, _SC, _AMT, _BLOB, HT, _CSI, MSSC) =>
         #legacySighash(TX, IDX, MSSC, HT)
    requires PH =/=K witness-v0 andBool lengthBytes(TX) >Int 0
  rule #ecdsaSighashMulti(PH, TX, _IDX, _SC, _AMT, BLOB, HT, CSI, _MSSC) =>
         lookupSighash(BLOB, HT, CSI)
    requires PH =/=K witness-v0 andBool lengthBytes(TX) ==Int 0

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

  // Non-empty signature: extract hashtype, compute sighash, verify (ECDSA).
  // In witness-v0 phase with a populated <tx> cell, #ecdsaSighash routes to
  // the K-side BIP-143 sighash; otherwise it falls back to the blob lookup.
  rule <k> OP_CHECKSIG => .K ...</k>
       <stack> ListItem(PK:Bytes) ListItem(SIG:Bytes) ST
            => ListItem(intToScriptNum(1)) ST </stack>
       <sighash> SIGHASHBLOB </sighash>
       <codesepIdx> CSI </codesepIdx>
       <flags> F </flags>
       <phase> PH </phase>
       <tx> TX </tx>
       <inputIndex> IDX </inputIndex>
       <scriptCode> SC </scriptCode>
       <scriptCodePhase> SCP </scriptCodePhase>
       <amount> AMT </amount>
       <scriptSigBytes> SIGB </scriptSigBytes>
       <scriptPubKeyBytes> SPK </scriptPubKeyBytes>
       <p2shRedeemBytes> REDEEM </p2shRedeemBytes>
    requires PH =/=K witness-v1
     andBool lengthBytes(SIG) >Int 0
     andBool notBool (PH ==K witness-v0 andBool hasFlag(F, FLAG_WITNESS_PUBKEYTYPE) andBool notBool #isCompressedPubKey(PK))
     andBool ecdsaVerify(PK, SIG,
               #ecdsaSighash(PH, SCP, TX, IDX, SC, AMT, SIGHASHBLOB, sigHashType(SIG), CSI, SIG, SIGB, SPK, REDEEM))

  // Non-empty sig fails verification, no NULLFAIL: push 0
  rule <k> OP_CHECKSIG => .K ...</k>
       <stack> ListItem(PK:Bytes) ListItem(SIG:Bytes) ST
            => ListItem(intToScriptNum(0)) ST </stack>
       <sighash> SIGHASHBLOB </sighash>
       <codesepIdx> CSI </codesepIdx>
       <flags> F </flags>
       <phase> PH </phase>
       <tx> TX </tx>
       <inputIndex> IDX </inputIndex>
       <scriptCode> SC </scriptCode>
       <scriptCodePhase> SCP </scriptCodePhase>
       <amount> AMT </amount>
       <scriptSigBytes> SIGB </scriptSigBytes>
       <scriptPubKeyBytes> SPK </scriptPubKeyBytes>
       <p2shRedeemBytes> REDEEM </p2shRedeemBytes>
    requires PH =/=K witness-v1
     andBool lengthBytes(SIG) >Int 0
     andBool notBool (PH ==K witness-v0 andBool hasFlag(F, FLAG_WITNESS_PUBKEYTYPE) andBool notBool #isCompressedPubKey(PK))
     andBool notBool ecdsaVerify(PK, SIG,
               #ecdsaSighash(PH, SCP, TX, IDX, SC, AMT, SIGHASHBLOB, sigHashType(SIG), CSI, SIG, SIGB, SPK, REDEEM))
     andBool notBool hasFlag(F, FLAG_NULLFAIL)

  // Non-empty sig fails verification, NULLFAIL set: script error
  rule <k> OP_CHECKSIG => #fail("NULLFAIL") ...</k>
       <stack> ListItem(PK:Bytes) ListItem(SIG:Bytes) ST => ST </stack>
       <sighash> SIGHASHBLOB </sighash>
       <codesepIdx> CSI </codesepIdx>
       <flags> F </flags>
       <phase> PH </phase>
       <tx> TX </tx>
       <inputIndex> IDX </inputIndex>
       <scriptCode> SC </scriptCode>
       <scriptCodePhase> SCP </scriptCodePhase>
       <amount> AMT </amount>
       <scriptSigBytes> SIGB </scriptSigBytes>
       <scriptPubKeyBytes> SPK </scriptPubKeyBytes>
       <p2shRedeemBytes> REDEEM </p2shRedeemBytes>
    requires PH =/=K witness-v1
     andBool lengthBytes(SIG) >Int 0
     andBool notBool (PH ==K witness-v0 andBool hasFlag(F, FLAG_WITNESS_PUBKEYTYPE) andBool notBool #isCompressedPubKey(PK))
     andBool notBool ecdsaVerify(PK, SIG,
               #ecdsaSighash(PH, SCP, TX, IDX, SC, AMT, SIGHASHBLOB, sigHashType(SIG), CSI, SIG, SIGB, SPK, REDEEM))
     andBool hasFlag(F, FLAG_NULLFAIL)

  // =========================================================================
  // Tapscript OP_CHECKSIG (BIP 342 — Schnorr verification, witness-v1 only)
  // =========================================================================

  // Empty sig in tapscript: push 0 (no error, no NULLFAIL, no weight cost)
  rule <k> OP_CHECKSIG => .K ...</k>
       <stack> ListItem(PK:Bytes) ListItem(SIG:Bytes) ST
            => ListItem(intToScriptNum(0)) ST </stack>
       <phase> witness-v1 </phase>
    requires lengthBytes(PK) >Int 0
     andBool lengthBytes(SIG) ==Int 0

  // Budget exhausted: non-empty sig in tapscript with insufficient budget (BIP 342)
  rule <k> OP_CHECKSIG => #fail("TAPSCRIPT_VALIDATION_WEIGHT") ...</k>
       <stack> ListItem(PK:Bytes) ListItem(SIG:Bytes) ST => ST </stack>
       <sigopsWeight> W </sigopsWeight>
       <phase> witness-v1 </phase>
    requires lengthBytes(PK) >Int 0
     andBool lengthBytes(SIG) >Int 0
     andBool W <Int 50

  // 32-byte pubkey: invalid Schnorr sig length (not 64 or 65)
  rule <k> OP_CHECKSIG => #fail("SCHNORR_SIG_SIZE") ...</k>
       <stack> ListItem(PK:Bytes) ListItem(SIG:Bytes) ST => ST </stack>
       <sigopsWeight> W => W -Int 50 </sigopsWeight>
       <phase> witness-v1 </phase>
    requires lengthBytes(PK) ==Int 32
     andBool lengthBytes(SIG) >Int 0
     andBool lengthBytes(SIG) =/=Int 64
     andBool lengthBytes(SIG) =/=Int 65
     andBool W >=Int 50

  // 32-byte pubkey: 65-byte sig with hash type 0x00 is invalid
  rule <k> OP_CHECKSIG => #fail("SCHNORR_SIG_HASHTYPE") ...</k>
       <stack> ListItem(PK:Bytes) ListItem(SIG:Bytes) ST => ST </stack>
       <sigopsWeight> W => W -Int 50 </sigopsWeight>
       <phase> witness-v1 </phase>
    requires lengthBytes(PK) ==Int 32
     andBool lengthBytes(SIG) ==Int 65
     andBool Bytes2Int(substrBytes(SIG, 64, 65), BE, Unsigned) ==Int 0
     andBool W >=Int 50

  // 32-byte pubkey: Schnorr verify succeeds → push 1.
  // Sighash via #tapscriptSighash (K-side BIP-342 when <tx> is populated,
  // else the precomputed blob).
  rule <k> OP_CHECKSIG => .K ...</k>
       <stack> ListItem(PK:Bytes) ListItem(SIG:Bytes) ST
            => ListItem(intToScriptNum(1)) ST </stack>
       <sighash> SIGHASHBLOB </sighash>
       <codesepIdx> CSI </codesepIdx>
       <codesepPos> CSP </codesepPos>
       <tapleafHash> TAPLEAF </tapleafHash>
       <tx> TX </tx>
       <prevouts> PREVOUTS </prevouts>
       <inputIndex> IDX </inputIndex>
       <witness> W </witness>
       <sigopsWeight> WT => WT -Int 50 </sigopsWeight>
       <phase> witness-v1 </phase>
    requires lengthBytes(PK) ==Int 32
     andBool #isSchnorrShape(SIG)
     andBool SchnorrVerify(
               PK,
               #tapscriptSighash(TX, PREVOUTS, IDX, #taprootAnnex(W), TAPLEAF, CSP,
                                  SIGHASHBLOB, #tapSigHashType(SIG), CSI),
               #tapSigBody(SIG))
     andBool WT >=Int 50

  // 32-byte pubkey: Schnorr verify fails → error (mandatory, no push-0 fallback)
  rule <k> OP_CHECKSIG => #fail("SCHNORR_SIG") ...</k>
       <stack> ListItem(PK:Bytes) ListItem(SIG:Bytes) ST => ST </stack>
       <sighash> SIGHASHBLOB </sighash>
       <codesepIdx> CSI </codesepIdx>
       <codesepPos> CSP </codesepPos>
       <tapleafHash> TAPLEAF </tapleafHash>
       <tx> TX </tx>
       <prevouts> PREVOUTS </prevouts>
       <inputIndex> IDX </inputIndex>
       <witness> W </witness>
       <sigopsWeight> WT => WT -Int 50 </sigopsWeight>
       <phase> witness-v1 </phase>
    requires lengthBytes(PK) ==Int 32
     andBool #isSchnorrShape(SIG)
     andBool notBool SchnorrVerify(
               PK,
               #tapscriptSighash(TX, PREVOUTS, IDX, #taprootAnnex(W), TAPLEAF, CSP,
                                  SIGHASHBLOB, #tapSigHashType(SIG), CSI),
               #tapSigBody(SIG))
     andBool WT >=Int 50

  // Non-32-byte non-empty pubkey in tapscript: unknown key type → push 1
  // (future softfork compatibility, BIP 342)
  rule <k> OP_CHECKSIG => .K ...</k>
       <stack> ListItem(PK:Bytes) ListItem(SIG:Bytes) ST
            => ListItem(intToScriptNum(1)) ST </stack>
       <sigopsWeight> W => W -Int 50 </sigopsWeight>
       <phase> witness-v1 </phase>
    requires lengthBytes(PK) >Int 0
     andBool lengthBytes(PK) =/=Int 32
     andBool lengthBytes(SIG) >Int 0
     andBool W >=Int 50

  // =========================================================================
  // OP_CHECKSIGADD (BIP 342 — tapscript multisig, witness-v1 only)
  // =========================================================================
  // Stack: pubkey (top), num, sig (bottom of the 3)

  // Empty pubkey (0 bytes) → error
  rule <k> OP_CHECKSIGADD => #fail("TAPSCRIPT_EMPTY_PUBKEY") ...</k>
       <stack> ListItem(PK:Bytes) ListItem(_N:Bytes) ListItem(_SIG:Bytes) ST => ST </stack>
       <phase> witness-v1 </phase>
    requires lengthBytes(PK) ==Int 0

  // Empty sig → push N (no verification, no error, no weight cost)
  rule <k> OP_CHECKSIGADD => .K ...</k>
       <stack> ListItem(PK:Bytes) ListItem(N:Bytes) ListItem(SIG:Bytes) ST
            => ListItem(N) ST </stack>
       <phase> witness-v1 </phase>
    requires lengthBytes(PK) >Int 0
     andBool lengthBytes(SIG) ==Int 0

  // Budget exhausted: non-empty sig in tapscript with insufficient budget (BIP 342)
  rule <k> OP_CHECKSIGADD => #fail("TAPSCRIPT_VALIDATION_WEIGHT") ...</k>
       <stack> ListItem(PK:Bytes) ListItem(_N:Bytes) ListItem(SIG:Bytes) ST => ST </stack>
       <sigopsWeight> W </sigopsWeight>
       <phase> witness-v1 </phase>
    requires lengthBytes(PK) >Int 0
     andBool lengthBytes(SIG) >Int 0
     andBool W <Int 50

  // 32-byte pubkey: invalid Schnorr sig length (not 64 or 65)
  rule <k> OP_CHECKSIGADD => #fail("SCHNORR_SIG_SIZE") ...</k>
       <stack> ListItem(PK:Bytes) ListItem(_N:Bytes) ListItem(SIG:Bytes) ST => ST </stack>
       <sigopsWeight> W => W -Int 50 </sigopsWeight>
       <phase> witness-v1 </phase>
    requires lengthBytes(PK) ==Int 32
     andBool lengthBytes(SIG) >Int 0
     andBool lengthBytes(SIG) =/=Int 64
     andBool lengthBytes(SIG) =/=Int 65
     andBool W >=Int 50

  // 32-byte pubkey: 65-byte sig with hash type 0x00 is invalid
  rule <k> OP_CHECKSIGADD => #fail("SCHNORR_SIG_HASHTYPE") ...</k>
       <stack> ListItem(PK:Bytes) ListItem(_N:Bytes) ListItem(SIG:Bytes) ST => ST </stack>
       <sigopsWeight> W => W -Int 50 </sigopsWeight>
       <phase> witness-v1 </phase>
    requires lengthBytes(PK) ==Int 32
     andBool lengthBytes(SIG) ==Int 65
     andBool Bytes2Int(substrBytes(SIG, 64, 65), BE, Unsigned) ==Int 0
     andBool W >=Int 50

  // 32-byte pubkey: Schnorr verify succeeds → push N+1
  rule <k> OP_CHECKSIGADD => .K ...</k>
       <stack> ListItem(PK:Bytes) ListItem(N:Bytes) ListItem(SIG:Bytes) ST
            => ListItem(intToScriptNum(scriptNumToInt(N) +Int 1)) ST </stack>
       <sighash> SIGHASHBLOB </sighash>
       <codesepIdx> CSI </codesepIdx>
       <codesepPos> CSP </codesepPos>
       <tapleafHash> TAPLEAF </tapleafHash>
       <tx> TX </tx>
       <prevouts> PREVOUTS </prevouts>
       <inputIndex> IDX </inputIndex>
       <witness> WIT </witness>
       <sigopsWeight> WT => WT -Int 50 </sigopsWeight>
       <phase> witness-v1 </phase>
    requires lengthBytes(PK) ==Int 32
     andBool #isSchnorrShape(SIG)
     andBool SchnorrVerify(
               PK,
               #tapscriptSighash(TX, PREVOUTS, IDX, #taprootAnnex(WIT), TAPLEAF, CSP,
                                  SIGHASHBLOB, #tapSigHashType(SIG), CSI),
               #tapSigBody(SIG))
     andBool WT >=Int 50

  // 32-byte pubkey: Schnorr verify fails → error
  rule <k> OP_CHECKSIGADD => #fail("SCHNORR_SIG") ...</k>
       <stack> ListItem(PK:Bytes) ListItem(_N:Bytes) ListItem(SIG:Bytes) ST => ST </stack>
       <sighash> SIGHASHBLOB </sighash>
       <codesepIdx> CSI </codesepIdx>
       <codesepPos> CSP </codesepPos>
       <tapleafHash> TAPLEAF </tapleafHash>
       <tx> TX </tx>
       <prevouts> PREVOUTS </prevouts>
       <inputIndex> IDX </inputIndex>
       <witness> WIT </witness>
       <sigopsWeight> WT => WT -Int 50 </sigopsWeight>
       <phase> witness-v1 </phase>
    requires lengthBytes(PK) ==Int 32
     andBool #isSchnorrShape(SIG)
     andBool notBool SchnorrVerify(
               PK,
               #tapscriptSighash(TX, PREVOUTS, IDX, #taprootAnnex(WIT), TAPLEAF, CSP,
                                  SIGHASHBLOB, #tapSigHashType(SIG), CSI),
               #tapSigBody(SIG))
     andBool WT >=Int 50

  // Non-32-byte non-empty pubkey in tapscript: unknown key type → push N+1
  // (future softfork compatibility, BIP 342)
  rule <k> OP_CHECKSIGADD => .K ...</k>
       <stack> ListItem(PK:Bytes) ListItem(N:Bytes) ListItem(SIG:Bytes) ST
            => ListItem(intToScriptNum(scriptNumToInt(N) +Int 1)) ST </stack>
       <sigopsWeight> W => W -Int 50 </sigopsWeight>
       <phase> witness-v1 </phase>
    requires lengthBytes(PK) >Int 0
     andBool lengthBytes(PK) =/=Int 32
     andBool lengthBytes(SIG) >Int 0
     andBool W >=Int 50

  // =========================================================================
  // OP_CHECKMULTISIG / OP_CHECKMULTISIGVERIFY — disabled in tapscript (BIP 342)
  // =========================================================================
  rule <k> OP_CHECKMULTISIG => #fail("TAPSCRIPT_CHECKMULTISIG") ...</k>
       <phase> witness-v1 </phase>

  rule <k> OP_CHECKMULTISIGVERIFY => #fail("TAPSCRIPT_CHECKMULTISIG") ...</k>
       <phase> witness-v1 </phase>

  // =========================================================================
  // OP_CHECKMULTISIG
  // =========================================================================
  // Stack layout (top to bottom):
  //   N, pkN, ..., pk1, M, sigM, ..., sig1, dummy

  // (#collectPubKeys/#collectSigs/#verifyMultisig syntax declared in SCRIPT-SEMANTICS)

  // Step 1: Pop N from stack (CScriptNum), begin collecting pubkeys
  // PUBKEY_COUNT: N must be in [0, 20]. Also count N ops for OP_COUNT limit.
  // Note: tapscript (witness-v1) rules above handle OP_CHECKMULTISIG separately.
  rule <k> OP_CHECKMULTISIG => #countOps(scriptNumToInt(N)) ~> #collectPubKeys(scriptNumToInt(N), .List) ...</k>
       <stack> ListItem(N:Bytes) ST => ST </stack>
       <flags> FL </flags>
       <phase> PH </phase>
    requires PH =/=K witness-v1
     andBool validNumFlags(N, FL)
     andBool scriptNumToInt(N) >=Int 0
     andBool scriptNumToInt(N) <=Int 20

  rule <k> OP_CHECKMULTISIG => #fail("PUBKEY_COUNT") ...</k>
       <stack> ListItem(N:Bytes) ST => ST </stack>
       <flags> FL </flags>
       <phase> PH </phase>
    requires PH =/=K witness-v1
     andBool validNumFlags(N, FL)
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
  // NULLDUMMY: when flag set, dummy must be empty.
  //
  // At this transition we compute the legacy "multisig scriptCode" (MSSC)
  // once: Bitcoin Core's EvalChecksig strips all collected sigs from the
  // subscript BEFORE running the per-sig verify loop (CONST_SCRIPTCODE off).
  // Witness-v0 doesn't apply FindAndDelete; #ecdsaSighashMulti ignores MSSC
  // there.
  rule <k> #collectSigs(0, PKs, Sigs) =>
           #verifyMultisig(PKs, Sigs,
             #findAndDeleteAll(
               #legacyScriptCodeOf(PH, SCP, SC, SIGB, SPK, REDEEM),
               Sigs)) ...</k>
       <stack> ListItem(DUMMY:Bytes) ST => ST </stack>
       <flags> F </flags>
       <phase> PH </phase>
       <scriptCode> SC </scriptCode>
       <scriptCodePhase> SCP </scriptCodePhase>
       <scriptSigBytes> SIGB </scriptSigBytes>
       <scriptPubKeyBytes> SPK </scriptPubKeyBytes>
       <p2shRedeemBytes> REDEEM </p2shRedeemBytes>
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
  rule <k> #verifyMultisig(_, .List, _) => .K ...</k>
       <stack> ST => ListItem(intToScriptNum(1)) ST </stack>

  // Step 4b: Not enough pubkeys for remaining sigs — fail immediately
  // Mirrors Bitcoin Core's "nSigsCount > nKeysCount" early exit.
  // NULLFAIL: ANY remaining non-empty sig causes script failure.
  rule <k> #verifyMultisig(PKs, Sigs, _) => .K ...</k>
       <stack> ST => ListItem(intToScriptNum(0)) ST </stack>
       <flags> F </flags>
    requires size(Sigs) >Int 0
     andBool size(Sigs) >Int size(PKs)
     andBool (notBool hasFlag(F, FLAG_NULLFAIL) orBool notBool #hasNonEmptySig(Sigs))

  rule <k> #verifyMultisig(PKs, Sigs, _) => #fail("NULLFAIL") ...</k>
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
  rule <k> #verifyMultisig(ListItem(PK:Bytes) PKs, ListItem(SIG:Bytes) Sigs, _)
        => #fail(#msEncErr(SIG, PK, F)) ...</k>
       <flags> F </flags>
    requires size(Sigs) <=Int size(PKs)
     andBool lengthBytes(SIG) >Int 0
     andBool notBool #msEncOK(SIG, PK, F)

  // Step 4c': WITNESS_PUBKEYTYPE: in witness v0, pubkey must be compressed
  rule <k> #verifyMultisig(ListItem(PK:Bytes) _PKs, ListItem(SIG:Bytes) _Sigs, _)
        => #fail("WITNESS_PUBKEYTYPE") ...</k>
       <flags> F </flags>
       <phase> witness-v0 </phase>
    requires lengthBytes(SIG) >Int 0
     andBool #msEncOK(SIG, PK, F)
     andBool hasFlag(F, FLAG_WITNESS_PUBKEYTYPE)
     andBool notBool #isCompressedPubKey(PK)

  // Step 4d: Empty sig — check pubkey encoding (STRICTENC), advance pubkey
  rule <k> #verifyMultisig(ListItem(PK:Bytes) PKs, ListItem(SIG:Bytes) Sigs, MSSC)
        => #verifyMultisig(PKs, ListItem(SIG) Sigs, MSSC) ...</k>
       <flags> F </flags>
    requires size(Sigs) <=Int size(PKs)
     andBool lengthBytes(SIG) ==Int 0
     andBool (notBool hasFlag(F, FLAG_STRICTENC) orBool validPubKeyType(PK))

  rule <k> #verifyMultisig(ListItem(PK:Bytes) _PKs, ListItem(SIG:Bytes) _Sigs, _)
        => #fail("PUBKEYTYPE") ...</k>
       <flags> F </flags>
    requires lengthBytes(SIG) ==Int 0
     andBool hasFlag(F, FLAG_STRICTENC) andBool notBool validPubKeyType(PK)

  // Step 4e: Encoding OK, sig matches current pubkey — advance both.
  // Uses MSSC (pre-stripped all-sigs scriptCode) via #ecdsaSighashMulti
  // for legacy sighash; witness-v0 uses SC from cell (BIP-143 unchanged).
  rule <k> #verifyMultisig(ListItem(PK:Bytes) PKs, ListItem(SIG:Bytes) Sigs, MSSC)
        => #verifyMultisig(PKs, Sigs, MSSC) ...</k>
       <sighash> SIGHASHBLOB </sighash>
       <codesepIdx> CSI </codesepIdx>
       <flags> F </flags>
       <phase> PH </phase>
       <tx> TX </tx>
       <inputIndex> IDX </inputIndex>
       <scriptCode> SC </scriptCode>
       <amount> AMT </amount>
    requires size(Sigs) <=Int size(PKs)
     andBool lengthBytes(SIG) >Int 0
     andBool #msEncOK(SIG, PK, F)
     andBool notBool (PH ==K witness-v0 andBool hasFlag(F, FLAG_WITNESS_PUBKEYTYPE) andBool notBool #isCompressedPubKey(PK))
     andBool ecdsaVerify(PK, SIG,
               #ecdsaSighashMulti(PH, TX, IDX, SC, AMT, SIGHASHBLOB, sigHashType(SIG), CSI, MSSC))

  // Step 4f: Encoding OK, sig does not match — advance pubkey only
  rule <k> #verifyMultisig(ListItem(PK:Bytes) PKs, ListItem(SIG:Bytes) Sigs, MSSC)
        => #verifyMultisig(PKs, ListItem(SIG) Sigs, MSSC) ...</k>
       <sighash> SIGHASHBLOB </sighash>
       <codesepIdx> CSI </codesepIdx>
       <flags> F </flags>
       <phase> PH </phase>
       <tx> TX </tx>
       <inputIndex> IDX </inputIndex>
       <scriptCode> SC </scriptCode>
       <amount> AMT </amount>
    requires size(Sigs) <=Int size(PKs)
     andBool lengthBytes(SIG) >Int 0
     andBool #msEncOK(SIG, PK, F)
     andBool notBool (PH ==K witness-v0 andBool hasFlag(F, FLAG_WITNESS_PUBKEYTYPE) andBool notBool #isCompressedPubKey(PK))
     andBool notBool ecdsaVerify(PK, SIG,
               #ecdsaSighashMulti(PH, TX, IDX, SC, AMT, SIGHASHBLOB, sigHashType(SIG), CSI, MSSC))

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

  // OP_CODESEPARATOR in witness-v0: bump the codesep counter AND promote
  // the decoder-stashed tail into <scriptCode>. BIP-143 says scriptCode for
  // sighash starts from the byte AFTER the most recent executed CODESEP,
  // which is exactly what <pendingCodesepTail> holds.
  rule <k> OP_CODESEPARATOR => .K ...</k>
       <codesepIdx> N => N +Int 1 </codesepIdx>
       <pendingCodesepTail> T </pendingCodesepTail>
       <scriptCode> _ => T </scriptCode>
       <phase> witness-v0 </phase>

  // OP_CODESEPARATOR in witness-v1 (tapscript): bump the counter AND
  // record the byte offset of this CODESEP within the tapscript, to be
  // folded into the BIP-342 sigmsg as codesep_pos. Position of the
  // CODESEP opcode (zero-indexed by byte):
  //     tapscriptLen - pendingTailLen - 1
  // The -1 accounts for the CODESEP byte itself which precedes the tail.
  rule <k> OP_CODESEPARATOR => .K ...</k>
       <codesepIdx> N => N +Int 1 </codesepIdx>
       <pendingCodesepTail> T </pendingCodesepTail>
       <tapscriptBytes> TS </tapscriptBytes>
       <codesepPos> _ => lengthBytes(TS) -Int lengthBytes(T) -Int 1 </codesepPos>
       <phase> witness-v1 </phase>

  // OP_CODESEPARATOR in legacy phases without CONST_SCRIPTCODE: bump
  // the counter AND promote the decoder-stashed tail into <scriptCode>.
  // We also record the setting phase in <scriptCodePhase> so that
  // #legacyScriptCodeOf can ignore the override when execution has
  // crossed into a later phase (Bitcoin Core resets pbegincodehash at
  // each phase boundary). Prover specs that don't fire OP_CODESEPARATOR
  // never hit this rule, keeping <scriptCode> / <scriptCodePhase> in
  // their initial (.Bytes / done) state.
  rule <k> OP_CODESEPARATOR => .K ...</k>
       <codesepIdx> N => N +Int 1 </codesepIdx>
       <pendingCodesepTail> T </pendingCodesepTail>
       <scriptCode> _ => T </scriptCode>
       <scriptCodePhase> _ => P </scriptCodePhase>
       <phase> P </phase>
       <flags> F </flags>
    requires P =/=K witness-v0 andBool P =/=K witness-v1
     andBool notBool hasFlag(F, FLAG_CONST_SCRIPTCODE)

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
  // (tapscript rule above handles witness-v1 separately)
  rule <k> OP_CHECKMULTISIGVERIFY
        => OP_CHECKMULTISIG ~> OP_VERIFY ...</k>
       <phase> PH </phase>
    requires PH =/=K witness-v1

endmodule
