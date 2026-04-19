requires "script-tx.k"
requires "script-crypto.k"
requires "plugin/krypto.md"

// K-side sighash computation.
//
// This module is the dispatch seam between the CHECKSIG-family rules and
// the per-BIP sighash variants (legacy / BIP-143 / BIP-341 key-path /
// BIP-342 script-path). Each variant will be implemented as its own
// function (`#legacySighash`, `#bip143Sighash`, `#bip341Sighash`,
// `#bip342Sighash`) over the raw <tx>, <prevouts>, and <inputIndex> cells.
//
// Phase dispatch is done by the calling rule in script-sig.k (each
// CHECKSIG rule matches on <phase>), so this module exposes pure
// sighash helpers rather than a single phase-dispatching entry point.
//
// Until each variant lands, `#sighashK(BLOB, HT, CSI)` delegates to the
// existing precomputed-blob lookup (`lookupSighash`), preserving current
// behavior while the infrastructure is in place.
module SCRIPT-SIGHASH
  imports SCRIPT-TX
  imports SCRIPT-CRYPTO
  imports KRYPTO
  imports BYTES
  imports INT
  imports BOOL

  // =========================================================================
  // Tagged hash (BIP-340) — used by BIP-341 / BIP-342.
  //
  //   taggedHash(tag, msg) = SHA256(SHA256(tag) || SHA256(tag) || msg)
  //
  // The tag hash is a 32-byte constant per tag name (TapSighash, TapLeaf,
  // TapBranch, TapTweak). We keep the full formula in K to stay self-contained
  // against any single SHA-256 implementation.
  // =========================================================================

  syntax Bytes ::= #taggedHash(String, Bytes) [function]
  rule #taggedHash(TAG, MSG) =>
         Sha256raw(
           Sha256raw(String2Bytes(TAG))
             +Bytes Sha256raw(String2Bytes(TAG))
             +Bytes MSG
         )

  // Double SHA-256 used by legacy and BIP-143 sighash final wrap.
  syntax Bytes ::= #doubleSha256(Bytes) [function]
  rule #doubleSha256(B) => Sha256raw(Sha256raw(B))

  // =========================================================================
  // BIP-143 sighash field hashes (SegWit v0).
  //
  // BIP-143 splits the sigmsg into three per-tx precomputable hashes that
  // cover prevouts, sequences, and outputs. Each is double-SHA-256 over a
  // concatenation of fixed-size records drawn from the raw tx bytes, with
  // all-zero placeholders when the hashtype masks that slot out.
  //
  // Hashtype layout:
  //   bit 7  (0x80)          = SIGHASH_ANYONECANPAY
  //   bits 0-4 (0x1F) == 1   = SIGHASH_ALL
  //                    == 2   = SIGHASH_NONE
  //                    == 3   = SIGHASH_SINGLE
  //
  // The helpers below are self-contained over <tx> cell bytes; they don't
  // look at <prevouts>, <scriptCode>, or <inputIndex> except where BIP-143
  // requires it (SINGLE's output selection uses inputIndex).
  // =========================================================================

  // Concatenate the 36-byte outpoint of every vin in [I, I+N).
  syntax Bytes ::= #concatOutpoints(Bytes, Int, Int) [function]
  rule #concatOutpoints(_, _, 0) => .Bytes
  rule #concatOutpoints(TX, I, N) =>
           #txVinOutpoint(TX, I)
           +Bytes #concatOutpoints(TX, I +Int 1, N -Int 1)
    requires N >Int 0

  // Concatenate the 4-byte LE sequence of every vin in [I, I+N).
  syntax Bytes ::= #concatSequences(Bytes, Int, Int) [function]
  rule #concatSequences(_, _, 0) => .Bytes
  rule #concatSequences(TX, I, N) =>
           Int2Bytes(4, #txVinSequence(TX, I), LE)
           +Bytes #concatSequences(TX, I +Int 1, N -Int 1)
    requires N >Int 0

  // Concatenate the full serialized vout (amount || cs len || script) for
  // every vout in [I, I+N).
  syntax Bytes ::= #concatVouts(Bytes, Int, Int) [function]
  rule #concatVouts(_, _, 0) => .Bytes
  rule #concatVouts(TX, I, N) =>
           #txVoutSerialized(TX, I)
           +Bytes #concatVouts(TX, I +Int 1, N -Int 1)
    requires N >Int 0

  // hashPrevouts — dSHA256 of all outpoints, or 32 zero bytes when
  // ANYONECANPAY masks prevouts out.
  syntax Bytes ::= #bip143HashPrevouts(Bytes, Int) [function]
  rule #bip143HashPrevouts(_, HT) => Int2Bytes(32, 0, BE)
    requires HT &Int 128 =/=Int 0
  rule #bip143HashPrevouts(TX, HT) =>
           #doubleSha256(#concatOutpoints(TX, 0, #txVinCount(TX)))
    requires HT &Int 128 ==Int 0

  // hashSequence — dSHA256 of all sequences, or 32 zero bytes when the
  // hashtype (ANYONECANPAY / SINGLE / NONE) masks sequences out.
  syntax Bytes ::= #bip143HashSequence(Bytes, Int) [function]
  rule #bip143HashSequence(_, HT) => Int2Bytes(32, 0, BE)
    requires HT &Int 128 =/=Int 0
      orBool (HT &Int 31) ==Int 2
      orBool (HT &Int 31) ==Int 3
  rule #bip143HashSequence(TX, HT) =>
           #doubleSha256(#concatSequences(TX, 0, #txVinCount(TX)))
    requires HT &Int 128 ==Int 0
      andBool (HT &Int 31) =/=Int 2
      andBool (HT &Int 31) =/=Int 3

  // hashOutputs —
  //   SIGHASH_SINGLE + inputIdx < vout count : dSHA256(vout[inputIdx]).
  //   SIGHASH_NONE   or SINGLE-out-of-bounds : 32 zero bytes.
  //   otherwise (ALL / 0x00 / 0x04..)        : dSHA256 of all vouts.
  //
  // Note: Bitcoin Core's SIGHASH_SINGLE out-of-bounds behavior for BIP-143
  // differs from legacy: BIP-143 zeros the hash (never the 0x01-hash bug),
  // which is what the third-rule guard below models.
  syntax Bytes ::= #bip143HashOutputs(Bytes, Int, Int) [function]
  rule #bip143HashOutputs(TX, IDX, HT) =>
           #doubleSha256(#txVoutSerialized(TX, IDX))
    requires (HT &Int 31) ==Int 3
      andBool IDX <Int #txVoutCount(TX)
  rule #bip143HashOutputs(TX, IDX, HT) => Int2Bytes(32, 0, BE)
    requires (HT &Int 31) ==Int 2
      orBool ((HT &Int 31) ==Int 3 andBool IDX >=Int #txVoutCount(TX))
  rule #bip143HashOutputs(TX, _, HT) =>
           #doubleSha256(#concatVouts(TX, 0, #txVoutCount(TX)))
    requires (HT &Int 31) =/=Int 2
      andBool (HT &Int 31) =/=Int 3

  // =========================================================================
  // BIP-143 sigmsg assembly (SegWit v0).
  //
  //   preimage =
  //     nVersion            (4 LE)
  //     hashPrevouts        (32)
  //     hashSequence        (32)
  //     outpoint_i          (32 + 4 LE)  -- the input being signed
  //     scriptCode          (compactSize len + bytes)
  //     amount_i            (8 LE)
  //     nSequence_i         (4 LE)
  //     hashOutputs         (32)
  //     nLockTime           (4 LE)
  //     hashType            (4 LE, *zero-extended* hashtype byte)
  //
  //   sighash = dSHA256(preimage)
  //
  // hashType is encoded as a 4-byte LE unsigned int where only the low byte
  // carries the actual hashtype. compactSize for scriptCode is 1 byte when
  // len <= 252 (the vast majority of P2WPKH/P2WSH cases) and 3 bytes for
  // len in [253, 65535]. Longer scriptCodes don't occur in practice (BIP-143
  // permits them but Core's script-size cap makes them unreachable here).
  // =========================================================================

  // compactSize encoding of the scriptCode length prefix.
  // Mirrors #compactSize in SCRIPT-SEMANTICS but we redefine locally to
  // avoid a module cycle (SCRIPT-SIGHASH is imported by SCRIPT-SEMANTICS).
  syntax Bytes ::= #bip143CompactSize(Int) [function]
  rule #bip143CompactSize(N) => Int2Bytes(1, N, BE)
    requires N <=Int 252
  rule #bip143CompactSize(N) =>
           Int2Bytes(1, 253, BE) +Bytes Int2Bytes(2, N, LE)
    requires N >Int 252 andBool N <=Int 65535
  rule #bip143CompactSize(N) =>
           Int2Bytes(1, 254, BE) +Bytes Int2Bytes(4, N, LE)
    requires N >Int 65535 andBool N <=Int 4294967295

  // Full BIP-143 sighash. All byte-level composition happens here; the only
  // external primitive is #doubleSha256 (Sha256raw hook). Matches Bitcoin
  // Core's SignatureHash(sigversion=WITNESS_V0) when CODESEPARATOR is not
  // involved; CODESEP support is via the <scriptCode> cell being updated
  // at exec time (see script-sig.k OP_CODESEPARATOR rule).
  syntax Bytes ::= #bip143Sighash(Bytes, Int, Bytes, Int, Int) [function]
  rule #bip143Sighash(TX, IDX, SC, AMOUNT, HT) =>
           #doubleSha256(
               Int2Bytes(4, #txVersion(TX), LE)
             +Bytes #bip143HashPrevouts(TX, HT)
             +Bytes #bip143HashSequence(TX, HT)
             +Bytes #txVinOutpoint(TX, IDX)
             +Bytes #bip143CompactSize(lengthBytes(SC)) +Bytes SC
             +Bytes Int2Bytes(8, AMOUNT, LE)
             +Bytes Int2Bytes(4, #txVinSequence(TX, IDX), LE)
             +Bytes #bip143HashOutputs(TX, IDX, HT)
             +Bytes Int2Bytes(4, #txLocktime(TX), LE)
             +Bytes Int2Bytes(4, HT, LE)
           )

  // =========================================================================
  // BIP-341 field hashes (Taproot — single SHA-256, not double).
  //
  // Unlike BIP-143 which hashes and then hashes again, BIP-341's field
  // hashes are a single Sha256raw over a flat concatenation. The final
  // sighash is obtained by a tagged hash over the full sigmsg.
  //
  // Layout (per BIP-341):
  //   sha_prevouts     = sha256(concat(outpoint_i) for i in vins)
  //   sha_amounts      = sha256(concat(8-byte LE amount_i) for i in vins)
  //   sha_scriptpubkeys = sha256(concat(cs_len(spk_i) || spk_i) for i in vins)
  //   sha_sequences    = sha256(concat(4-byte LE sequence_i) for i in vins)
  //   sha_outputs      = sha256(concat(serialized vout_j) for j in vouts)
  //
  // Prevouts source: <prevouts> cell (each record is a serialized TxOut,
  // walked via #prevoutAt/#prevoutAmount/#prevoutScriptSerialized).
  // =========================================================================

  // Concat of 8-byte LE amounts from prevouts[I, I+N).
  syntax Bytes ::= #concatPrevoutAmounts(Bytes, Int, Int) [function]
  rule #concatPrevoutAmounts(_, _, 0) => .Bytes
  rule #concatPrevoutAmounts(P, I, N) =>
           Int2Bytes(8, #prevoutAmount(P, I), LE)
           +Bytes #concatPrevoutAmounts(P, I +Int 1, N -Int 1)
    requires N >Int 0

  // Concat of serialized scriptPubKeys (cs_len || bytes) from prevouts[I, I+N).
  syntax Bytes ::= #concatPrevoutScripts(Bytes, Int, Int) [function]
  rule #concatPrevoutScripts(_, _, 0) => .Bytes
  rule #concatPrevoutScripts(P, I, N) =>
           #prevoutScriptSerialized(P, I)
           +Bytes #concatPrevoutScripts(P, I +Int 1, N -Int 1)
    requires N >Int 0

  // BIP-341 single-SHA-256 field hashes. N = number of vins (for prevout
  // iteration) / vouts (for output iteration).
  syntax Bytes ::= #bip341ShaPrevouts(Bytes) [function]
  rule #bip341ShaPrevouts(TX) =>
           Sha256raw(#concatOutpoints(TX, 0, #txVinCount(TX)))

  syntax Bytes ::= #bip341ShaAmounts(Bytes, Int) [function]
  rule #bip341ShaAmounts(P, N) =>
           Sha256raw(#concatPrevoutAmounts(P, 0, N))

  syntax Bytes ::= #bip341ShaScriptpubkeys(Bytes, Int) [function]
  rule #bip341ShaScriptpubkeys(P, N) =>
           Sha256raw(#concatPrevoutScripts(P, 0, N))

  syntax Bytes ::= #bip341ShaSequences(Bytes) [function]
  rule #bip341ShaSequences(TX) =>
           Sha256raw(#concatSequences(TX, 0, #txVinCount(TX)))

  syntax Bytes ::= #bip341ShaOutputs(Bytes) [function]
  rule #bip341ShaOutputs(TX) =>
           Sha256raw(#concatVouts(TX, 0, #txVoutCount(TX)))

  // =========================================================================
  // BIP-341 sigmsg assembly (Taproot).
  //
  //   epoch                   = 0x00
  //   hash_type               = 1 byte
  //   nVersion                = 4 LE
  //   nLockTime               = 4 LE
  //   [if !ANYONECANPAY]
  //     sha_prevouts           (32)
  //     sha_amounts            (32)
  //     sha_scriptpubkeys      (32)
  //     sha_sequences          (32)
  //   [if base != NONE && base != SINGLE]
  //     sha_outputs            (32)
  //   spend_type              = (ext_flag << 1) | has_annex   (1 byte)
  //   [if ANYONECANPAY]
  //     outpoint_i             (36)
  //     amount_i               (8 LE)
  //     scriptpubkey_size_i    (cs)
  //     scriptpubkey_i         (variable)
  //     sequence_i             (4 LE)
  //   [else]
  //     input_index            (4 LE)
  //   [if has_annex]
  //     sha256(cs_len(annex) || annex)   (32)
  //   [if base == SINGLE]
  //     sha256(serialized vout[input_index])   (32)
  //   [if ext_flag == 1] (script-path, BIP-342)
  //     tapleaf_hash           (32)
  //     key_version            (1 byte = 0)
  //     codesep_pos            (4 LE)
  //
  //   sighash = taggedHash("TapSighash", 0x00 || sigmsg)
  //
  // Hashtype 0x00 is SIGHASH_DEFAULT (treated like SIGHASH_ALL).
  // =========================================================================

  // Decompose hashtype into (base, anyonecanpay) pieces.
  //   base = 1 (ALL), 2 (NONE), 3 (SINGLE); DEFAULT (0x00) is treated as 1.
  syntax Int ::= #bip341Base(Int) [function]
  rule #bip341Base(0)  => 1           // SIGHASH_DEFAULT -> ALL
  rule #bip341Base(HT) => HT &Int 3   requires HT =/=Int 0

  syntax Bool ::= #bip341Anyonecanpay(Int) [function]
  rule #bip341Anyonecanpay(HT) => HT &Int 128 =/=Int 0

  // Block 1: prevouts/amounts/scriptpubkeys/sequences hashes (or empty
  // when ANYONECANPAY masks them out).
  syntax Bytes ::= #bip341BlockPrevouts(Bytes, Bytes, Int, Int) [function]
  // args: tx, prevouts, hashtype, vinCount
  rule #bip341BlockPrevouts(TX, P, HT, N) =>
           #bip341ShaPrevouts(TX)
           +Bytes #bip341ShaAmounts(P, N)
           +Bytes #bip341ShaScriptpubkeys(P, N)
           +Bytes #bip341ShaSequences(TX)
    requires HT &Int 128 ==Int 0
  rule #bip341BlockPrevouts(_, _, HT, _) => .Bytes
    requires HT &Int 128 =/=Int 0

  // Block 2: sha_outputs (or empty for NONE/SINGLE).
  syntax Bytes ::= #bip341BlockOutputs(Bytes, Int) [function]
  rule #bip341BlockOutputs(TX, HT) => #bip341ShaOutputs(TX)
    requires #bip341Base(HT) =/=Int 2 andBool #bip341Base(HT) =/=Int 3
  rule #bip341BlockOutputs(_, HT) => .Bytes
    requires #bip341Base(HT) ==Int 2 orBool #bip341Base(HT) ==Int 3

  // Block 3: per-input fields. ANYONECANPAY: outpoint+amount+spk+seq.
  // Non-ANYONECANPAY: 4-byte LE inputIndex.
  syntax Bytes ::= #bip341BlockInput(Bytes, Bytes, Int, Int) [function]
  // args: tx, prevouts, inputIdx, hashtype
  rule #bip341BlockInput(TX, P, IDX, HT) =>
           #txVinOutpoint(TX, IDX)
           +Bytes Int2Bytes(8, #prevoutAmount(P, IDX), LE)
           +Bytes #prevoutScriptSerialized(P, IDX)
           +Bytes Int2Bytes(4, #txVinSequence(TX, IDX), LE)
    requires HT &Int 128 =/=Int 0
  rule #bip341BlockInput(_, _, IDX, HT) => Int2Bytes(4, IDX, LE)
    requires HT &Int 128 ==Int 0

  // Block 4: annex hash. ANNEX is either the raw annex bytes (including
  // the 0x50 prefix) or .Bytes when no annex is present.
  syntax Bytes ::= #bip341BlockAnnex(Bytes) [function]
  rule #bip341BlockAnnex(ANNEX) =>
           Sha256raw(#bip143CompactSize(lengthBytes(ANNEX)) +Bytes ANNEX)
    requires lengthBytes(ANNEX) >Int 0
  rule #bip341BlockAnnex(ANNEX) => .Bytes
    requires lengthBytes(ANNEX) ==Int 0

  // Block 5: sha256 of the single matching output when base == SINGLE.
  syntax Bytes ::= #bip341BlockSingleOutput(Bytes, Int, Int) [function]
  rule #bip341BlockSingleOutput(TX, IDX, HT) =>
           Sha256raw(#txVoutSerialized(TX, IDX))
    requires #bip341Base(HT) ==Int 3
      andBool IDX <Int #txVoutCount(TX)
  rule #bip341BlockSingleOutput(_, _, HT) => .Bytes
    requires #bip341Base(HT) =/=Int 3

  // spend_type byte: (ext_flag << 1) | (1 if has_annex else 0).
  syntax Int ::= #bip341SpendType(Int, Bytes) [function]
  // args: extFlag, annex (empty -> 0 bit)
  rule #bip341SpendType(EXT, ANNEX) =>
           (EXT <<Int 1)
           |Int (#if lengthBytes(ANNEX) >Int 0 #then 1 #else 0 #fi)

  // Full BIP-341 key-path sighash (ext_flag = 0, no tapleaf/keyVer/codesep).
  // Callers pass:
  //   tx       : <tx> cell
  //   prevouts : <prevouts> cell
  //   inputIdx : <inputIndex> cell
  //   annex    : annex bytes with 0x50 prefix (or .Bytes when no annex)
  //   ht       : hashtype byte
  syntax Bytes ::= #bip341Sighash(Bytes, Bytes, Int, Bytes, Int) [function]
  rule #bip341Sighash(TX, PREVOUTS, IDX, ANNEX, HT) =>
           #taggedHash("TapSighash",
               Int2Bytes(1, 0, BE)                              // epoch
             +Bytes Int2Bytes(1, HT, BE)                        // hashtype
             +Bytes Int2Bytes(4, #txVersion(TX), LE)
             +Bytes Int2Bytes(4, #txLocktime(TX), LE)
             +Bytes #bip341BlockPrevouts(TX, PREVOUTS, HT, #txVinCount(TX))
             +Bytes #bip341BlockOutputs(TX, HT)
             +Bytes Int2Bytes(1, #bip341SpendType(0, ANNEX), BE)
             +Bytes #bip341BlockInput(TX, PREVOUTS, IDX, HT)
             +Bytes #bip341BlockAnnex(ANNEX)
             +Bytes #bip341BlockSingleOutput(TX, IDX, HT)
           )

  // =========================================================================
  // BIP-342 sigmsg (Tapscript script-path).
  //
  // Extends the BIP-341 sigmsg with three additional fields when
  // ext_flag == 1:
  //   tapleaf_hash   (32 bytes)   = taggedHash("TapLeaf", leaf_ver || cs(len) || script)
  //   key_version    (1 byte = 0) — reserved for future pubkey type changes
  //   codesep_pos    (4 LE bytes) — byte offset of most recent executed
  //                                 OP_CODESEPARATOR, or 0xFFFFFFFF if none.
  //
  // Everything else is identical to BIP-341 with ext_flag=1 in spend_type.
  // =========================================================================

  syntax Bytes ::= #bip342Sighash(Bytes, Bytes, Int, Bytes, Int, Bytes, Int) [function]
  // args: tx, prevouts, inputIdx, annex, hashtype, tapleafHash, codesepPos
  rule #bip342Sighash(TX, PREVOUTS, IDX, ANNEX, HT, TAPLEAF, CSP) =>
           #taggedHash("TapSighash",
               Int2Bytes(1, 0, BE)                              // epoch
             +Bytes Int2Bytes(1, HT, BE)                        // hashtype
             +Bytes Int2Bytes(4, #txVersion(TX), LE)
             +Bytes Int2Bytes(4, #txLocktime(TX), LE)
             +Bytes #bip341BlockPrevouts(TX, PREVOUTS, HT, #txVinCount(TX))
             +Bytes #bip341BlockOutputs(TX, HT)
             +Bytes Int2Bytes(1, #bip341SpendType(1, ANNEX), BE) // ext_flag=1
             +Bytes #bip341BlockInput(TX, PREVOUTS, IDX, HT)
             +Bytes #bip341BlockAnnex(ANNEX)
             +Bytes #bip341BlockSingleOutput(TX, IDX, HT)
             +Bytes TAPLEAF                                     // 32 bytes
             +Bytes Int2Bytes(1, 0, BE)                         // key_version=0
             +Bytes Int2Bytes(4, CSP, LE)                       // codesep_pos
           )

  // =========================================================================
  // Delegation stub.
  //
  // Returns the 32-byte sighash, or .Bytes on lookup failure (matches
  // the current `lookupSighash` behavior so ecdsaVerify / SchnorrVerify
  // fail cleanly without raising errors).
  //
  // Callers in the CHECKSIG rules pass the blob read from <sighash>; once
  // every phase has a K-native sighash rule, the blob arg is dropped.
  // =========================================================================

  syntax Bytes ::= #sighashK(Bytes, Int, Int) [function]
  rule #sighashK(BLOB, HT, CSI) => lookupSighash(BLOB, HT, CSI)

endmodule
