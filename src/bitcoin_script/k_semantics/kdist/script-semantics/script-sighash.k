requires "script-tx.k"
requires "script-crypto.k"
requires "plugin/krypto.md"
requires "bitcoin-sighash-plugin/bitcoin-sighash.md"

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
  imports BITCOIN-SIGHASH
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
  // Streaming SHA-256 walkers over tx fields.
  //
  // K's `+Bytes` allocates and copies on every call, making right-recursive
  // byte-concatenation O(n²) — catastrophic for the 5000+ vin stress txs on
  // mainnet (empirically 500 ms/input before, <1 ms after).
  //
  // These helpers thread an opaque SHA-256 midstate Bytes through a walker,
  // calling Sha256Update with a small (~40 byte) chunk per vin/vout rather
  // than building the full preimage as K Bytes. The underlying Crypto++
  // SHA256 is stream-stateful; the plugin serializes/restores the state
  // blob around each Update call.
  //
  // Each walker returns the updated midstate; call Sha256Final on it to
  // get the 32-byte digest.
  // =========================================================================

  // Stream walkers. Each public `#stream*` wrapper delegates to its
  // corresponding bitcoin-sighash-plugin hook, which iterates in C and
  // calls SHA256_Update per record. The `Pure` variants preserve the
  // pure-K recursive definition so the Haskell prover can reason about
  // them inductively; a [simplification] lemma in lemmas.k asserts
  // `BitcoinXStream(...) === #streamXPure(...)`.
  //
  // For per-step K overhead reasons (each K rewrite step through the
  // LLVM backend is ~90 µs, swamping the ~1 ns actual SHA-256 work),
  // running the pure walker on a 5000-vin stress tx costs ~500 ms.
  // The bulk hook drops that to ~5 µs.

  // ---- #streamOutpoints: delegate + pure version ----
  syntax Bytes ::= #streamOutpoints(Bytes, Bytes, Int, Int) [function]
  // args: state, tx, current-vin-offset, vins-remaining
  rule #streamOutpoints(S, TX, O, N) => BitcoinOutpointsStream(S, TX, O, N)

  syntax Bytes ::= #streamOutpointsPure(Bytes, Bytes, Int, Int) [function]
  rule #streamOutpointsPure(S, _, _, 0) => S
  rule #streamOutpointsPure(S, TX, O, N) =>
           #streamOutpointsPure(Sha256Update(S, #txVinOutpointAtOffset(TX, O)),
                                TX, O +Int #vinLen(TX, O), N -Int 1)
    requires N >Int 0

  // ---- #streamSequences ----
  syntax Bytes ::= #streamSequences(Bytes, Bytes, Int, Int) [function]
  rule #streamSequences(S, TX, O, N) => BitcoinSequencesStream(S, TX, O, N)

  syntax Bytes ::= #streamSequencesPure(Bytes, Bytes, Int, Int) [function]
  rule #streamSequencesPure(S, _, _, 0) => S
  rule #streamSequencesPure(S, TX, O, N) =>
           #streamSequencesPure(
               Sha256Update(S, Int2Bytes(4, #txVinSequenceAtOffset(TX, O), LE)),
               TX, O +Int #vinLen(TX, O), N -Int 1)
    requires N >Int 0

  // ---- #streamVouts ----
  syntax Bytes ::= #streamVouts(Bytes, Bytes, Int, Int) [function]
  rule #streamVouts(S, TX, O, N) => BitcoinVoutsStream(S, TX, O, N)

  syntax Bytes ::= #streamVoutsPure(Bytes, Bytes, Int, Int) [function]
  rule #streamVoutsPure(S, _, _, 0) => S
  rule #streamVoutsPure(S, TX, O, N) =>
           #streamVoutsPure(Sha256Update(S, #txVoutSerializedAtOffset(TX, O)),
                            TX, O +Int #voutLen(TX, O), N -Int 1)
    requires N >Int 0

  // ---- #streamPrevoutAmounts ----
  // Prevouts blob has no tx header: offset 0 is the first prevout. The
  // bulk hook only needs the count.
  syntax Bytes ::= #streamPrevoutAmounts(Bytes, Bytes, Int) [function]
  rule #streamPrevoutAmounts(S, P, N) => BitcoinPrevoutAmountsStream(S, P, N)

  syntax Bytes ::= #streamPrevoutAmountsPure(Bytes, Bytes, Int, Int) [function]
  rule #streamPrevoutAmountsPure(S, _, _, 0) => S
  rule #streamPrevoutAmountsPure(S, P, O, N) =>
           #streamPrevoutAmountsPure(
               Sha256Update(S, Int2Bytes(8, #prevoutAmountAtOffset(P, O), LE)),
               P, O +Int #voutLen(P, O), N -Int 1)
    requires N >Int 0

  // ---- #streamPrevoutScripts ----
  syntax Bytes ::= #streamPrevoutScripts(Bytes, Bytes, Int) [function]
  rule #streamPrevoutScripts(S, P, N) => BitcoinPrevoutScriptsStream(S, P, N)

  syntax Bytes ::= #streamPrevoutScriptsPure(Bytes, Bytes, Int, Int) [function]
  rule #streamPrevoutScriptsPure(S, _, _, 0) => S
  rule #streamPrevoutScriptsPure(S, P, O, N) =>
           #streamPrevoutScriptsPure(
               Sha256Update(S, #prevoutScriptSerializedAtOffset(P, O)),
               P, O +Int #voutLen(P, O), N -Int 1)
    requires N >Int 0

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
  // ANYONECANPAY masks prevouts out. Streams outpoints through a SHA-256
  // midstate rather than building the full concat in Bytes.
  syntax Bytes ::= #bip143HashPrevouts(Bytes, Int) [function]
  rule #bip143HashPrevouts(_, HT) => Int2Bytes(32, 0, BE)
    requires HT &Int 128 =/=Int 0
  rule #bip143HashPrevouts(TX, HT) =>
           Sha256raw(Sha256Final(#streamOutpoints(Sha256Init(), TX,
                     #txVin0Offset(TX), #txVinCount(TX))))
    requires HT &Int 128 ==Int 0

  // hashSequence — dSHA256 of all sequences, or 32 zero bytes when the
  // hashtype (ANYONECANPAY / SINGLE / NONE) masks sequences out.
  syntax Bytes ::= #bip143HashSequence(Bytes, Int) [function]
  rule #bip143HashSequence(_, HT) => Int2Bytes(32, 0, BE)
    requires HT &Int 128 =/=Int 0
      orBool (HT &Int 31) ==Int 2
      orBool (HT &Int 31) ==Int 3
  rule #bip143HashSequence(TX, HT) =>
           Sha256raw(Sha256Final(#streamSequences(Sha256Init(), TX,
                     #txVin0Offset(TX), #txVinCount(TX))))
    requires HT &Int 128 ==Int 0
      andBool (HT &Int 31) =/=Int 2
      andBool (HT &Int 31) =/=Int 3

  // hashOutputs —
  //   SIGHASH_SINGLE + inputIdx < vout count : dSHA256(vout[inputIdx]).
  //   SIGHASH_NONE   or SINGLE-out-of-bounds : 32 zero bytes.
  //   otherwise (ALL / 0x00 / 0x04..)        : dSHA256 of all vouts.
  syntax Bytes ::= #bip143HashOutputs(Bytes, Int, Int) [function]
  rule #bip143HashOutputs(TX, IDX, HT) =>
           #doubleSha256(#txVoutSerialized(TX, IDX))
    requires (HT &Int 31) ==Int 3
      andBool IDX <Int #txVoutCount(TX)
  rule #bip143HashOutputs(TX, IDX, HT) => Int2Bytes(32, 0, BE)
    requires (HT &Int 31) ==Int 2
      orBool ((HT &Int 31) ==Int 3 andBool IDX >=Int #txVoutCount(TX))
  rule #bip143HashOutputs(TX, _, HT) =>
           Sha256raw(Sha256Final(#streamVouts(Sha256Init(), TX,
                     #txVout0Offset(TX), #txVoutCount(TX))))
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
  // iteration) / vouts (for output iteration). Each is a streaming SHA-256
  // over the per-vin/per-vout records — never builds the full concat in Bytes.
  syntax Bytes ::= #bip341ShaPrevouts(Bytes) [function]
  rule #bip341ShaPrevouts(TX) =>
           Sha256Final(#streamOutpoints(Sha256Init(), TX,
                       #txVin0Offset(TX), #txVinCount(TX)))

  // Prevouts blob has no tx header; vin[0] is at offset 0.
  syntax Bytes ::= #bip341ShaAmounts(Bytes, Int) [function]
  rule #bip341ShaAmounts(P, N) =>
           Sha256Final(#streamPrevoutAmounts(Sha256Init(), P, N))

  syntax Bytes ::= #bip341ShaScriptpubkeys(Bytes, Int) [function]
  rule #bip341ShaScriptpubkeys(P, N) =>
           Sha256Final(#streamPrevoutScripts(Sha256Init(), P, N))

  syntax Bytes ::= #bip341ShaSequences(Bytes) [function]
  rule #bip341ShaSequences(TX) =>
           Sha256Final(#streamSequences(Sha256Init(), TX,
                       #txVin0Offset(TX), #txVinCount(TX)))

  syntax Bytes ::= #bip341ShaOutputs(Bytes) [function]
  rule #bip341ShaOutputs(TX) =>
           Sha256Final(#streamVouts(Sha256Init(), TX,
                       #txVout0Offset(TX), #txVoutCount(TX)))

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
  // Legacy (pre-SegWit) sighash.
  //
  // Constructs a modified copy of the spending transaction and appends
  // the 4-byte LE hashtype, double-SHA-256 the whole thing. Unlike
  // BIP-143/341/342 which hash field-by-field, legacy literally
  // re-serializes a modified tx. Hashtype-specific mutations:
  //
  //   ANYONECANPAY (bit 7):
  //     vin_count -> 1, only vin[inputIdx] is kept, others dropped.
  //
  //   base type = ALL (default + 0x01):
  //     vouts unchanged.
  //     non-current vins: nSequence unchanged.
  //
  //   base type = NONE (0x02):
  //     vouts cleared (vout_count = 0).
  //     non-current vins: nSequence = 0.
  //
  //   base type = SINGLE (0x03):
  //     if inputIdx >= vout_count: return fixed 0x0100..00 sighash
  //     (the "SIGHASH_SINGLE bug").
  //     Else vouts truncated to [0, inputIdx+1). Vouts before inputIdx
  //     are placeholders (amount = 0xffffffffffffffff, empty script).
  //     Only vout[inputIdx] is the real one.
  //     non-current vins: nSequence = 0.
  //
  // All vins except vin[inputIdx] have their scriptSig set to empty
  // (cs_len = 0x00). vin[inputIdx]'s scriptSig is replaced with the
  // subscript (scriptCode).
  // =========================================================================

  // nSequence to emit for a non-target vin (the one we're not signing).
  syntax Int ::= #legacyOtherSequence(Bytes, Int, Int) [function]
  // args: tx, vin index, hashtype
  rule #legacyOtherSequence(_, _, HT) => 0
    requires (HT &Int 31) ==Int 2 orBool (HT &Int 31) ==Int 3
  rule #legacyOtherSequence(TX, I, HT) => #txVinSequence(TX, I)
    requires (HT &Int 31) =/=Int 2 andBool (HT &Int 31) =/=Int 3

  // At-offset variant for stream walkers.
  syntax Int ::= #legacyOtherSequenceAtOffset(Bytes, Int, Int) [function]
  rule #legacyOtherSequenceAtOffset(_, _, HT) => 0
    requires (HT &Int 31) ==Int 2 orBool (HT &Int 31) ==Int 3
  rule #legacyOtherSequenceAtOffset(TX, O, HT) => #txVinSequenceAtOffset(TX, O)
    requires (HT &Int 31) =/=Int 2 andBool (HT &Int 31) =/=Int 3

  // Serialized modified vin[I] given inputIdx IDX and subscript SC.
  syntax Bytes ::= #legacyVin(Bytes, Int, Int, Bytes, Int) [function]
  // args: tx, I (this vin's index), IDX (target), subscript, hashtype
  // The signed vin: outpoint || cs(len(sub)) || sub || original sequence
  rule #legacyVin(TX, IDX, IDX, SC, _HT) =>
           #txVinOutpoint(TX, IDX)
           +Bytes #bip143CompactSize(lengthBytes(SC))
           +Bytes SC
           +Bytes Int2Bytes(4, #txVinSequence(TX, IDX), LE)
  // Other vins: outpoint || 0x00 (empty scriptSig) || (maybe-zeroed sequence)
  rule #legacyVin(TX, I, IDX, _SC, HT) =>
           #txVinOutpoint(TX, I)
           +Bytes Int2Bytes(1, 0, BE)
           +Bytes Int2Bytes(4, #legacyOtherSequence(TX, I, HT), LE)
    requires I =/=Int IDX

  // Iterate and concat modified vins for [I, N).
  syntax Bytes ::= #concatLegacyVins(Bytes, Int, Int, Int, Bytes, Int) [function]
  // args: tx, current I, N (stop), IDX, subscript, hashtype
  rule #concatLegacyVins(_, N, N, _, _, _) => .Bytes
  rule #concatLegacyVins(TX, I, N, IDX, SC, HT) =>
           #legacyVin(TX, I, IDX, SC, HT)
           +Bytes #concatLegacyVins(TX, I +Int 1, N, IDX, SC, HT)
    requires I <Int N

  // Full vins block (count prefix + serialized vins). ANYONECANPAY keeps
  // only the target vin (count=1); else all vins.
  syntax Bytes ::= #legacyVinsBlock(Bytes, Int, Bytes, Int) [function]
  // args: tx, inputIdx, subscript, hashtype
  rule #legacyVinsBlock(TX, IDX, SC, HT) =>
           #bip143CompactSize(1)
           +Bytes #legacyVin(TX, IDX, IDX, SC, HT)
    requires HT &Int 128 =/=Int 0
  rule #legacyVinsBlock(TX, IDX, SC, HT) =>
           #bip143CompactSize(#txVinCount(TX))
           +Bytes #concatLegacyVins(TX, 0, #txVinCount(TX), IDX, SC, HT)
    requires HT &Int 128 ==Int 0

  // Modified vout[J] for hashtype HT and inputIdx IDX.
  // SINGLE: j < inputIdx → placeholder (amount=0xff..ff, empty script);
  //         j == inputIdx → the real vout[inputIdx];
  //         j > inputIdx → should never be constructed (voutCount caps it).
  // Other: the real vout[j].
  syntax Bytes ::= #legacyVout(Bytes, Int, Int, Int) [function]
  // args: tx, J (this vout's index), IDX (target), hashtype
  // SINGLE + j < inputIdx: placeholder
  rule #legacyVout(_, J, IDX, HT) =>
           Int2Bytes(8, 18446744073709551615, LE)  // amount = -1 cast to u64
           +Bytes Int2Bytes(1, 0, BE)              // empty scriptPubKey
    requires (HT &Int 31) ==Int 3 andBool J <Int IDX
  // Any other j: pass through the real vout
  rule #legacyVout(TX, J, IDX, HT) => #txVoutSerialized(TX, J)
    requires (HT &Int 31) =/=Int 3 orBool J >=Int IDX

  // Iterate and concat modified vouts for [J, N).
  syntax Bytes ::= #concatLegacyVouts(Bytes, Int, Int, Int, Int) [function]
  // args: tx, current J, N (stop), IDX, hashtype
  rule #concatLegacyVouts(_, N, N, _, _) => .Bytes
  rule #concatLegacyVouts(TX, J, N, IDX, HT) =>
           #legacyVout(TX, J, IDX, HT)
           +Bytes #concatLegacyVouts(TX, J +Int 1, N, IDX, HT)
    requires J <Int N

  // Modified vout count: 0 for NONE, IDX+1 for SINGLE, else tx's voutCount.
  syntax Int ::= #legacyVoutCount(Bytes, Int, Int) [function]
  rule #legacyVoutCount(_, _, HT) => 0
    requires (HT &Int 31) ==Int 2
  rule #legacyVoutCount(_, IDX, HT) => IDX +Int 1
    requires (HT &Int 31) ==Int 3
  rule #legacyVoutCount(TX, _, HT) => #txVoutCount(TX)
    requires (HT &Int 31) =/=Int 2 andBool (HT &Int 31) =/=Int 3

  // Full vouts block (count prefix + vouts).
  syntax Bytes ::= #legacyVoutsBlock(Bytes, Int, Int) [function]
  rule #legacyVoutsBlock(TX, IDX, HT) =>
           #bip143CompactSize(#legacyVoutCount(TX, IDX, HT))
           +Bytes #concatLegacyVouts(TX, 0, #legacyVoutCount(TX, IDX, HT), IDX, HT)

  // Legacy sighash preimage: modified tx + 4-byte LE hashtype.
  // (Kept for documentation / non-streaming fallback; #legacySighash uses
  // the streaming path below.)
  syntax Bytes ::= #legacyPreimage(Bytes, Int, Bytes, Int) [function]
  // args: tx, inputIdx, subscript, hashtype
  rule #legacyPreimage(TX, IDX, SC, HT) =>
           Int2Bytes(4, #txVersion(TX), LE)
           +Bytes #legacyVinsBlock(TX, IDX, SC, HT)
           +Bytes #legacyVoutsBlock(TX, IDX, HT)
           +Bytes Int2Bytes(4, #txLocktime(TX), LE)
           +Bytes Int2Bytes(4, HT, LE)

  // ---- Streaming version of the legacy preimage hash ---------------------
  //
  // Threads a SHA-256 midstate through the same field sequence as
  // #legacyPreimage so the preimage is never materialized as K Bytes.
  // Returns the final 32-byte first-round digest (caller wraps with a
  // second Sha256raw for the dSHA256).

  // Stream one vin's legacy form through S. The per-vin chunk is tiny
  // (~41 bytes for non-target vins, outpoint + small scriptCode + sequence
  // for the target vin), so building it as Bytes is fine. O is this vin's
  // byte offset in TX; I is the vin index (only used to pick target branch).
  syntax Bytes ::= #streamLegacyVinAtOffset(Bytes, Bytes, Int, Int, Int, Bytes, Int) [function]
  // args: S, tx, offset, I (this vin's index), IDX (target), subscript, hashtype
  rule #streamLegacyVinAtOffset(S, TX, O, IDX, IDX, SC, _HT) =>
           Sha256Update(S,
               #txVinOutpointAtOffset(TX, O)
             +Bytes #bip143CompactSize(lengthBytes(SC))
             +Bytes SC
             +Bytes Int2Bytes(4, #txVinSequenceAtOffset(TX, O), LE))
  rule #streamLegacyVinAtOffset(S, TX, O, I, IDX, _SC, HT) =>
           Sha256Update(S,
               #txVinOutpointAtOffset(TX, O)
             +Bytes Int2Bytes(1, 0, BE)
             +Bytes Int2Bytes(4, #legacyOtherSequenceAtOffset(TX, O, HT), LE))
    requires I =/=Int IDX

  // Stream vins from offset O, for N iterations. Offset-threaded to avoid
  // the O(n²) re-walk that #txVinAt would cost.
  syntax Bytes ::= #streamLegacyVins(Bytes, Bytes, Int, Int, Int, Int, Bytes, Int) [function]
  // args: S, tx, current-offset, current-I, N (stop), IDX, SC, HT
  rule #streamLegacyVins(S, _, _, N, N, _, _, _) => S
  rule #streamLegacyVins(S, TX, O, I, N, IDX, SC, HT) =>
           #streamLegacyVins(
               #streamLegacyVinAtOffset(S, TX, O, I, IDX, SC, HT),
               TX, O +Int #vinLen(TX, O), I +Int 1, N, IDX, SC, HT)
    requires I <Int N

  // Stream the full vins block (count prefix + vins) through S.
  // Delegates to the bitcoin-sighash-plugin hook which emits the count
  // prefix + walks the vins in C.
  syntax Bytes ::= #streamLegacyVinsBlock(Bytes, Bytes, Int, Bytes, Int) [function]
  // ANYONECANPAY: include only the target vin (n=1, scoped to IDX's offset).
  rule #streamLegacyVinsBlock(S, TX, IDX, SC, HT) =>
           BitcoinLegacyVinsBlockStream(S, TX, #txVinAt(TX, IDX), 1, 0, SC, HT)
    requires HT &Int 128 =/=Int 0
  // Normal: include all vins.
  rule #streamLegacyVinsBlock(S, TX, IDX, SC, HT) =>
           BitcoinLegacyVinsBlockStream(S, TX, #txVin0Offset(TX),
                                        #txVinCount(TX), IDX, SC, HT)
    requires HT &Int 128 ==Int 0

  // Pure K version for Haskell-prover reasoning.
  syntax Bytes ::= #streamLegacyVinsBlockPure(Bytes, Bytes, Int, Bytes, Int) [function]
  rule #streamLegacyVinsBlockPure(S, TX, IDX, SC, HT) =>
           #streamLegacyVinAtOffset(Sha256Update(S, #bip143CompactSize(1)),
                            TX, #txVinAt(TX, IDX), IDX, IDX, SC, HT)
    requires HT &Int 128 =/=Int 0
  rule #streamLegacyVinsBlockPure(S, TX, IDX, SC, HT) =>
           #streamLegacyVins(Sha256Update(S, #bip143CompactSize(#txVinCount(TX))),
                             TX, #txVin0Offset(TX), 0, #txVinCount(TX), IDX, SC, HT)
    requires HT &Int 128 ==Int 0

  // Modified vout[J] at offset O in TX — same dispatch as #legacyVout but
  // takes the offset rather than having to re-walk for it.
  syntax Bytes ::= #legacyVoutAtOffset(Bytes, Int, Int, Int, Int) [function]
  // args: tx, offset, J (this vout's index), IDX (target), HT
  rule #legacyVoutAtOffset(_, _, J, IDX, HT) =>
           Int2Bytes(8, 18446744073709551615, LE)
           +Bytes Int2Bytes(1, 0, BE)
    requires (HT &Int 31) ==Int 3 andBool J <Int IDX
  rule #legacyVoutAtOffset(TX, O, J, IDX, HT) => #txVoutSerializedAtOffset(TX, O)
    requires (HT &Int 31) =/=Int 3 orBool J >=Int IDX

  // Stream vouts starting at offset O, for N iterations. Only advances
  // the offset past REAL vouts (SINGLE placeholders have a synthetic
  // payload but their emitting index is < IDX, which — by SINGLE's
  // definition — means we never actually walk past a placeholder
  // because vout[IDX] is the real vout at offset #txVoutAt(TX, IDX)).
  //
  // Wait — in the SINGLE+J<IDX case we emit a placeholder but the
  // underlying tx still has a real vout[J]. We must advance past it.
  syntax Bytes ::= #streamLegacyVouts(Bytes, Bytes, Int, Int, Int, Int, Int) [function]
  // args: S, tx, offset, J, N (stop), IDX, HT
  rule #streamLegacyVouts(S, _, _, N, N, _, _) => S
  rule #streamLegacyVouts(S, TX, O, J, N, IDX, HT) =>
           #streamLegacyVouts(
               Sha256Update(S, #legacyVoutAtOffset(TX, O, J, IDX, HT)),
               TX, O +Int #voutLen(TX, O), J +Int 1, N, IDX, HT)
    requires J <Int N

  // Stream the full vouts block (count prefix + modified vouts) through S.
  // Delegates to the bitcoin-sighash-plugin hook which emits the count
  // prefix + walks the vouts in C (including SIGHASH_SINGLE placeholders).
  syntax Bytes ::= #streamLegacyVoutsBlock(Bytes, Bytes, Int, Int) [function]
  rule #streamLegacyVoutsBlock(S, TX, IDX, HT) =>
           BitcoinLegacyVoutsBlockStream(S, TX, #txVout0Offset(TX),
                                         #legacyVoutCount(TX, IDX, HT),
                                         IDX, HT)

  // Pure K version for Haskell-prover reasoning.
  syntax Bytes ::= #streamLegacyVoutsBlockPure(Bytes, Bytes, Int, Int) [function]
  rule #streamLegacyVoutsBlockPure(S, TX, IDX, HT) =>
           #streamLegacyVouts(
               Sha256Update(S, #bip143CompactSize(#legacyVoutCount(TX, IDX, HT))),
               TX, #txVout0Offset(TX), 0,
               #legacyVoutCount(TX, IDX, HT), IDX, HT)

  // Stream the full legacy preimage (version + vins + vouts + locktime +
  // hashtype) through S and return the finalized 32-byte first-round digest.
  syntax Bytes ::= #streamLegacyPreimageHash(Bytes, Int, Bytes, Int) [function]
  rule #streamLegacyPreimageHash(TX, IDX, SC, HT) =>
         Sha256Final(
           Sha256Update(
             Sha256Update(
               #streamLegacyVoutsBlock(
                 #streamLegacyVinsBlock(
                   Sha256Update(Sha256Init(),
                                Int2Bytes(4, #txVersion(TX), LE)),
                   TX, IDX, SC, HT),
                 TX, IDX, HT),
               Int2Bytes(4, #txLocktime(TX), LE)),
             Int2Bytes(4, HT, LE)))

  // FindAndDelete(OP_CODESEPARATOR) — script-aware removal of codesep
  // opcodes. The old implementation did a byte-level scan which would
  // strip 0xab bytes that happen to appear inside push data (e.g. a
  // pubkey hash containing 0xab). Bitcoin Core's FindAndDelete iterates
  // opcode-by-opcode and only strips the opcode when the full opcode
  // matches the pattern — which for `CScript([OP_CODESEPARATOR])` is
  // the single byte 0xab.

  // Length (in bytes) of the opcode starting at B[I].
  //   1-75       : push N: 1 + N
  //   76 (PUSHDATA1): 2 + next byte
  //   77 (PUSHDATA2): 3 + 2-byte LE
  //   78 (PUSHDATA4): 5 + 4-byte LE
  //   else       : 1 byte
  // For truncated pushes (insufficient bytes remaining), falls back to 1
  // so the walker makes forward progress; callers cap the slice via
  // #minInt against lengthBytes(B).
  syntax Int ::= #opcodeLen(Bytes, Int) [function]
  rule #opcodeLen(B, I) => 1 +Int #byteAt(B, I)
    requires #byteAt(B, I) >=Int 1 andBool #byteAt(B, I) <=Int 75
  rule #opcodeLen(B, I) => 2 +Int #byteAt(B, I +Int 1)
    requires #byteAt(B, I) ==Int 76 andBool I +Int 1 <Int lengthBytes(B)
  rule #opcodeLen(B, I) =>
           3 +Int Bytes2Int(substrBytes(B, I +Int 1, I +Int 3), LE, Unsigned)
    requires #byteAt(B, I) ==Int 77 andBool I +Int 3 <=Int lengthBytes(B)
  rule #opcodeLen(B, I) =>
           5 +Int Bytes2Int(substrBytes(B, I +Int 1, I +Int 5), LE, Unsigned)
    requires #byteAt(B, I) ==Int 78 andBool I +Int 5 <=Int lengthBytes(B)
  rule #opcodeLen(_, _) => 1 [owise]

  // min(A, B) helper. K has #if/#then/#else/#fi but a function rule is clearer.
  syntax Int ::= #minInt(Int, Int) [function]
  rule #minInt(A, B) => A requires A <=Int B
  rule #minInt(A, B) => B requires A >Int B

  syntax Bytes ::= #dropCodeseps(Bytes) [function]
  rule #dropCodeseps(B) => #dropCodesepsAcc(B, 0, .Bytes)

  syntax Bytes ::= #dropCodesepsAcc(Bytes, Int, Bytes) [function]
  rule #dropCodesepsAcc(B, I, ACC) => ACC
    requires I >=Int lengthBytes(B)
  // OP_CODESEPARATOR (as an opcode, not push data): skip 1 byte.
  rule #dropCodesepsAcc(B, I, ACC) => #dropCodesepsAcc(B, I +Int 1, ACC)
    requires I <Int lengthBytes(B) andBool #byteAt(B, I) ==Int 171
  // Any other opcode: copy the opcode bytes (capped at end of script).
  rule #dropCodesepsAcc(B, I, ACC) =>
           #dropCodesepsAcc(B,
               #minInt(I +Int #opcodeLen(B, I), lengthBytes(B)),
               ACC +Bytes substrBytes(B, I,
                 #minInt(I +Int #opcodeLen(B, I), lengthBytes(B))))
    requires I <Int lengthBytes(B) andBool #byteAt(B, I) =/=Int 171

  // FindAndDelete(script, pattern) — script-aware opcode removal where
  // the opcode's starting bytes match PATTERN (of any length). Used by
  // Bitcoin Core's EvalChecksig to strip the signature from the subscript
  // before hashing (legacy / BASE sigversion, CONST_SCRIPTCODE off).
  // Pattern of length 0 is treated as no-op (no matches).
  syntax Bytes ::= #findAndDelete(Bytes, Bytes) [function]
  rule #findAndDelete(S, P) => S
    requires lengthBytes(P) ==Int 0
  rule #findAndDelete(S, P) => #faDelAcc(S, P, 0, .Bytes)
    requires lengthBytes(P) >Int 0

  // Construct the minimal push-encoded form of DATA, matching Bitcoin
  // Core's `CScript() << vchData` serialization. FindAndDelete(sig)
  // actually looks for the SIG pushed as a complete opcode, not the raw
  // sig bytes; e.g. a 72-byte sig in a script looks like `0x48 <72B>`
  // and that whole 73-byte sequence is the pattern that must match.
  syntax Bytes ::= #pushed(Bytes) [function]
  rule #pushed(D) => .Bytes
    requires lengthBytes(D) ==Int 0
  rule #pushed(D) => Int2Bytes(1, lengthBytes(D), BE) +Bytes D
    requires lengthBytes(D) >=Int 1 andBool lengthBytes(D) <=Int 75
  rule #pushed(D) =>
           Int2Bytes(1, 76, BE) +Bytes Int2Bytes(1, lengthBytes(D), BE) +Bytes D
    requires lengthBytes(D) >=Int 76 andBool lengthBytes(D) <=Int 255
  rule #pushed(D) =>
           Int2Bytes(1, 77, BE) +Bytes Int2Bytes(2, lengthBytes(D), LE) +Bytes D
    requires lengthBytes(D) >=Int 256 andBool lengthBytes(D) <=Int 65535
  rule #pushed(D) =>
           Int2Bytes(1, 78, BE) +Bytes Int2Bytes(4, lengthBytes(D), LE) +Bytes D
    requires lengthBytes(D) >=Int 65536 andBool lengthBytes(D) <=Int 4294967295

  // Iteratively apply #findAndDelete(scriptCode, pushed(sig)) for every
  // signature in SIGS. Used by legacy CHECKMULTISIG, where Bitcoin Core's
  // EvalChecksig strips ALL collected sigs from the subscript before
  // starting the per-sig verification loop. Witness-v0 CHECKMULTISIG
  // does NOT apply this (BIP-143).
  syntax Bytes ::= #findAndDeleteAll(Bytes, List) [function]
  rule #findAndDeleteAll(S, .List) => S
  rule #findAndDeleteAll(S, ListItem(SIG:Bytes) SIGS) =>
         #findAndDeleteAll(#findAndDelete(S, #pushed(SIG)), SIGS)

  syntax Bytes ::= #faDelAcc(Bytes, Bytes, Int, Bytes) [function]
  rule #faDelAcc(S, _, I, ACC) => ACC
    requires I >=Int lengthBytes(S)
  // Prefix at opcode start matches pattern: skip this opcode entirely.
  rule #faDelAcc(S, P, I, ACC) =>
           #faDelAcc(S, P,
                     #minInt(I +Int #opcodeLen(S, I), lengthBytes(S)),
                     ACC)
    requires I <Int lengthBytes(S)
     andBool I +Int lengthBytes(P) <=Int lengthBytes(S)
     andBool substrBytes(S, I, I +Int lengthBytes(P)) ==K P
  // Prefix doesn't match: copy opcode bytes, advance.
  rule #faDelAcc(S, P, I, ACC) =>
           #faDelAcc(S, P,
                     #minInt(I +Int #opcodeLen(S, I), lengthBytes(S)),
                     ACC +Bytes substrBytes(S, I,
                       #minInt(I +Int #opcodeLen(S, I), lengthBytes(S))))
    requires I <Int lengthBytes(S)
     andBool (I +Int lengthBytes(P) >Int lengthBytes(S)
        orBool substrBytes(S, I, I +Int lengthBytes(P)) =/=K P)

  // Legacy sighash with SIGHASH_SINGLE out-of-bounds special case.
  // Uses streaming SHA-256 for the first round: #streamLegacyPreimageHash
  // walks the preimage fields directly into a SHA-256 midstate instead of
  // materializing the concatenation in K Bytes (which would be O(tx_size²)
  // on large txs). The second SHA-256 wrap is then a fixed 32-byte input.
  syntax Bytes ::= #legacySighash(Bytes, Int, Bytes, Int) [function]
  rule #legacySighash(TX, IDX, _SC, HT) =>
           Int2Bytes(32, 1, LE)
    requires (HT &Int 31) ==Int 3 andBool IDX >=Int #txVoutCount(TX)
  rule #legacySighash(TX, IDX, SC, HT) =>
           Sha256raw(#streamLegacyPreimageHash(TX, IDX, #dropCodeseps(SC), HT))
    requires (HT &Int 31) =/=Int 3 orBool IDX <Int #txVoutCount(TX)

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
