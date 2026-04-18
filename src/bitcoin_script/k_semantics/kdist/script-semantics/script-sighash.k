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
