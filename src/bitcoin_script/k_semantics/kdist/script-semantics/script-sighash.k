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
