requires "script-num.k"
requires "plugin/krypto.md"

module SCRIPT-CRYPTO
  imports SCRIPT-NUM
  imports KRYPTO
  imports BYTES
  imports BOOL
  imports INT
  imports K-EQUAL

  // =========================================================================
  // DER signature parsing helpers
  // =========================================================================
  // DER format: 30 <total_len> 02 <r_len> <r_bytes...> 02 <s_len> <s_bytes...> <hashtype>
  // ECDSARecover expects exactly 32-byte r and s values.

  // Extract the x || y public key body (strip the 04 prefix)
  syntax Bytes ::= pubKeyBody(Bytes) [function]
  rule pubKeyBody(PK) => substrBytes(PK, 1, 65)

  // Length of the r component in the DER encoding
  syntax Int ::= derRLen(Bytes) [function]
  rule derRLen(SIG) => Bytes2Int(substrBytes(SIG, 3, 4), BE, Unsigned)

  // Length of the s component in the DER encoding
  syntax Int ::= derSLen(Bytes) [function]
  rule derSLen(SIG) => Bytes2Int(substrBytes(SIG, 5 +Int derRLen(SIG), 6 +Int derRLen(SIG)), BE, Unsigned)

  // Normalize a DER integer component to exactly 32 bytes
  // Handles leading 0x00 padding (33-byte DER integers) and short values
  syntax Bytes ::= normTo32(Bytes) [function]
  rule normTo32(B) => Int2Bytes(32, Bytes2Int(B, BE, Unsigned), BE)

  // Extract r as exactly 32 bytes
  syntax Bytes ::= derR(Bytes) [function]
  rule derR(SIG) => normTo32(substrBytes(SIG, 4, 4 +Int derRLen(SIG)))

  // Extract s as exactly 32 bytes
  syntax Bytes ::= derS(Bytes) [function]
  rule derS(SIG) => normTo32(substrBytes(SIG, 6 +Int derRLen(SIG), 6 +Int derRLen(SIG) +Int derSLen(SIG)))

  // =========================================================================
  // Sighash lookup: extract hashtype from signature, look up in sighash blob
  // =========================================================================

  // Extract hashtype byte (last byte) from a DER+hashtype signature
  syntax Int ::= sigHashType(Bytes) [function]
  rule sigHashType(SIG) => Bytes2Int(substrBytes(SIG, lengthBytes(SIG) -Int 1, lengthBytes(SIG)), BE, Unsigned)
    requires lengthBytes(SIG) >Int 0
  rule sigHashType(SIG) => 1
    requires lengthBytes(SIG) ==Int 0

  // Look up sighash in a blob by hashtype.
  // Blob format: concatenated (1-byte hashtype + 32-byte hash) entries.
  // Backward compat: if blob is exactly 32 bytes, return it directly.
  syntax Bytes ::= lookupSighash(Bytes, Int) [function]

  // Legacy: 32-byte blob = raw sighash (ignore hashtype)
  rule lookupSighash(BLOB, _) => BLOB
    requires lengthBytes(BLOB) ==Int 32

  // Found matching entry: return the 32-byte hash
  rule lookupSighash(BLOB, HT) => substrBytes(BLOB, 1, 33)
    requires lengthBytes(BLOB) >=Int 33
     andBool Bytes2Int(substrBytes(BLOB, 0, 1), BE, Unsigned) ==Int HT

  // Entry doesn't match: skip to next 33-byte chunk
  rule lookupSighash(BLOB, HT) => lookupSighash(substrBytes(BLOB, 33, lengthBytes(BLOB)), HT)
    requires lengthBytes(BLOB) >=Int 33
     andBool Bytes2Int(substrBytes(BLOB, 0, 1), BE, Unsigned) =/=Int HT

  // No match found or blob too short: return empty bytes (ecdsaVerify will fail)
  rule lookupSighash(BLOB, _) => .Bytes
    requires lengthBytes(BLOB) <Int 32
  rule lookupSighash(BLOB, _) => .Bytes
    requires lengthBytes(BLOB) >Int 32
     andBool lengthBytes(BLOB) <Int 33

  // =========================================================================
  // Compressed public key support
  // =========================================================================

  // Compress a 64-byte public key body (x || y) to 33-byte compressed form.
  // Prefix: 02 if y is even, 03 if y is odd.
  syntax Bytes ::= compressKey(Bytes) [function]
  rule compressKey(BODY) =>
      Int2Bytes(1, 2 +Int (Bytes2Int(substrBytes(BODY, 63, 64), BE, Unsigned) &Int 1), BE)
      +Bytes substrBytes(BODY, 0, 32)
    requires lengthBytes(BODY) ==Int 64

  // Defensive: non-64-byte input returns a dummy that won't match any real key
  rule compressKey(BODY) => Int2Bytes(33, 0, BE)
    requires lengthBytes(BODY) =/=Int 64

  // =========================================================================
  // Strict DER signature validation (BIP66 / DERSIG flag)
  // =========================================================================
  // DER: 30 <total_len> 02 <r_len> <r_bytes...> 02 <s_len> <s_bytes...> <hashtype>

  syntax Bool ::= isValidDER(Bytes) [function, total]

  // Must be at least 9 bytes: 30 01 02 01 xx 02 01 xx HT
  // Must be at most 73 bytes: 30 46 02 21 <33> 02 21 <33> HT
  rule isValidDER(SIG) => false requires lengthBytes(SIG) <Int 9
  rule isValidDER(SIG) => false requires lengthBytes(SIG) >Int 73

  rule isValidDER(SIG) => #checkDERInner(SIG)
    requires lengthBytes(SIG) >=Int 9
     andBool lengthBytes(SIG) <=Int 73

  // Helper: extract R length from DER sig
  syntax Int ::= #derRL(Bytes) [function]
  rule #derRL(SIG) => Bytes2Int(substrBytes(SIG, 3, 4), BE, Unsigned)

  // Helper: extract S length from DER sig
  syntax Int ::= #derSL(Bytes) [function]
  rule #derSL(SIG) => Bytes2Int(substrBytes(SIG, 5 +Int #derRL(SIG), 6 +Int #derRL(SIG)), BE, Unsigned)

  // Helper: offset of S data
  syntax Int ::= #derSO(Bytes) [function]
  rule #derSO(SIG) => 6 +Int #derRL(SIG)

  syntax Bool ::= #checkDERInner(Bytes) [function]
  rule #checkDERInner(SIG) => true
    requires Bytes2Int(substrBytes(SIG, 0, 1), BE, Unsigned) ==Int 48           // 0x30 compound
     andBool Bytes2Int(substrBytes(SIG, 1, 2), BE, Unsigned)
             ==Int lengthBytes(SIG) -Int 3                                      // total len = sig - 3
     andBool Bytes2Int(substrBytes(SIG, 2, 3), BE, Unsigned) ==Int 2            // 0x02 R tag
     andBool #derRL(SIG) >=Int 1                                                // R length >= 1
     andBool #derRL(SIG) <=Int lengthBytes(SIG) -Int 7                          // room for S
     // R not negative, no excessive padding
     andBool Bytes2Int(substrBytes(SIG, 4, 5), BE, Unsigned) &Int 128 ==Int 0
     andBool (#derRL(SIG) <=Int 1
        orBool Bytes2Int(substrBytes(SIG, 4, 5), BE, Unsigned) =/=Int 0)
     // S tag
     andBool Bytes2Int(substrBytes(SIG, 4 +Int #derRL(SIG),
                                        5 +Int #derRL(SIG)), BE, Unsigned) ==Int 2
     // S length
     andBool #derSL(SIG) >=Int 1
     andBool (#derSO(SIG) +Int #derSL(SIG)) ==Int lengthBytes(SIG) -Int 1       // S ends at hashtype
     // S not negative
     andBool Bytes2Int(substrBytes(SIG, #derSO(SIG), #derSO(SIG) +Int 1), BE, Unsigned) &Int 128 ==Int 0
     // No excessive S padding
     andBool (#derSL(SIG) <=Int 1
        orBool Bytes2Int(substrBytes(SIG, #derSO(SIG), #derSO(SIG) +Int 1), BE, Unsigned) =/=Int 0)

  rule #checkDERInner(_) => false [owise]

  // =========================================================================
  // Signature/pubkey format validation (for STRICTENC flag)
  // =========================================================================

  // Valid hashtype: base type 1-3, optionally OR'd with 0x80 (ANYONECANPAY)
  syntax Bool ::= validHashType(Int) [function, total]
  rule validHashType(HT) => true
    requires (HT &Int 31) >=Int 1 andBool (HT &Int 31) <=Int 3
     andBool (HT &Int 224) ==Int 0  // only bits 0-4 and bit 7 allowed
  rule validHashType(_) => false [owise]

  // Valid pubkey: 33-byte compressed (02/03 prefix) or 65-byte uncompressed (04 prefix)
  syntax Bool ::= validPubKeyType(Bytes) [function, total]
  rule validPubKeyType(PK) => true
    requires ( lengthBytes(PK) ==Int 33
               andBool ( Bytes2Int(substrBytes(PK, 0, 1), BE, Unsigned) ==Int 2
                  orBool Bytes2Int(substrBytes(PK, 0, 1), BE, Unsigned) ==Int 3 ) )
      orBool ( lengthBytes(PK) ==Int 65
               andBool Bytes2Int(substrBytes(PK, 0, 1), BE, Unsigned) ==Int 4 )
  rule validPubKeyType(_) => false [owise]

  // =========================================================================
  // ecdsaVerify: reusable ECDSA verification (used by CHECKSIG & CHECKMULTISIG)
  // =========================================================================

  syntax Bool ::= ecdsaVerify(Bytes, Bytes, Bytes) [function]
  // ecdsaVerify(pubkey, sig_der_with_hashtype, sighash_32B)

  // Uncompressed key (65 bytes, 04 prefix)
  rule ecdsaVerify(PK, SIG, SIGHASH) => true
    requires lengthBytes(PK)      ==Int 65
     andBool lengthBytes(SIGHASH) ==Int 32
     andBool lengthBytes(SIG)     >=Int 9
     andBool ( ECDSARecover(SIGHASH, 27, derR(SIG), derS(SIG)) ==K pubKeyBody(PK)
        orBool ECDSARecover(SIGHASH, 28, derR(SIG), derS(SIG)) ==K pubKeyBody(PK) )

  // Compressed key (33 bytes, 02/03 prefix)
  rule ecdsaVerify(PK, SIG, SIGHASH) => true
    requires lengthBytes(PK)      ==Int 33
     andBool lengthBytes(SIGHASH) ==Int 32
     andBool lengthBytes(SIG)     >=Int 9
     andBool ( compressKey(ECDSARecover(SIGHASH, 27, derR(SIG), derS(SIG))) ==K PK
        orBool compressKey(ECDSARecover(SIGHASH, 28, derR(SIG), derS(SIG))) ==K PK )

  rule ecdsaVerify(_, _, _) => false [owise]

  // =========================================================================
  // LOW_S check: S value must be <= half the secp256k1 curve order
  // =========================================================================
  // secp256k1 order n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
  // half order = n / 2

  syntax Int ::= "SECP256K1_HALF_ORDER" [macro]
  rule SECP256K1_HALF_ORDER => 57896044618658097711785492504343953926418782139537452191302581570759080747168

  syntax Bool ::= isLowDerS(Bytes) [function, total]
  rule isLowDerS(SIG) => Bytes2Int(derS(SIG), BE, Unsigned) <=Int SECP256K1_HALF_ORDER
    requires isValidDER(SIG)
  rule isLowDerS(_) => false [owise]

endmodule
