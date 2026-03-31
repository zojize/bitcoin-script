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
endmodule
