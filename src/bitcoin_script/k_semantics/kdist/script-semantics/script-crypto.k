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
  // ecdsaVerify: reusable ECDSA verification (used by CHECKSIG & CHECKMULTISIG)
  // =========================================================================

  syntax Bool ::= ecdsaVerify(Bytes, Bytes, Bytes) [function]
  // ecdsaVerify(pubkey_65B, sig_der_with_hashtype, sighash_32B)

  rule ecdsaVerify(PK, SIG, SIGHASH) => true
    requires lengthBytes(PK)      ==Int 65
     andBool lengthBytes(SIGHASH) ==Int 32
     andBool ( ECDSARecover(SIGHASH, 27, derR(SIG), derS(SIG)) ==K pubKeyBody(PK)
        orBool ECDSARecover(SIGHASH, 28, derR(SIG), derS(SIG)) ==K pubKeyBody(PK) )

  rule ecdsaVerify(_, _, _) => false [owise]
endmodule
