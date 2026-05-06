requires "script-syntax.k"

module SCRIPT-NUM
  imports SCRIPT-SYNTAX
  imports INT
  imports STRING
  imports BYTES
  imports BOOL

  // =========================================================================
  // Byte-access helpers (used across all modules).
  // =========================================================================

  // Read a single byte at offset I as an unsigned int [0..255].
  syntax Int ::= #byteAt(Bytes, Int) [function]
  rule #byteAt(B, I) => Bytes2Int(substrBytes(B, I, I +Int 1), BE, Unsigned)

  // Last byte of a byte string; useful for sigHashType and CScriptNum sign byte.
  syntax Int ::= #byteLast(Bytes) [function]
  rule #byteLast(B) => #byteAt(B, lengthBytes(B) -Int 1)

  // CScriptNum boolean: true -> b"\x01" (intToScriptNum(1)),
  //                     false -> b""     (intToScriptNum(0)).
  // Used by every comparison/boolean opcode to push a canonical 1/0 result
  // without duplicating the rule for each truth value.
  syntax Bytes ::= #boolToBytes(Bool) [function, total]
  rule #boolToBytes(true)  => intToScriptNum(1)
  rule #boolToBytes(false) => intToScriptNum(0)

  // =========================================================================
  // CScriptNum: Bitcoin script number encoding (LE sign-magnitude, 0-4 bytes)
  //
  //   0      -> b""
  //   1      -> b"\x01"
  //  -1      -> b"\x81"
  //  127     -> b"\x7f"
  //  128     -> b"\x80\x00"
  //  -128    -> b"\x80\x80"
  //  255     -> b"\xff\x00"
  //  -255    -> b"\xff\x80"
  // =========================================================================

  // --- Decode: Bytes -> Int ---
  // NOTE: scriptNumToInt must be total (LLVM backend crashes on partial functions).
  // The 4-byte limit (nMaxNumSize) is enforced at the opcode rule level, not here.
  syntax Int ::= scriptNumToInt(Bytes) [function]

  // Empty bytes = 0
  rule scriptNumToInt(B) => 0
    requires lengthBytes(B) ==Int 0

  // Positive: high bit of last byte is 0
  rule scriptNumToInt(B) => Bytes2Int(B, LE, Unsigned)
    requires lengthBytes(B) >Int 0
     andBool #byteLast(B) &Int 128 ==Int 0

  // Negative: high bit of last byte is 1 — clear sign bit and negate
  rule scriptNumToInt(B) =>
      0 -Int Bytes2Int(
        substrBytes(B, 0, lengthBytes(B) -Int 1)
          +Bytes Int2Bytes(1, #byteLast(B) &Int 127, BE),
        LE, Unsigned)
    requires lengthBytes(B) >Int 0
     andBool #byteLast(B) &Int 128 =/=Int 0

  // --- 4-byte limit predicate (used by opcode rules) ---
  syntax Bool ::= validNum(Bytes) [function, total]
  rule validNum(B) => lengthBytes(B) <=Int 4

  // --- 5-byte limit predicate (used by CLTV/CSV: nMaxNumSize=5) ---
  syntax Bool ::= validNum5(Bytes) [function, total]
  rule validNum5(B) => lengthBytes(B) <=Int 5

  // --- CScriptNum minimal encoding check (for MINIMALDATA flag) ---
  // Returns true if the byte encoding is the shortest possible for the value.
  // Non-minimal: trailing zero byte when second-to-last byte's high bit is clear.
  syntax Bool ::= #isMinimalNum(Bytes) [function, total]

  // Empty = minimal (represents 0)
  rule #isMinimalNum(B) => true
    requires lengthBytes(B) ==Int 0

  // Non-empty: check if last byte's value part (bits 0-6) is zero
  // If so, either size is 1 (unnecessary zero/sign byte) or
  // second-to-last byte's high bit is clear (unnecessary padding)
  rule #isMinimalNum(B) => true
    requires lengthBytes(B) >Int 0
     andBool (#byteLast(B) &Int 127) =/=Int 0

  rule #isMinimalNum(B) => false
    requires lengthBytes(B) ==Int 1
     andBool (#byteAt(B, 0) &Int 127) ==Int 0

  rule #isMinimalNum(B) => true
    requires lengthBytes(B) >Int 1
     andBool (#byteLast(B) &Int 127) ==Int 0
     andBool (#byteAt(B, lengthBytes(B) -Int 2) &Int 128) =/=Int 0

  rule #isMinimalNum(B) => false
    requires lengthBytes(B) >Int 1
     andBool (Bytes2Int(substrBytes(B, lengthBytes(B) -Int 1, lengthBytes(B)), BE, Unsigned) &Int 127) ==Int 0
     andBool (Bytes2Int(substrBytes(B, lengthBytes(B) -Int 2, lengthBytes(B) -Int 1), BE, Unsigned) &Int 128) ==Int 0

  // --- Combined check: validNum + optional minimal encoding ---
  syntax Bool ::= validNumFlags(Bytes, Int) [function, total]
  rule validNumFlags(B, F) => validNum(B)
    requires (F &Int 64) ==Int 0  // FLAG_MINIMALDATA = 64
  rule validNumFlags(B, F) => validNum(B) andBool #isMinimalNum(B)
    requires (F &Int 64) =/=Int 0

  // --- Error string helpers for arithmetic opcode failure rules ---
  // Called only when notBool validNumFlags(V, F):
  //   SCRIPTNUM  : number exceeds the 4-byte CScriptNum limit (always an error)
  //   MINIMALDATA: valid length but non-minimal encoding with MINIMALDATA flag set
  syntax String ::= #numError(Bytes, Int) [function]
  rule #numError(V, _F) => "SCRIPTNUM"
    requires notBool validNum(V)
  rule #numError(V, F) => "MINIMALDATA"
    requires validNum(V) andBool (F &Int 64) =/=Int 0 andBool notBool #isMinimalNum(V)

  // Binary variant: check A first (second-from-top), then B (top).
  syntax String ::= #numError2(Bytes, Bytes, Int) [function]
  rule #numError2(A, _B, F) => #numError(A, F)
    requires notBool validNumFlags(A, F)
  rule #numError2(A, B, F) => #numError(B, F)
    requires validNumFlags(A, F) andBool notBool validNumFlags(B, F)

  // Ternary variant: check X, then MIN, then MAX.
  syntax String ::= #numError3(Bytes, Bytes, Bytes, Int) [function]
  rule #numError3(X, _MIN, _MAX, F) => #numError(X, F)
    requires notBool validNumFlags(X, F)
  rule #numError3(X, MIN, _MAX, F) => #numError(MIN, F)
    requires validNumFlags(X, F) andBool notBool validNumFlags(MIN, F)
  rule #numError3(X, MIN, MAX, F) => #numError(MAX, F)
    requires validNumFlags(X, F) andBool validNumFlags(MIN, F) andBool notBool validNumFlags(MAX, F)

  // --- Encode: Int -> Bytes ---
  syntax Bytes ::= intToScriptNum(Int) [function]
  syntax Bytes ::= intToScriptNumAbs(Int) [function]

  // Zero encodes as empty bytes
  rule intToScriptNum(0) => .Bytes

  // Positive: encode as unsigned LE, then add 0x00 byte if high bit set
  rule intToScriptNum(I) => intToScriptNumAbs(I)
    requires I >Int 0

  // Negative: encode |I| as unsigned LE, then set high bit of last byte
  rule intToScriptNum(I) => #setSignBit(intToScriptNumAbs(0 -Int I))
    requires I <Int 0

  // Encode absolute value as minimal unsigned LE bytes
  rule intToScriptNumAbs(I) => Int2Bytes(1, I, LE)
    requires I >Int 0 andBool I <Int 128

  // 1 byte with sign padding (high bit set: 128-255)
  rule intToScriptNumAbs(I) => Int2Bytes(1, I, LE) +Bytes Int2Bytes(1, 0, BE)
    requires I >=Int 128 andBool I <Int 256

  // 2 bytes, no padding needed (high bit of byte 1 is 0)
  rule intToScriptNumAbs(I) => Int2Bytes(2, I, LE)
    requires I >=Int 256 andBool I <Int 32768

  // 2 bytes with sign padding (high bit of byte 1 is set: 32768-65535)
  rule intToScriptNumAbs(I) => Int2Bytes(2, I, LE) +Bytes Int2Bytes(1, 0, BE)
    requires I >=Int 32768 andBool I <Int 65536

  // 3 bytes, no padding needed (high bit of byte 2 is 0)
  rule intToScriptNumAbs(I) => Int2Bytes(3, I, LE)
    requires I >=Int 65536 andBool I <Int 8388608

  // 3 bytes with sign padding (high bit of byte 2 is set: 8388608-16777215)
  rule intToScriptNumAbs(I) => Int2Bytes(3, I, LE) +Bytes Int2Bytes(1, 0, BE)
    requires I >=Int 8388608 andBool I <Int 16777216

  // 4 bytes, no padding needed (high bit of byte 3 is 0)
  rule intToScriptNumAbs(I) => Int2Bytes(4, I, LE)
    requires I >=Int 16777216 andBool I <Int 2147483648

  // 5 bytes: value needs 4 unsigned bytes but high bit (bit 31) is set
  rule intToScriptNumAbs(I) => Int2Bytes(4, I, LE) +Bytes Int2Bytes(1, 0, BE)
    requires I >=Int 2147483648 andBool I <Int 4294967296

  // Set the sign bit (high bit of last byte) for negative encoding
  syntax Bytes ::= "#setSignBit" "(" Bytes ")" [function]
  rule #setSignBit(B) =>
    substrBytes(B, 0, lengthBytes(B) -Int 1)
      +Bytes Int2Bytes(1, Bytes2Int(substrBytes(B, lengthBytes(B) -Int 1, lengthBytes(B)), BE, Unsigned) |Int 128, BE)

  // =========================================================================
  // Hex literal to Bytes conversion
  // =========================================================================

  syntax String ::= HexPgm2String(HexPgm) [function, total, hook(STRING.token2string)]

  // Convert a hex string (e.g. "abcd01") to raw Bytes
  syntax Bytes ::= hexToBytes(String, Int) [function]

  rule hexToBytes(_, 0) => .Bytes
  rule hexToBytes(S, N) => Int2Bytes(1, String2Base(substrString(S, 0, 2), 16), BE) +Bytes hexToBytes(substrString(S, 2, lengthString(S)), N -Int 1)
    requires N >Int 0

  syntax Bytes ::= hexStringToBytes(String) [function]
  rule hexStringToBytes(S) => hexToBytes(S, lengthString(S) /Int 2)
endmodule
