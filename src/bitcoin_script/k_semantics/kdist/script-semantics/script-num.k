requires "script-syntax.k"

module SCRIPT-NUM
  imports SCRIPT-SYNTAX
  imports INT
  imports STRING
  imports BYTES
  imports BOOL

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
     andBool Bytes2Int(substrBytes(B, lengthBytes(B) -Int 1, lengthBytes(B)), BE, Unsigned) &Int 128 ==Int 0

  // Negative: high bit of last byte is 1 — clear sign bit and negate
  rule scriptNumToInt(B) =>
      0 -Int Bytes2Int(
        substrBytes(B, 0, lengthBytes(B) -Int 1)
          +Bytes Int2Bytes(1, Bytes2Int(substrBytes(B, lengthBytes(B) -Int 1, lengthBytes(B)), BE, Unsigned) &Int 127, BE),
        LE, Unsigned)
    requires lengthBytes(B) >Int 0
     andBool Bytes2Int(substrBytes(B, lengthBytes(B) -Int 1, lengthBytes(B)), BE, Unsigned) &Int 128 =/=Int 0

  // --- 4-byte limit predicate (used by opcode rules) ---
  syntax Bool ::= validNum(Bytes) [function, total]
  rule validNum(B) => lengthBytes(B) <=Int 4

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

  rule intToScriptNumAbs(I) => Int2Bytes(2, I, LE) +Bytes Int2Bytes(1, 0, BE)
    requires I ==Int 128

  rule intToScriptNumAbs(I) => Int2Bytes(2, I, LE)
    requires I >Int 128 andBool I <Int 32768
     andBool I &Int 32768 ==Int 0

  rule intToScriptNumAbs(I) => Int2Bytes(2, I, LE) +Bytes Int2Bytes(1, 0, BE)
    requires I >=Int 32768 andBool I <Int 65536
     andBool I &Int 32768 =/=Int 0

  rule intToScriptNumAbs(I) => Int2Bytes(3, I, LE)
    requires I >=Int 32768 andBool I <Int 8388608
     andBool I &Int 8388608 ==Int 0

  rule intToScriptNumAbs(I) => Int2Bytes(3, I, LE) +Bytes Int2Bytes(1, 0, BE)
    requires I >=Int 8388608 andBool I <Int 16777216
     andBool I &Int 8388608 =/=Int 0

  rule intToScriptNumAbs(I) => Int2Bytes(4, I, LE)
    requires I >=Int 8388608 andBool I <Int 2147483648
     andBool I &Int 2147483648 ==Int 0

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
