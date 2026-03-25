requires "plugin/krypto.md"

module SCRIPT-SYNTAX
  imports INT-SYNTAX
  imports STRING-SYNTAX
  imports BYTES-SYNTAX

  // --- Hex literal token ---
  syntax HexLiteral ::= r"[0-9a-fA-F]+" [token]

  // --- Opcodes ---
  syntax OpCode ::= "OP_DUP"
                  | "OP_ADD"
                  | "OP_EQUALVERIFY"
                  | "OP_HASH160"
                  | "OP_CHECKSIG"
                  | "OP_CHECKMULTISIG"
                  | "OP_PUSHBYTES_20" HexLiteral
                  | "OP_PUSHBYTES_32" HexLiteral
                  | "OP_PUSHBYTES_33" HexLiteral
                  | "OP_PUSHBYTES_65" HexLiteral
                  | "OP_PUSHBYTES_70" HexLiteral
                  | "OP_PUSHBYTES_71" HexLiteral
                  | "OP_PUSHBYTES_72" HexLiteral
                  | "OP_PUSHBYTES_73" HexLiteral
                  | "OP_PUSH" Int
                  | "OP_0"  | "OP_1"  | "OP_2"  | "OP_3"
                  | "OP_4"  | "OP_5"  | "OP_6"  | "OP_7"
                  | "OP_8"  | "OP_9"  | "OP_10" | "OP_11"
                  | "OP_12" | "OP_13" | "OP_14" | "OP_15"
                  | "OP_16"

  // --- Script is a sequence of opcodes (whitespace-separated) ---
  syntax Script ::= OpCode | Script Script [left]
endmodule

module SCRIPT
  imports SCRIPT-SYNTAX
  imports KRYPTO
  imports INT
  imports STRING
  imports BOOL
  imports K-EQUAL
  imports LIST
  imports BYTES

  // --- Configuration ---
  configuration
    <T>
      <k> $PGM:Script </k>
      <stack> .List </stack>
    </T>

  // --- Script sequencing: flatten Script Script into K sequence ---
  rule <k> S1:Script S2:Script => S1 ~> S2 ...</k>

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

  // Set the sign bit (high bit of last byte) for negative encoding
  syntax Bytes ::= "#setSignBit" "(" Bytes ")" [function]
  rule #setSignBit(B) =>
    substrBytes(B, 0, lengthBytes(B) -Int 1)
      +Bytes Int2Bytes(1, Bytes2Int(substrBytes(B, lengthBytes(B) -Int 1, lengthBytes(B)), BE, Unsigned) |Int 128, BE)

  // =========================================================================
  // Hex literal to Bytes conversion
  // =========================================================================

  syntax String ::= HexLiteral2String(HexLiteral) [function, total, hook(STRING.token2string)]

  // Convert a hex string (e.g. "abcd01") to raw Bytes
  syntax Bytes ::= hexToBytes(String, Int) [function]

  rule hexToBytes(_, 0) => .Bytes
  rule hexToBytes(S, N) => Int2Bytes(1, String2Base(substrString(S, 0, 2), 16), BE) +Bytes hexToBytes(substrString(S, 2, lengthString(S)), N -Int 1)
    requires N >Int 0

  syntax Bytes ::= hexStringToBytes(String) [function]
  rule hexStringToBytes(S) => hexToBytes(S, lengthString(S) /Int 2)

  // =========================================================================
  // OP_PUSHBYTES_* (shared implementation via #pushBytes)
  // =========================================================================

  syntax KItem ::= "#pushBytes" "(" Int "," HexLiteral ")"

  rule <k> OP_PUSHBYTES_20 H => #pushBytes(20, H) ...</k>
  rule <k> OP_PUSHBYTES_32 H => #pushBytes(32, H) ...</k>
  rule <k> OP_PUSHBYTES_33 H => #pushBytes(33, H) ...</k>
  rule <k> OP_PUSHBYTES_65 H => #pushBytes(65, H) ...</k>
  rule <k> OP_PUSHBYTES_70 H => #pushBytes(70, H) ...</k>
  rule <k> OP_PUSHBYTES_71 H => #pushBytes(71, H) ...</k>
  rule <k> OP_PUSHBYTES_72 H => #pushBytes(72, H) ...</k>
  rule <k> OP_PUSHBYTES_73 H => #pushBytes(73, H) ...</k>

  rule <k> #pushBytes(N, H) => .K ...</k>
       <stack> ST => ListItem(hexStringToBytes(HexLiteral2String(H))) ST </stack>
    requires lengthString(HexLiteral2String(H)) ==Int 2 *Int N

  // =========================================================================
  // OP_PUSH (test helper: push integer onto stack as CScriptNum bytes)
  // =========================================================================

  rule <k> OP_PUSH I:Int => .K ...</k>
       <stack> ST => ListItem(intToScriptNum(I)) ST </stack>

  // =========================================================================
  // OP_0 through OP_16: push small integer constants as CScriptNum bytes
  // =========================================================================

  rule <k> OP_0  => .K ...</k>  <stack> ST => ListItem(intToScriptNum(0))  ST </stack>
  rule <k> OP_1  => .K ...</k>  <stack> ST => ListItem(intToScriptNum(1))  ST </stack>
  rule <k> OP_2  => .K ...</k>  <stack> ST => ListItem(intToScriptNum(2))  ST </stack>
  rule <k> OP_3  => .K ...</k>  <stack> ST => ListItem(intToScriptNum(3))  ST </stack>
  rule <k> OP_4  => .K ...</k>  <stack> ST => ListItem(intToScriptNum(4))  ST </stack>
  rule <k> OP_5  => .K ...</k>  <stack> ST => ListItem(intToScriptNum(5))  ST </stack>
  rule <k> OP_6  => .K ...</k>  <stack> ST => ListItem(intToScriptNum(6))  ST </stack>
  rule <k> OP_7  => .K ...</k>  <stack> ST => ListItem(intToScriptNum(7))  ST </stack>
  rule <k> OP_8  => .K ...</k>  <stack> ST => ListItem(intToScriptNum(8))  ST </stack>
  rule <k> OP_9  => .K ...</k>  <stack> ST => ListItem(intToScriptNum(9))  ST </stack>
  rule <k> OP_10 => .K ...</k>  <stack> ST => ListItem(intToScriptNum(10)) ST </stack>
  rule <k> OP_11 => .K ...</k>  <stack> ST => ListItem(intToScriptNum(11)) ST </stack>
  rule <k> OP_12 => .K ...</k>  <stack> ST => ListItem(intToScriptNum(12)) ST </stack>
  rule <k> OP_13 => .K ...</k>  <stack> ST => ListItem(intToScriptNum(13)) ST </stack>
  rule <k> OP_14 => .K ...</k>  <stack> ST => ListItem(intToScriptNum(14)) ST </stack>
  rule <k> OP_15 => .K ...</k>  <stack> ST => ListItem(intToScriptNum(15)) ST </stack>
  rule <k> OP_16 => .K ...</k>  <stack> ST => ListItem(intToScriptNum(16)) ST </stack>

  // =========================================================================
  // OP_DUP
  // =========================================================================

  rule <k> OP_DUP => .K ...</k>
       <stack> ListItem(V) ST => ListItem(V) ListItem(V) ST </stack>

  // =========================================================================
  // OP_ADD: pop two CScriptNum bytes, add, push result as CScriptNum bytes
  // =========================================================================

  rule <k> OP_ADD => .K ...</k>
       <stack> ListItem(A:Bytes) ListItem(B:Bytes) ST
            => ListItem(intToScriptNum(scriptNumToInt(A) +Int scriptNumToInt(B))) ST </stack>

  // =========================================================================
  // OP_HASH160: RIPEMD160(SHA256(data))
  // =========================================================================

  rule <k> OP_HASH160 => .K ...</k>
       <stack> ListItem(V:Bytes) ST => ListItem(RipEmd160raw(Sha256raw(V))) ST </stack>

  // =========================================================================
  // OP_EQUALVERIFY: pop two byte values, continue if equal, otherwise stuck
  // =========================================================================

  rule <k> OP_EQUALVERIFY => .K ...</k>
       <stack> ListItem(V:Bytes) ListItem(V:Bytes) ST => ST </stack>

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

  // =========================================================================
  // OP_CHECKSIG
  // =========================================================================
  // Pops 3 items: <pubkey> (top), <sig_der_with_hashtype>, <sighash> (bottom).
  // Pushes CScriptNum 1 (true) or empty bytes (false).

  rule <k> OP_CHECKSIG => .K ...</k>
       <stack> ListItem(PK:Bytes) ListItem(SIG:Bytes) ListItem(SIGHASH:Bytes) ST
            => ListItem(intToScriptNum(1)) ST </stack>
    requires ecdsaVerify(PK, SIG, SIGHASH)

  rule <k> OP_CHECKSIG => .K ...</k>
       <stack> ListItem(PK:Bytes) ListItem(SIG:Bytes) ListItem(SIGHASH:Bytes) ST
            => ListItem(intToScriptNum(0)) ST </stack>
    requires notBool ecdsaVerify(PK, SIG, SIGHASH)
    [owise]

  // =========================================================================
  // OP_CHECKMULTISIG
  // =========================================================================
  // Stack layout (top to bottom):
  //   N, pkN, ..., pk1, M, sigM, ..., sig1, dummy, sighash
  //
  // Pops N (number of pubkeys), N pubkeys, M (number of required sigs),
  // M signatures, a dummy element (Bitcoin's off-by-one bug), and a sighash.
  // Verifies M-of-N: signatures must match pubkeys in order.
  // Pushes CScriptNum 1 (true) or empty bytes (false).

  syntax KItem ::= "#collectPubKeys" "(" Int "," List ")"
                 | "#collectSigs" "(" Int "," List "," List ")"
                 | "#verifyMultisig" "(" List "," List "," Bytes ")"

  // Step 1: Pop N from stack (CScriptNum), begin collecting pubkeys
  rule <k> OP_CHECKMULTISIG => #collectPubKeys(scriptNumToInt(N), .List) ...</k>
       <stack> ListItem(N:Bytes) ST => ST </stack>

  // Step 2a: Pop one pubkey, prepend to collected list
  rule <k> #collectPubKeys(N, PKs) => #collectPubKeys(N -Int 1, ListItem(PK) PKs) ...</k>
       <stack> ListItem(PK) ST => ST </stack>
    requires N >Int 0

  // Step 2b: All N pubkeys collected; pop M (CScriptNum) and begin collecting sigs
  rule <k> #collectPubKeys(0, PKs) => #collectSigs(scriptNumToInt(M), PKs, .List) ...</k>
       <stack> ListItem(M:Bytes) ST => ST </stack>

  // Step 3a: Pop one sig, prepend to collected list
  rule <k> #collectSigs(M, PKs, Sigs) => #collectSigs(M -Int 1, PKs, ListItem(SIG) Sigs) ...</k>
       <stack> ListItem(SIG) ST => ST </stack>
    requires M >Int 0

  // Step 3b: All M sigs collected; pop dummy element + sighash, begin verification
  rule <k> #collectSigs(0, PKs, Sigs) => #verifyMultisig(PKs, Sigs, SIGHASH) ...</k>
       <stack> ListItem(_) ListItem(SIGHASH:Bytes) ST => ST </stack>

  // Step 4a: All sigs verified (sigs list exhausted) — push true
  rule <k> #verifyMultisig(_, .List, _) => .K ...</k>
       <stack> ST => ListItem(intToScriptNum(1)) ST </stack>

  // Step 4b: Sigs remain but pubkeys exhausted — push false
  rule <k> #verifyMultisig(.List, ListItem(_) _, _) => .K ...</k>
       <stack> ST => ListItem(intToScriptNum(0)) ST </stack>

  // Step 4c: Current sig matches current pubkey — advance both
  rule <k> #verifyMultisig(ListItem(PK:Bytes) PKs, ListItem(SIG:Bytes) Sigs, SIGHASH)
        => #verifyMultisig(PKs, Sigs, SIGHASH) ...</k>
    requires ecdsaVerify(PK, SIG, SIGHASH)

  // Step 4d: Current sig does not match current pubkey — advance pubkey only
  rule <k> #verifyMultisig(ListItem(PK:Bytes) PKs, ListItem(SIG:Bytes) Sigs, SIGHASH)
        => #verifyMultisig(PKs, ListItem(SIG) Sigs, SIGHASH) ...</k>
    requires notBool ecdsaVerify(PK, SIG, SIGHASH)

endmodule
