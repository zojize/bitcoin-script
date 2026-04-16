requires "script-semantics.k"

// Script decoder: converts raw bytes to opcode sequences.
// Includes resource limits (opCount, push size) and MINIMALDATA push checks.
module SCRIPT-DECODE
  imports SCRIPT-SEMANTICS
  imports INT
  imports STRING
  imports BYTES
  imports BOOL

  // Hex script decoding: HexPgm -> Bytes -> opcodes
  // =========================================================================

  // Strip "0x" prefix, convert hex string to bytes, decode
  rule <k> H:HexPgm => #decodeScript(hexStringToBytes(substrString(HexPgm2String(H), 2, lengthString(HexPgm2String(H))))) ...</k>

  // (#scriptByte/#scriptTail syntax+rules in SCRIPT-SEMANTICS)

  // --- Resource limits ---
  // MAX_OPS_PER_SCRIPT = 201, MAX_SCRIPT_ELEMENT_SIZE = 520, MAX_SCRIPT_SIZE = 10000

  // Count one opcode (for opcodes > OP_16, byte > 96). Fails if > 201.
  // (#countOp/#countOps syntax declared in SCRIPT-SEMANTICS)
  rule <k> #countOp => .K ...</k>
       <opCount> N => N +Int 1 </opCount>
    requires N +Int 1 <=Int 201

  rule <k> #countOp => #fail("OP_COUNT") ...</k>
       <opCount> N </opCount>
    requires N +Int 1 >Int 201

  // Count N ops at once (used by CHECKMULTISIG for pubkey count)
  rule <k> #countOps(M) => .K ...</k>
       <opCount> N => N +Int M </opCount>
    requires N +Int M <=Int 201

  rule <k> #countOps(M) => #fail("OP_COUNT") ...</k>
       <opCount> N </opCount>
    requires N +Int M >Int 201

  // --- MINIMALDATA: check push encoding uses smallest opcode ---
  // #isMinimalPush(opcode_byte, push_data) -> Bool
  // (#isMinimalPush syntax declared in SCRIPT-SEMANTICS)

  // Empty data → should use OP_0 (byte 0), not a push
  rule #isMinimalPush(_, DATA) => false
    requires lengthBytes(DATA) ==Int 0

  // Single-byte 1-16 → should use OP_1 through OP_16
  rule #isMinimalPush(_, DATA) => false
    requires lengthBytes(DATA) ==Int 1
     andBool Bytes2Int(DATA, BE, Unsigned) >=Int 1
     andBool Bytes2Int(DATA, BE, Unsigned) <=Int 16

  // Single-byte 0x81 → should use OP_1NEGATE
  rule #isMinimalPush(_, DATA) => false
    requires lengthBytes(DATA) ==Int 1
     andBool Bytes2Int(DATA, BE, Unsigned) ==Int 129

  // 1-75 bytes (non-special) → PUSHBYTES_N (opcode = length) is minimal
  rule #isMinimalPush(OPC, DATA) => OPC ==Int lengthBytes(DATA)
    requires lengthBytes(DATA) >=Int 1
     andBool lengthBytes(DATA) <=Int 75
     andBool notBool ( lengthBytes(DATA) ==Int 1
        andBool ( ( Bytes2Int(DATA, BE, Unsigned) >=Int 1
               andBool Bytes2Int(DATA, BE, Unsigned) <=Int 16 )
          orBool Bytes2Int(DATA, BE, Unsigned) ==Int 129 ) )

  // 76-255 bytes → PUSHDATA1 (76) is minimal
  rule #isMinimalPush(OPC, DATA) => OPC ==Int 76
    requires lengthBytes(DATA) >=Int 76
     andBool lengthBytes(DATA) <=Int 255

  // 256+ bytes → PUSHDATA2 (77) is minimal
  rule #isMinimalPush(OPC, DATA) => OPC ==Int 77
    requires lengthBytes(DATA) >=Int 256

  // Anything else → not minimal
  rule #isMinimalPush(_, _) => false [owise]

  // --- Decode entry point ---
  // #decodeScript dispatches to #decode1, counting opcodes > OP_16 (byte > 96).
  // (syntax declared in SCRIPT-SEMANTICS)

  // Empty script — done (also check STACK_SIZE at end)
  rule <k> #decodeScript(B) => .K ...</k>
       <stack> ST </stack>
       <altstack> AST </altstack>
    requires lengthBytes(B) ==Int 0
     andBool size(ST) +Int size(AST) <=Int 1000

  // STACK_SIZE: check stack + altstack <= 1000
  rule <k> #decodeScript(_) => #fail("STACK_SIZE") ...</k>
       <stack> ST </stack>
       <altstack> AST </altstack>
    requires size(ST) +Int size(AST) >Int 1000

  // Opcode > OP_16 (byte > 96): count before decoding
  rule <k> #decodeScript(B) => #countOp ~> #decode1(B) ...</k>
       <stack> ST </stack>
       <altstack> AST </altstack>
    requires lengthBytes(B) >Int 0
     andBool #scriptByte(B) >Int 96
     andBool size(ST) +Int size(AST) <=Int 1000

  // Opcode <= OP_16 (byte <= 96): decode without counting
  rule <k> #decodeScript(B) => #decode1(B) ...</k>
       <stack> ST </stack>
       <altstack> AST </altstack>
    requires lengthBytes(B) >Int 0
     andBool #scriptByte(B) <=Int 96
     andBool size(ST) +Int size(AST) <=Int 1000

  // OP_0 (0x00)
  rule <k> #decode1(B) => #guardExec(OP_0) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0
     andBool #scriptByte(B) ==Int 0

  // OP_PUSHBYTES_1 through OP_PUSHBYTES_75 (0x01 - 0x4b)
  rule <k> #decode1(B) => #decodePush(#scriptByte(B), #scriptByte(B), #scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0
     andBool #scriptByte(B) >=Int 1
     andBool #scriptByte(B) <=Int 75

  // #decodePush(opcode_byte, data_length, remaining_script)
  // Resolves push: extract data, check PUSH_SIZE, emit OP_PUSHDATA with opcode byte
  // MINIMALDATA is checked at execution time (not decode) so dead IF branches are OK
  rule <k> #decodePush(OPC, N, B) => #guardExec(OP_PUSHDATA(OPC, substrBytes(B, 0, N)))
        ~> #decodeScript(substrBytes(B, N, lengthBytes(B))) ...</k>
    requires lengthBytes(B) >=Int N
     andBool N <=Int 520

  rule <k> #decodePush(_, N, _) => #fail("PUSH_SIZE") ...</k>
    requires N >Int 520

  // OP_PUSHDATA1 (0x4c = 76): next byte is length, then that many bytes of data
  rule <k> #decode1(B) =>
      #decodePush(
        76,
        Bytes2Int(substrBytes(B, 1, 2), BE, Unsigned),
        substrBytes(B, 2, lengthBytes(B))
      ) ...</k>
    requires lengthBytes(B) >Int 1
     andBool #scriptByte(B) ==Int 76

  // OP_PUSHDATA2 (0x4d = 77): next 2 bytes (LE) are length, then data
  rule <k> #decode1(B) =>
      #decodePush(
        77,
        Bytes2Int(substrBytes(B, 1, 3), LE, Unsigned),
        substrBytes(B, 3, lengthBytes(B))
      ) ...</k>
    requires lengthBytes(B) >Int 2
     andBool #scriptByte(B) ==Int 77

  // OP_PUSHDATA4 (0x4e = 78): next 4 bytes (LE) are length, then data
  rule <k> #decode1(B) =>
      #decodePush(
        78,
        Bytes2Int(substrBytes(B, 1, 5), LE, Unsigned),
        substrBytes(B, 5, lengthBytes(B))
      ) ...</k>
    requires lengthBytes(B) >Int 4
     andBool #scriptByte(B) ==Int 78

  // OP_1NEGATE (0x4f = 79)
  rule <k> #decode1(B) => #guardExec(OP_1NEGATE) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 79

  // OP_1 through OP_16 (0x51 - 0x60)
  rule <k> #decode1(B) => #guardExec(OP_1)  ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 81
  rule <k> #decode1(B) => #guardExec(OP_2)  ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 82
  rule <k> #decode1(B) => #guardExec(OP_3)  ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 83
  rule <k> #decode1(B) => #guardExec(OP_4)  ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 84
  rule <k> #decode1(B) => #guardExec(OP_5)  ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 85
  rule <k> #decode1(B) => #guardExec(OP_6)  ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 86
  rule <k> #decode1(B) => #guardExec(OP_7)  ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 87
  rule <k> #decode1(B) => #guardExec(OP_8)  ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 88
  rule <k> #decode1(B) => #guardExec(OP_9)  ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 89
  rule <k> #decode1(B) => #guardExec(OP_10) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 90
  rule <k> #decode1(B) => #guardExec(OP_11) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 91
  rule <k> #decode1(B) => #guardExec(OP_12) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 92
  rule <k> #decode1(B) => #guardExec(OP_13) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 93
  rule <k> #decode1(B) => #guardExec(OP_14) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 94
  rule <k> #decode1(B) => #guardExec(OP_15) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 95
  rule <k> #decode1(B) => #guardExec(OP_16) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 96

  // OP_NOP (0x61 = 97)
  rule <k> #decode1(B) => #guardExec(OP_NOP) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 97

  // OP_IF (0x63 = 99)
  rule <k> #decode1(B) => OP_IF ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 99

  // OP_NOTIF (0x64 = 100)
  rule <k> #decode1(B) => OP_NOTIF ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 100

  // OP_ELSE (0x67 = 103)
  rule <k> #decode1(B) => OP_ELSE ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 103

  // OP_ENDIF (0x68 = 104)
  rule <k> #decode1(B) => OP_ENDIF ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 104

  // OP_VERIFY (0x69 = 105)
  rule <k> #decode1(B) => #guardExec(OP_VERIFY) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 105

  // OP_RETURN (0x6a = 106)
  rule <k> #decode1(B) => #guardExec(OP_RETURN) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 106

  // OP_TOALTSTACK (0x6b = 107)
  rule <k> #decode1(B) => #guardExec(OP_TOALTSTACK) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 107

  // OP_FROMALTSTACK (0x6c = 108)
  rule <k> #decode1(B) => #guardExec(OP_FROMALTSTACK) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 108

  // OP_2DROP (0x6d = 109)
  rule <k> #decode1(B) => #guardExec(OP_2DROP) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 109

  // OP_2DUP (0x6e = 110)
  rule <k> #decode1(B) => #guardExec(OP_2DUP) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 110

  // OP_3DUP (0x6f = 111)
  rule <k> #decode1(B) => #guardExec(OP_3DUP) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 111

  // OP_2OVER (0x70 = 112)
  rule <k> #decode1(B) => #guardExec(OP_2OVER) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 112

  // OP_2ROT (0x71 = 113)
  rule <k> #decode1(B) => #guardExec(OP_2ROT) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 113

  // OP_2SWAP (0x72 = 114)
  rule <k> #decode1(B) => #guardExec(OP_2SWAP) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 114

  // OP_IFDUP (0x73 = 115)
  rule <k> #decode1(B) => #guardExec(OP_IFDUP) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 115

  // OP_DEPTH (0x74 = 116)
  rule <k> #decode1(B) => #guardExec(OP_DEPTH) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 116

  // OP_DROP (0x75 = 117)
  rule <k> #decode1(B) => #guardExec(OP_DROP) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 117

  // OP_DUP (0x76 = 118)
  rule <k> #decode1(B) => #guardExec(OP_DUP) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 118

  // OP_NIP (0x77 = 119)
  rule <k> #decode1(B) => #guardExec(OP_NIP) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 119

  // OP_OVER (0x78 = 120)
  rule <k> #decode1(B) => #guardExec(OP_OVER) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 120

  // OP_PICK (0x79 = 121)
  rule <k> #decode1(B) => #guardExec(OP_PICK) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 121

  // OP_ROLL (0x7a = 122)
  rule <k> #decode1(B) => #guardExec(OP_ROLL) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 122

  // OP_ROT (0x7b = 123)
  rule <k> #decode1(B) => #guardExec(OP_ROT) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 123

  // OP_SWAP (0x7c = 124)
  rule <k> #decode1(B) => #guardExec(OP_SWAP) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 124

  // OP_TUCK (0x7d = 125)
  rule <k> #decode1(B) => #guardExec(OP_TUCK) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 125

  // OP_SIZE (0x82 = 130)
  rule <k> #decode1(B) => #guardExec(OP_SIZE) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 130

  // OP_EQUAL (0x87 = 135)
  rule <k> #decode1(B) => #guardExec(OP_EQUAL) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 135

  // OP_EQUALVERIFY (0x88 = 136)
  rule <k> #decode1(B) => #guardExec(OP_EQUALVERIFY) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 136

  // OP_1ADD (0x8b = 139)
  rule <k> #decode1(B) => #guardExec(OP_1ADD) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 139

  // OP_1SUB (0x8c = 140)
  rule <k> #decode1(B) => #guardExec(OP_1SUB) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 140

  // OP_NEGATE (0x8f = 143)
  rule <k> #decode1(B) => #guardExec(OP_NEGATE) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 143

  // OP_ABS (0x90 = 144)
  rule <k> #decode1(B) => #guardExec(OP_ABS) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 144

  // OP_NOT (0x91 = 145)
  rule <k> #decode1(B) => #guardExec(OP_NOT) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 145

  // OP_0NOTEQUAL (0x92 = 146)
  rule <k> #decode1(B) => #guardExec(OP_0NOTEQUAL) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 146

  // OP_ADD (0x93 = 147)
  rule <k> #decode1(B) => #guardExec(OP_ADD) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 147

  // OP_SUB (0x94 = 148)
  rule <k> #decode1(B) => #guardExec(OP_SUB) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 148

  // OP_BOOLAND (0x9a = 154)
  rule <k> #decode1(B) => #guardExec(OP_BOOLAND) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 154

  // OP_BOOLOR (0x9b = 155)
  rule <k> #decode1(B) => #guardExec(OP_BOOLOR) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 155

  // OP_NUMEQUAL (0x9c = 156)
  rule <k> #decode1(B) => #guardExec(OP_NUMEQUAL) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 156

  // OP_NUMEQUALVERIFY (0x9d = 157)
  rule <k> #decode1(B) => #guardExec(OP_NUMEQUALVERIFY) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 157

  // OP_NUMNOTEQUAL (0x9e = 158)
  rule <k> #decode1(B) => #guardExec(OP_NUMNOTEQUAL) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 158

  // OP_LESSTHAN (0x9f = 159)
  rule <k> #decode1(B) => #guardExec(OP_LESSTHAN) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 159

  // OP_GREATERTHAN (0xa0 = 160)
  rule <k> #decode1(B) => #guardExec(OP_GREATERTHAN) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 160

  // OP_LESSTHANOREQUAL (0xa1 = 161)
  rule <k> #decode1(B) => #guardExec(OP_LESSTHANOREQUAL) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 161

  // OP_GREATERTHANOREQUAL (0xa2 = 162)
  rule <k> #decode1(B) => #guardExec(OP_GREATERTHANOREQUAL) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 162

  // OP_MIN (0xa3 = 163)
  rule <k> #decode1(B) => #guardExec(OP_MIN) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 163

  // OP_MAX (0xa4 = 164)
  rule <k> #decode1(B) => #guardExec(OP_MAX) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 164

  // OP_WITHIN (0xa5 = 165)
  rule <k> #decode1(B) => #guardExec(OP_WITHIN) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 165

  // OP_RIPEMD160 (0xa6 = 166)
  rule <k> #decode1(B) => #guardExec(OP_RIPEMD160) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 166

  // OP_SHA1 (0xa7 = 167)
  rule <k> #decode1(B) => #guardExec(OP_SHA1) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 167

  // OP_SHA256 (0xa8 = 168)
  rule <k> #decode1(B) => #guardExec(OP_SHA256) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 168

  // OP_HASH160 (0xa9 = 169)
  rule <k> #decode1(B) => #guardExec(OP_HASH160) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 169

  // OP_HASH256 (0xaa = 170)
  rule <k> #decode1(B) => #guardExec(OP_HASH256) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 170

  // OP_CODESEPARATOR (0xab = 171)
  rule <k> #decode1(B) => #guardExec(OP_CODESEPARATOR) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 171

  // OP_CHECKSIG (0xac = 172)
  rule <k> #decode1(B) => #guardExec(OP_CHECKSIG) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 172

  // OP_CHECKSIGVERIFY (0xad = 173)
  rule <k> #decode1(B) => #guardExec(OP_CHECKSIGVERIFY) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 173

  // OP_CHECKMULTISIG (0xae = 174)
  rule <k> #decode1(B) => #guardExec(OP_CHECKMULTISIG) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 174

  // OP_CHECKMULTISIGVERIFY (0xaf = 175)
  rule <k> #decode1(B) => #guardExec(OP_CHECKMULTISIGVERIFY) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 175

  // OP_NOP1 (0xb0 = 176)
  rule <k> #decode1(B) => #guardExec(OP_NOP1) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 176

  // OP_NOP2 / OP_CHECKLOCKTIMEVERIFY (0xb1 = 177)
  rule <k> #decode1(B) => #guardExec(OP_NOP2) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 177

  // OP_NOP3 / OP_CHECKSEQUENCEVERIFY (0xb2 = 178)
  rule <k> #decode1(B) => #guardExec(OP_NOP3) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 178

  // OP_NOP4 (0xb3 = 179)
  rule <k> #decode1(B) => #guardExec(OP_NOP4) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 179

  // OP_NOP5 (0xb4 = 180)
  rule <k> #decode1(B) => #guardExec(OP_NOP5) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 180

  // OP_NOP6 (0xb5 = 181)
  rule <k> #decode1(B) => #guardExec(OP_NOP6) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 181

  // OP_NOP7 (0xb6 = 182)
  rule <k> #decode1(B) => #guardExec(OP_NOP7) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 182

  // OP_NOP8 (0xb7 = 183)
  rule <k> #decode1(B) => #guardExec(OP_NOP8) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 183

  // OP_NOP9 (0xb8 = 184)
  rule <k> #decode1(B) => #guardExec(OP_NOP9) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 184

  // OP_NOP10 (0xb9 = 185)
  rule <k> #decode1(B) => #guardExec(OP_NOP10) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 185

  // OP_RESERVED_OP: reserved opcodes that fail when executed but are OK in dead branches
  // In tapscript (witness-v1), 0x50 and 0x62 are OP_SUCCESSx (BIP 342)
  // 0x50 (80) = OP_RESERVED — OP_SUCCESS in tapscript
  rule <k> #decode1(B) => #opSuccess ...</k>
       <phase> witness-v1 </phase>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 80
  rule <k> #decode1(B) => #guardExec(OP_RESERVED_OP) ~> #decodeScript(#scriptTail(B)) ...</k>
       <phase> PH </phase>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 80
     andBool PH =/=K witness-v1
  // 0x62 (98) = OP_VER — OP_SUCCESS in tapscript
  rule <k> #decode1(B) => #opSuccess ...</k>
       <phase> witness-v1 </phase>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 98
  rule <k> #decode1(B) => #guardExec(OP_RESERVED_OP) ~> #decodeScript(#scriptTail(B)) ...</k>
       <phase> PH </phase>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 98
     andBool PH =/=K witness-v1
  // 0x89 (137) = OP_RESERVED1
  rule <k> #decode1(B) => #guardExec(OP_RESERVED_OP) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 137
  // 0x8a (138) = OP_RESERVED2
  rule <k> #decode1(B) => #guardExec(OP_RESERVED_OP) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 138

  // OP_INVALIDOPCODE: opcodes that always fail (even in dead branches)
  // 0x65 (101) = OP_VERIF
  rule <k> #decode1(B) => OP_INVALIDOPCODE ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 101
  // 0x66 (102) = OP_VERNOTIF
  rule <k> #decode1(B) => OP_INVALIDOPCODE ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 102

  // Disabled opcodes: always fail even in dead branches (non-tapscript)
  // In tapscript (witness-v1), these are OP_SUCCESSx (BIP 342)

  // 0x7e (126) = OP_CAT, 0x7f (127) = OP_SUBSTR
  rule <k> #decode1(B) => #opSuccess ...</k>
       <phase> witness-v1 </phase>
    requires lengthBytes(B) >Int 0
     andBool #scriptByte(B) >=Int 126 andBool #scriptByte(B) <=Int 127
  rule <k> #decode1(B) => OP_INVALIDOPCODE ~> #decodeScript(#scriptTail(B)) ...</k>
       <phase> PH </phase>
    requires lengthBytes(B) >Int 0
     andBool #scriptByte(B) >=Int 126 andBool #scriptByte(B) <=Int 127
     andBool PH =/=K witness-v1

  // 0x80 (128) = OP_LEFT, 0x81 (129) = OP_RIGHT
  rule <k> #decode1(B) => #opSuccess ...</k>
       <phase> witness-v1 </phase>
    requires lengthBytes(B) >Int 0
     andBool #scriptByte(B) >=Int 128 andBool #scriptByte(B) <=Int 129
  rule <k> #decode1(B) => OP_INVALIDOPCODE ~> #decodeScript(#scriptTail(B)) ...</k>
       <phase> PH </phase>
    requires lengthBytes(B) >Int 0
     andBool #scriptByte(B) >=Int 128 andBool #scriptByte(B) <=Int 129
     andBool PH =/=K witness-v1

  // 0x83 (131) = OP_INVERT, 0x84 (132) = OP_AND, 0x85 (133) = OP_OR, 0x86 (134) = OP_XOR
  rule <k> #decode1(B) => #opSuccess ...</k>
       <phase> witness-v1 </phase>
    requires lengthBytes(B) >Int 0
     andBool #scriptByte(B) >=Int 131 andBool #scriptByte(B) <=Int 134
  rule <k> #decode1(B) => OP_INVALIDOPCODE ~> #decodeScript(#scriptTail(B)) ...</k>
       <phase> PH </phase>
    requires lengthBytes(B) >Int 0
     andBool #scriptByte(B) >=Int 131 andBool #scriptByte(B) <=Int 134
     andBool PH =/=K witness-v1

  // 0x8d (141) = OP_2MUL, 0x8e (142) = OP_2DIV
  rule <k> #decode1(B) => #opSuccess ...</k>
       <phase> witness-v1 </phase>
    requires lengthBytes(B) >Int 0
     andBool #scriptByte(B) >=Int 141 andBool #scriptByte(B) <=Int 142
  rule <k> #decode1(B) => OP_INVALIDOPCODE ~> #decodeScript(#scriptTail(B)) ...</k>
       <phase> PH </phase>
    requires lengthBytes(B) >Int 0
     andBool #scriptByte(B) >=Int 141 andBool #scriptByte(B) <=Int 142
     andBool PH =/=K witness-v1

  // 0x95 (149) = OP_MUL, 0x96 (150) = OP_DIV, 0x97 (151) = OP_MOD
  // 0x98 (152) = OP_LSHIFT, 0x99 (153) = OP_RSHIFT
  rule <k> #decode1(B) => #opSuccess ...</k>
       <phase> witness-v1 </phase>
    requires lengthBytes(B) >Int 0
     andBool #scriptByte(B) >=Int 149 andBool #scriptByte(B) <=Int 153
  rule <k> #decode1(B) => OP_INVALIDOPCODE ~> #decodeScript(#scriptTail(B)) ...</k>
       <phase> PH </phase>
    requires lengthBytes(B) >Int 0
     andBool #scriptByte(B) >=Int 149 andBool #scriptByte(B) <=Int 153
     andBool PH =/=K witness-v1

  // OP_CHECKSIGADD (0xba = 186) — real opcode in tapscript (BIP 342)
  // In non-tapscript contexts, 0xba is an undefined opcode (fails when executed)
  rule <k> #decode1(B) => #guardExec(OP_CHECKSIGADD) ~> #decodeScript(#scriptTail(B)) ...</k>
       <phase> witness-v1 </phase>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 186
  rule <k> #decode1(B) => #guardExec(OP_RESERVED_OP) ~> #decodeScript(#scriptTail(B)) ...</k>
       <phase> PH </phase>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 186
     andBool PH =/=K witness-v1

  // Undefined opcodes: 0xbb-0xfe (187-254)
  // In tapscript (witness-v1): OP_SUCCESSx (BIP 342)
  // In non-tapscript: reserved (fail when executed, OK in dead branches)
  rule <k> #decode1(B) => #opSuccess ...</k>
       <phase> witness-v1 </phase>
    requires lengthBytes(B) >Int 0
     andBool #scriptByte(B) >=Int 187 andBool #scriptByte(B) <=Int 254
  rule <k> #decode1(B) => #guardExec(OP_RESERVED_OP) ~> #decodeScript(#scriptTail(B)) ...</k>
       <phase> PH </phase>
    requires lengthBytes(B) >Int 0
     andBool #scriptByte(B) >=Int 187 andBool #scriptByte(B) <=Int 254
     andBool PH =/=K witness-v1

  // 0xff (255) = OP_INVALIDOPCODE — fails when executed, OK in dead branches
  rule <k> #decode1(B) => #guardExec(OP_RESERVED_OP) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 255


endmodule
