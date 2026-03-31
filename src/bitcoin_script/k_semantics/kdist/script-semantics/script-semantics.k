requires "plugin/krypto.md"
requires "script-syntax.k"
requires "script-num.k"
requires "script-crypto.k"

// Core Bitcoin Script semantics: configuration + all opcode rules.
// All input is hex-based via config variables $SCRIPTSIG and $SCRIPTPUBKEY.
module SCRIPT-SEMANTICS
  imports SCRIPT-SYNTAX
  imports SCRIPT-NUM
  imports SCRIPT-CRYPTO
  imports KRYPTO
  imports INT
  imports STRING
  imports BOOL
  imports K-EQUAL
  imports LIST
  imports BYTES

  // --- Phase sort ---
  syntax Phase ::= "scriptSig" | "scriptPubKey" | "p2sh-redeem" | "done"

  // --- Configuration ---
  configuration
    <T>
      <k> #init </k>
      <stack> .List </stack>
      <altstack> .List </altstack>
      <exec> .List </exec>
      <phase> scriptSig </phase>
      <error> "" </error>
      <sighash> $SIGHASH:Bytes </sighash>
      <timestamp> $TIMESTAMP:Int </timestamp>
      <scriptSigBytes> $SCRIPTSIG:Bytes </scriptSigBytes>
      <scriptPubKeyBytes> $SCRIPTPUBKEY:Bytes </scriptPubKeyBytes>
      <witness> $WITNESS:Bytes </witness>
      <savedStack> .List </savedStack>
      <opCount> 0 </opCount>
    </T>

  // --- Error mechanism ---
  // #fail(code) sets the error cell and halts execution by clearing the k cell.
  syntax KItem ::= "#fail" "(" String ")"
  rule <k> #fail(ERR) ~> _:K => .K </k>
       <error> _ => ERR </error>

  // =========================================================================
  // Initialization: start executing scriptSig (or skip to scriptPubKey)
  // =========================================================================

  syntax KItem ::= "#init"
                 | "#phaseComplete"

  // scriptSig is non-empty: decode and execute it (max 10000 bytes)
  rule <k> #init => #decodeScript(SIG) ~> #phaseComplete ...</k>
       <scriptSigBytes> SIG </scriptSigBytes>
    requires lengthBytes(SIG) >Int 0
     andBool lengthBytes(SIG) <=Int 10000

  rule <k> #init => #fail("SCRIPT_SIZE") ...</k>
       <scriptSigBytes> SIG </scriptSigBytes>
    requires lengthBytes(SIG) >Int 10000

  // scriptSig is empty: skip straight to scriptPubKey
  rule <k> #init => #decodeScript(PK) ~> #phaseComplete ...</k>
       <scriptSigBytes> SIG </scriptSigBytes>
       <scriptPubKeyBytes> PK </scriptPubKeyBytes>
       <phase> _ => scriptPubKey </phase>
    requires lengthBytes(SIG) ==Int 0
     andBool lengthBytes(PK) <=Int 10000

  rule <k> #init => #fail("SCRIPT_SIZE") ...</k>
       <scriptSigBytes> SIG </scriptSigBytes>
       <scriptPubKeyBytes> PK </scriptPubKeyBytes>
    requires lengthBytes(SIG) ==Int 0
     andBool lengthBytes(PK) >Int 10000

  // =========================================================================
  // Phase transitions
  // =========================================================================

  // After scriptSig completes: save stack if P2SH, then run scriptPubKey
  // Altstack is cleared between phases; exec stack must be empty (balanced IF/ENDIF)
  rule <k> #phaseComplete => #decodeScript(PK) ~> #phaseComplete ...</k>
       <phase> scriptSig => scriptPubKey </phase>
       <scriptPubKeyBytes> PK </scriptPubKeyBytes>
       <stack> ST </stack>
       <savedStack> _ => ST </savedStack>
       <altstack> _ => .List </altstack>
       <exec> .List </exec>
       <opCount> _ => 0 </opCount>
       <timestamp> TS </timestamp>
    requires #isP2SH(PK) andBool TS >=Int 1333238400
     andBool lengthBytes(PK) <=Int 10000

  rule <k> #phaseComplete => #decodeScript(PK) ~> #phaseComplete ...</k>
       <phase> scriptSig => scriptPubKey </phase>
       <scriptPubKeyBytes> PK </scriptPubKeyBytes>
       <altstack> _ => .List </altstack>
       <exec> .List </exec>
       <opCount> _ => 0 </opCount>
       <timestamp> TS </timestamp>
    requires (notBool #isP2SH(PK) orBool TS <Int 1333238400)
     andBool lengthBytes(PK) <=Int 10000

  // After scriptPubKey completes, NOT P2SH: done
  // Exec stack must be empty (balanced IF/ENDIF)
  rule <k> #phaseComplete => .K ...</k>
       <phase> scriptPubKey => done </phase>
       <exec> .List </exec>
       <scriptPubKeyBytes> PK </scriptPubKeyBytes>
       <timestamp> TS </timestamp>
    requires notBool #isP2SH(PK) orBool TS <Int 1333238400

  // After scriptPubKey completes, IS P2SH, scriptPubKey succeeded:
  // restore saved stack, pop redeem script, decode and execute it
  rule <k> #phaseComplete => #decodeScript(REDEEM) ~> #phaseComplete ...</k>
       <phase> scriptPubKey => p2sh-redeem </phase>
       <exec> .List </exec>
       <opCount> _ => 0 </opCount>
       <scriptPubKeyBytes> PK </scriptPubKeyBytes>
       <timestamp> TS </timestamp>
       <stack> ListItem(V:Bytes) _ => REST </stack>
       <savedStack> ListItem(REDEEM:Bytes) REST </savedStack>
       <scriptSigBytes> SIG </scriptSigBytes>
    requires #isP2SH(PK) andBool TS >=Int 1333238400
     andBool #isPushOnly(SIG)
     andBool #isTruthy(V)
     andBool lengthBytes(REDEEM) <=Int 10000

  // After scriptPubKey completes, IS P2SH, but scriptPubKey FAILED (stack top falsy):
  // do not execute redeem script, just finish
  rule <k> #phaseComplete => .K ...</k>
       <phase> scriptPubKey => done </phase>
       <exec> .List </exec>
       <stack> ListItem(V:Bytes) _ </stack>
       <scriptPubKeyBytes> PK </scriptPubKeyBytes>
       <timestamp> TS </timestamp>
       <scriptSigBytes> SIG </scriptSigBytes>
    requires #isP2SH(PK) andBool TS >=Int 1333238400
     andBool #isPushOnly(SIG)
     andBool notBool #isTruthy(V)

  // After p2sh-redeem completes: done
  rule <k> #phaseComplete => .K ...</k>
       <phase> p2sh-redeem => done </phase>
       <exec> .List </exec>

  // =========================================================================
  // P2SH detection and push-only check
  // =========================================================================

  syntax Bool ::= #isP2SH(Bytes) [function]
  // P2SH: exactly 23 bytes: OP_HASH160 (0xa9) PUSHBYTES_20 (0x14) <20 bytes> OP_EQUAL (0x87)
  rule #isP2SH(B) => true
    requires lengthBytes(B) ==Int 23
     andBool Bytes2Int(substrBytes(B, 0, 1), BE, Unsigned) ==Int 169
     andBool Bytes2Int(substrBytes(B, 1, 2), BE, Unsigned) ==Int 20
     andBool Bytes2Int(substrBytes(B, 22, 23), BE, Unsigned) ==Int 135
  rule #isP2SH(_) => false [owise]

  syntax Bool ::= #isPushOnly(Bytes) [function]
  // Every opcode must be a push: 0x00-0x4e (data pushes), 0x51-0x60 (OP_1..OP_16), 0x4f (OP_1NEGATE)
  rule #isPushOnly(B) => true
    requires lengthBytes(B) ==Int 0

  // PUSHBYTES_1 through PUSHBYTES_75: skip 1 + N bytes
  rule #isPushOnly(B) => #isPushOnly(substrBytes(B, 1 +Int #scriptByte(B), lengthBytes(B)))
    requires lengthBytes(B) >Int 0
     andBool #scriptByte(B) >=Int 1
     andBool #scriptByte(B) <=Int 75
     andBool lengthBytes(B) >Int #scriptByte(B)

  // PUSHDATA1 (0x4c = 76): skip 1 (opcode) + 1 (length byte) + N (data)
  rule #isPushOnly(B) => #isPushOnly(substrBytes(B, 2 +Int Bytes2Int(substrBytes(B, 1, 2), BE, Unsigned), lengthBytes(B)))
    requires lengthBytes(B) >Int 1
     andBool #scriptByte(B) ==Int 76
     andBool lengthBytes(B) >=Int 2 +Int Bytes2Int(substrBytes(B, 1, 2), BE, Unsigned)

  // PUSHDATA2 (0x4d = 77): skip 1 + 2 (LE length) + N
  rule #isPushOnly(B) => #isPushOnly(substrBytes(B, 3 +Int Bytes2Int(substrBytes(B, 1, 3), LE, Unsigned), lengthBytes(B)))
    requires lengthBytes(B) >Int 2
     andBool #scriptByte(B) ==Int 77
     andBool lengthBytes(B) >=Int 3 +Int Bytes2Int(substrBytes(B, 1, 3), LE, Unsigned)

  // PUSHDATA4 (0x4e = 78): skip 1 + 4 (LE length) + N
  rule #isPushOnly(B) => #isPushOnly(substrBytes(B, 5 +Int Bytes2Int(substrBytes(B, 1, 5), LE, Unsigned), lengthBytes(B)))
    requires lengthBytes(B) >Int 4
     andBool #scriptByte(B) ==Int 78
     andBool lengthBytes(B) >=Int 5 +Int Bytes2Int(substrBytes(B, 1, 5), LE, Unsigned)

  // OP_0, OP_1NEGATE, OP_1..OP_16
  rule #isPushOnly(B) => #isPushOnly(#scriptTail(B))
    requires lengthBytes(B) >Int 0
     andBool ( #scriptByte(B) ==Int 0
        orBool ( #scriptByte(B) >=Int 79 andBool #scriptByte(B) <=Int 96 ) )

  rule #isPushOnly(_) => false [owise]

  // =========================================================================
  // Hex script decoding: HexPgm -> Bytes -> opcodes
  // =========================================================================

  // Strip "0x" prefix, convert hex string to bytes, decode
  rule <k> H:HexPgm => #decodeScript(hexStringToBytes(substrString(HexPgm2String(H), 2, lengthString(HexPgm2String(H))))) ...</k>

  // --- Decode helpers ---
  syntax Int ::= #scriptByte(Bytes) [function]
  rule #scriptByte(B) => Bytes2Int(substrBytes(B, 0, 1), BE, Unsigned)

  syntax Bytes ::= #scriptTail(Bytes) [function]
  rule #scriptTail(B) => substrBytes(B, 1, lengthBytes(B))

  // --- Resource limits ---
  // MAX_OPS_PER_SCRIPT = 201, MAX_SCRIPT_ELEMENT_SIZE = 520, MAX_SCRIPT_SIZE = 10000

  // Count one opcode (for opcodes > OP_16, byte > 96). Fails if > 201.
  syntax KItem ::= "#countOp"
                 | "#countOps" "(" Int ")"

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

  // --- Decode entry point ---
  // #decodeScript dispatches to #decode1, counting opcodes > OP_16 (byte > 96).
  syntax KItem ::= "#decodeScript" "(" Bytes ")"
                 | "#decode1" "(" Bytes ")"
                 | "#decodePush" "(" Int "," Bytes ")"

  // Empty script — done
  rule <k> #decodeScript(B) => .K ...</k>
    requires lengthBytes(B) ==Int 0

  // Opcode > OP_16 (byte > 96): count before decoding
  rule <k> #decodeScript(B) => #countOp ~> #decode1(B) ...</k>
    requires lengthBytes(B) >Int 0
     andBool #scriptByte(B) >Int 96

  // Opcode <= OP_16 (byte <= 96): decode without counting
  rule <k> #decodeScript(B) => #decode1(B) ...</k>
    requires lengthBytes(B) >Int 0
     andBool #scriptByte(B) <=Int 96

  // OP_0 (0x00)
  rule <k> #decode1(B) => #guardExec(OP_0) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0
     andBool #scriptByte(B) ==Int 0

  // OP_PUSHBYTES_1 through OP_PUSHBYTES_75 (0x01 - 0x4b)
  // Extracts N bytes and pushes them directly onto the stack
  rule <k> #decode1(B) => #decodePush(#scriptByte(B), #scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0
     andBool #scriptByte(B) >=Int 1
     andBool #scriptByte(B) <=Int 75

  rule <k> #decodePush(N, B) => #guardExec(OP_PUSHDATA(substrBytes(B, 0, N)))
        ~> #decodeScript(substrBytes(B, N, lengthBytes(B))) ...</k>
    requires lengthBytes(B) >=Int N
     andBool N <=Int 520

  rule <k> #decodePush(N, _) => #fail("PUSH_SIZE") ...</k>
    requires N >Int 520

  // OP_PUSHDATA1 (0x4c = 76): next byte is length, then that many bytes of data
  rule <k> #decode1(B) =>
      #decodePush(
        Bytes2Int(substrBytes(B, 1, 2), BE, Unsigned),
        substrBytes(B, 2, lengthBytes(B))
      ) ...</k>
    requires lengthBytes(B) >Int 1
     andBool #scriptByte(B) ==Int 76

  // OP_PUSHDATA2 (0x4d = 77): next 2 bytes (LE) are length, then data
  rule <k> #decode1(B) =>
      #decodePush(
        Bytes2Int(substrBytes(B, 1, 3), LE, Unsigned),
        substrBytes(B, 3, lengthBytes(B))
      ) ...</k>
    requires lengthBytes(B) >Int 2
     andBool #scriptByte(B) ==Int 77

  // OP_PUSHDATA4 (0x4e = 78): next 4 bytes (LE) are length, then data
  rule <k> #decode1(B) =>
      #decodePush(
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
  // 0x50 (80) = OP_RESERVED
  rule <k> #decode1(B) => #guardExec(OP_RESERVED_OP) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 80
  // 0x62 (98) = OP_VER
  rule <k> #decode1(B) => #guardExec(OP_RESERVED_OP) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) ==Int 98
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

  // Disabled opcodes: always fail even in dead branches
  // 0x7e (126) = OP_CAT, 0x7f (127) = OP_SUBSTR
  rule <k> #decode1(B) => OP_INVALIDOPCODE ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0
     andBool #scriptByte(B) >=Int 126 andBool #scriptByte(B) <=Int 127
  // 0x80 (128) = OP_LEFT, 0x81 (129) = OP_RIGHT
  rule <k> #decode1(B) => OP_INVALIDOPCODE ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0
     andBool #scriptByte(B) >=Int 128 andBool #scriptByte(B) <=Int 129
  // 0x83 (131) = OP_INVERT, 0x84 (132) = OP_AND, 0x85 (133) = OP_OR, 0x86 (134) = OP_XOR
  rule <k> #decode1(B) => OP_INVALIDOPCODE ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0
     andBool #scriptByte(B) >=Int 131 andBool #scriptByte(B) <=Int 134
  // 0x8d (141) = OP_2MUL, 0x8e (142) = OP_2DIV
  rule <k> #decode1(B) => OP_INVALIDOPCODE ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0
     andBool #scriptByte(B) >=Int 141 andBool #scriptByte(B) <=Int 142
  // 0x95 (149) = OP_MUL, 0x96 (150) = OP_DIV, 0x97 (151) = OP_MOD
  // 0x98 (152) = OP_LSHIFT, 0x99 (153) = OP_RSHIFT
  rule <k> #decode1(B) => OP_INVALIDOPCODE ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0
     andBool #scriptByte(B) >=Int 149 andBool #scriptByte(B) <=Int 153

  // Undefined opcodes: 0xba-0xff (186-255) — fail when executed, OK in dead branches
  rule <k> #decode1(B) => #guardExec(OP_RESERVED_OP) ~> #decodeScript(#scriptTail(B)) ...</k>
    requires lengthBytes(B) >Int 0 andBool #scriptByte(B) >=Int 186

  // =========================================================================
  // OP_PUSHDATA: push raw bytes onto the stack (emitted by decoder for data pushes)
  // =========================================================================

  rule <k> OP_PUSHDATA(D) => .K ...</k>
       <stack> ST => ListItem(D) ST </stack>

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
  // OP_1NEGATE: push -1 as CScriptNum
  // =========================================================================

  rule <k> OP_1NEGATE => .K ...</k>
       <stack> ST => ListItem(intToScriptNum(-1)) ST </stack>

  // =========================================================================
  // OP_NOP: do nothing
  // =========================================================================

  rule <k> OP_NOP => .K ...</k>

  // OP_NOP1-NOP10: all no-ops (NOP2/NOP3 = CLTV/CSV, treated as NOP pre-softfork)
  rule <k> OP_NOP1  => .K ...</k>
  rule <k> OP_NOP2  => .K ...</k>
  rule <k> OP_NOP3  => .K ...</k>
  rule <k> OP_NOP4  => .K ...</k>
  rule <k> OP_NOP5  => .K ...</k>
  rule <k> OP_NOP6  => .K ...</k>
  rule <k> OP_NOP7  => .K ...</k>
  rule <k> OP_NOP8  => .K ...</k>
  rule <k> OP_NOP9  => .K ...</k>
  rule <k> OP_NOP10 => .K ...</k>

  // =========================================================================
  // OP_VERIFY: pop top, continue if truthy, get stuck if falsy
  // =========================================================================

  rule <k> OP_VERIFY => .K ...</k>
       <stack> ListItem(V:Bytes) ST => ST </stack>
    requires #isTruthy(V)

  rule <k> OP_VERIFY => #fail("VERIFY") ...</k>
       <stack> ListItem(V:Bytes) ST => ST </stack>
    requires notBool #isTruthy(V)

  // =========================================================================
  // OP_RETURN: immediately fail
  // =========================================================================

  rule <k> OP_RETURN => #fail("OP_RETURN") ...</k>

  // =========================================================================
  // OP_RESERVED_OP: reserved opcodes fail when executed (OK in dead branches)
  // =========================================================================

  rule <k> OP_RESERVED_OP => #fail("BAD_OPCODE") ...</k>

  // =========================================================================
  // OP_INVALIDOPCODE: disabled/undefined opcodes always fail
  // =========================================================================
  // Emitted directly by decoder (not via #guardExec) — fires even in dead branches.

  rule <k> OP_INVALIDOPCODE => #fail("DISABLED_OPCODE") ...</k>

  // =========================================================================
  // IF/ELSE/ENDIF conditional execution
  // =========================================================================
  // The <exec> cell holds a list of booleans tracking nested IF state.
  // Execution proceeds only when all entries are true (#allTrue).

  syntax Bool ::= #allTrue(List) [function]
  rule #allTrue(.List) => true
  rule #allTrue(ListItem(true) REST) => #allTrue(REST)
  rule #allTrue(ListItem(false) _) => false

  // =========================================================================
  // #guardExec: centralized execution guard
  // =========================================================================
  // All non-flow-control opcodes are wrapped in #guardExec by the decoder.
  // When executing (#allTrue), unwrap to the opcode; when skipping, discard.

  syntax KItem ::= "#guardExec" "(" OpCode ")"

  rule <k> #guardExec(OP) => OP ...</k>
       <exec> EX </exec>
    requires #allTrue(EX)

  rule <k> #guardExec(_) => .K ...</k>
       <exec> EX </exec>
    requires notBool #allTrue(EX)

  // --- When currently executing (#allTrue(<exec>) is true) ---

  // OP_IF: pop top, push #isTruthy(top) onto <exec>
  rule <k> OP_IF => .K ...</k>
       <stack> ListItem(V:Bytes) ST => ST </stack>
       <exec> EX => ListItem(#isTruthy(V)) EX </exec>
    requires #allTrue(EX)

  // OP_NOTIF: pop top, push negation onto <exec>
  rule <k> OP_NOTIF => .K ...</k>
       <stack> ListItem(V:Bytes) ST => ST </stack>
       <exec> EX => ListItem(notBool #isTruthy(V)) EX </exec>
    requires #allTrue(EX)

  // --- When NOT currently executing ---

  // OP_IF/OP_NOTIF in non-executing context: push false to track nesting
  rule <k> OP_IF => .K ...</k>
       <exec> EX => ListItem(false) EX </exec>
    requires notBool #allTrue(EX)

  rule <k> OP_NOTIF => .K ...</k>
       <exec> EX => ListItem(false) EX </exec>
    requires notBool #allTrue(EX)

  // --- OP_ELSE: always fires ---
  // If the rest of <exec> is all-true, toggle top; otherwise keep false
  rule <k> OP_ELSE => .K ...</k>
       <exec> ListItem(true) REST => ListItem(false) REST </exec>
    requires #allTrue(REST)

  rule <k> OP_ELSE => .K ...</k>
       <exec> ListItem(false) REST => ListItem(true) REST </exec>
    requires #allTrue(REST)

  // OP_ELSE in deeply nested non-executing block: don't toggle
  rule <k> OP_ELSE => .K ...</k>
       <exec> ListItem(_) REST => ListItem(false) REST </exec>
    requires notBool #allTrue(REST)

  // --- OP_ENDIF: always fires ---
  rule <k> OP_ENDIF => .K ...</k>
       <exec> ListItem(_) REST => REST </exec>

  // =========================================================================
  // #isTruthy: Bitcoin truthiness check
  // =========================================================================

  syntax Bool ::= #isTruthy(Bytes) [function]
  // Truthy: non-empty, not all-zero, not negative-zero (0x80)
  rule #isTruthy(B) => false
    requires lengthBytes(B) ==Int 0
  rule #isTruthy(B) => notBool #isZeroBytes(B, 0)
    requires lengthBytes(B) >Int 0

  syntax Bool ::= #isZeroBytes(Bytes, Int) [function]
  // Check if all bytes are zero (or the last byte is 0x80 = negative zero)
  rule #isZeroBytes(B, I) => true
    requires I ==Int lengthBytes(B)
  rule #isZeroBytes(B, I) => false
    requires I <Int lengthBytes(B)
     andBool I <Int lengthBytes(B) -Int 1
     andBool Bytes2Int(substrBytes(B, I, I +Int 1), BE, Unsigned) =/=Int 0
  rule #isZeroBytes(B, I) => #isZeroBytes(B, I +Int 1)
    requires I <Int lengthBytes(B)
     andBool I <Int lengthBytes(B) -Int 1
     andBool Bytes2Int(substrBytes(B, I, I +Int 1), BE, Unsigned) ==Int 0
  // Last byte: 0x00 or 0x80 (negative zero) both count as zero
  rule #isZeroBytes(B, I) => true
    requires I ==Int lengthBytes(B) -Int 1
     andBool ( Bytes2Int(substrBytes(B, I, I +Int 1), BE, Unsigned) ==Int 0
        orBool Bytes2Int(substrBytes(B, I, I +Int 1), BE, Unsigned) ==Int 128 )
  rule #isZeroBytes(B, I) => false
    requires I ==Int lengthBytes(B) -Int 1
     andBool Bytes2Int(substrBytes(B, I, I +Int 1), BE, Unsigned) =/=Int 0
     andBool Bytes2Int(substrBytes(B, I, I +Int 1), BE, Unsigned) =/=Int 128

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
    requires validNum(A) andBool validNum(B)

  // =========================================================================
  // OP_HASH160: RIPEMD160(SHA256(data))
  // =========================================================================

  rule <k> OP_HASH160 => .K ...</k>
       <stack> ListItem(V:Bytes) ST => ListItem(RipEmd160raw(Sha256raw(V))) ST </stack>

  // =========================================================================
  // OP_EQUAL: pop two byte values, push 1 if equal, 0 if not
  // =========================================================================

  // Equal: same value V matches both positions
  rule <k> OP_EQUAL => .K ...</k>
       <stack> ListItem(V:Bytes) ListItem(V:Bytes) ST
            => ListItem(intToScriptNum(1)) ST </stack>

  // Not equal: owise catches the case where A =/= B
  rule <k> OP_EQUAL => .K ...</k>
       <stack> ListItem(_:Bytes) ListItem(_:Bytes) ST
            => ListItem(intToScriptNum(0)) ST </stack>
    [owise]

  // =========================================================================
  // OP_EQUALVERIFY: pop two byte values, continue if equal, fail if not
  // =========================================================================

  rule <k> OP_EQUALVERIFY => .K ...</k>
       <stack> ListItem(V:Bytes) ListItem(V:Bytes) ST => ST </stack>

  rule <k> OP_EQUALVERIFY => #fail("EQUALVERIFY") ...</k>
       <stack> ListItem(A:Bytes) ListItem(B:Bytes) ST => ST </stack>
    requires A =/=K B

  // =========================================================================
  // OP_CHECKSIG (extracts hashtype from sig, looks up sighash in blob)
  // =========================================================================

  // Empty signature: always pushes false (no sighash lookup needed)
  rule <k> OP_CHECKSIG => .K ...</k>
       <stack> ListItem(_PK:Bytes) ListItem(SIG:Bytes) ST
            => ListItem(intToScriptNum(0)) ST </stack>
    requires lengthBytes(SIG) ==Int 0

  // Non-empty signature: extract hashtype, look up sighash, verify
  rule <k> OP_CHECKSIG => .K ...</k>
       <stack> ListItem(PK:Bytes) ListItem(SIG:Bytes) ST
            => ListItem(intToScriptNum(1)) ST </stack>
       <sighash> SIGHASHBLOB </sighash>
    requires lengthBytes(SIG) >Int 0
     andBool ecdsaVerify(PK, SIG, lookupSighash(SIGHASHBLOB, sigHashType(SIG)))

  rule <k> OP_CHECKSIG => .K ...</k>
       <stack> ListItem(PK:Bytes) ListItem(SIG:Bytes) ST
            => ListItem(intToScriptNum(0)) ST </stack>
       <sighash> SIGHASHBLOB </sighash>
    requires lengthBytes(SIG) >Int 0
     andBool notBool ecdsaVerify(PK, SIG, lookupSighash(SIGHASHBLOB, sigHashType(SIG)))
    [owise]

  // =========================================================================
  // OP_CHECKMULTISIG (reads sighash from <sighash> cell)
  // =========================================================================
  // Stack layout (top to bottom):
  //   N, pkN, ..., pk1, M, sigM, ..., sig1, dummy

  syntax KItem ::= "#collectPubKeys" "(" Int "," List ")"
                 | "#collectSigs" "(" Int "," List "," List ")"
                 | "#verifyMultisig" "(" List "," List ")"

  // Step 1: Pop N from stack (CScriptNum), begin collecting pubkeys
  // PUBKEY_COUNT: N must be in [0, 20]. Also count N ops for OP_COUNT limit.
  rule <k> OP_CHECKMULTISIG => #countOps(scriptNumToInt(N)) ~> #collectPubKeys(scriptNumToInt(N), .List) ...</k>
       <stack> ListItem(N:Bytes) ST => ST </stack>
    requires validNum(N)
     andBool scriptNumToInt(N) >=Int 0
     andBool scriptNumToInt(N) <=Int 20

  rule <k> OP_CHECKMULTISIG => #fail("PUBKEY_COUNT") ...</k>
       <stack> ListItem(N:Bytes) ST => ST </stack>
    requires validNum(N)
     andBool (scriptNumToInt(N) <Int 0 orBool scriptNumToInt(N) >Int 20)

  // Step 2a: Pop one pubkey, prepend to collected list
  rule <k> #collectPubKeys(N, PKs) => #collectPubKeys(N -Int 1, ListItem(PK) PKs) ...</k>
       <stack> ListItem(PK) ST => ST </stack>
    requires N >Int 0

  // Step 2b: All N pubkeys collected; pop M (CScriptNum) and begin collecting sigs
  // SIG_COUNT: M must be in [0, size(PKs)]
  rule <k> #collectPubKeys(0, PKs) => #collectSigs(scriptNumToInt(M), PKs, .List) ...</k>
       <stack> ListItem(M:Bytes) ST => ST </stack>
    requires validNum(M)
     andBool scriptNumToInt(M) >=Int 0
     andBool scriptNumToInt(M) <=Int size(PKs)

  rule <k> #collectPubKeys(0, PKs) => #fail("SIG_COUNT") ...</k>
       <stack> ListItem(M:Bytes) ST => ST </stack>
    requires validNum(M)
     andBool (scriptNumToInt(M) <Int 0 orBool scriptNumToInt(M) >Int size(PKs))

  // Step 3a: Pop one sig, prepend to collected list
  rule <k> #collectSigs(M, PKs, Sigs) => #collectSigs(M -Int 1, PKs, ListItem(SIG) Sigs) ...</k>
       <stack> ListItem(SIG) ST => ST </stack>
    requires M >Int 0

  // Step 3b: All M sigs collected; pop dummy element, begin verification
  rule <k> #collectSigs(0, PKs, Sigs) => #verifyMultisig(PKs, Sigs) ...</k>
       <stack> ListItem(_) ST => ST </stack>

  // Step 4a: All sigs verified (sigs list exhausted) — push true
  rule <k> #verifyMultisig(_, .List) => .K ...</k>
       <stack> ST => ListItem(intToScriptNum(1)) ST </stack>

  // Step 4b: Sigs remain but pubkeys exhausted — push false
  rule <k> #verifyMultisig(.List, ListItem(_) _) => .K ...</k>
       <stack> ST => ListItem(intToScriptNum(0)) ST </stack>

  // Step 4c: Empty sig in multisig — always fails to match, advance pubkey only
  rule <k> #verifyMultisig(ListItem(_PK:Bytes) PKs, ListItem(SIG:Bytes) Sigs)
        => #verifyMultisig(PKs, ListItem(SIG) Sigs) ...</k>
    requires lengthBytes(SIG) ==Int 0

  // Step 4d: Current sig matches current pubkey — advance both
  rule <k> #verifyMultisig(ListItem(PK:Bytes) PKs, ListItem(SIG:Bytes) Sigs)
        => #verifyMultisig(PKs, Sigs) ...</k>
       <sighash> SIGHASHBLOB </sighash>
    requires lengthBytes(SIG) >Int 0
     andBool ecdsaVerify(PK, SIG, lookupSighash(SIGHASHBLOB, sigHashType(SIG)))

  // Step 4e: Current sig does not match current pubkey — advance pubkey only
  rule <k> #verifyMultisig(ListItem(PK:Bytes) PKs, ListItem(SIG:Bytes) Sigs)
        => #verifyMultisig(PKs, ListItem(SIG) Sigs) ...</k>
       <sighash> SIGHASHBLOB </sighash>
    requires lengthBytes(SIG) >Int 0
     andBool notBool ecdsaVerify(PK, SIG, lookupSighash(SIGHASHBLOB, sigHashType(SIG)))

  // =========================================================================
  // Additional hash opcodes
  // =========================================================================

  // OP_RIPEMD160: RIPEMD160(data) — single hash
  rule <k> OP_RIPEMD160 => .K ...</k>
       <stack> ListItem(V:Bytes) ST => ListItem(RipEmd160raw(V)) ST </stack>

  // OP_SHA1: not implemented (no SHA1 hook in KRYPTO) — gets stuck

  // OP_SHA256: SHA256(data) — single hash
  rule <k> OP_SHA256 => .K ...</k>
       <stack> ListItem(V:Bytes) ST => ListItem(Sha256raw(V)) ST </stack>

  // OP_HASH256: SHA256(SHA256(data)) — double hash
  rule <k> OP_HASH256 => .K ...</k>
       <stack> ListItem(V:Bytes) ST => ListItem(Sha256raw(Sha256raw(V))) ST </stack>

  // OP_CODESEPARATOR: NOP for now
  rule <k> OP_CODESEPARATOR => .K ...</k>

  // =========================================================================
  // OP_CHECKSIGVERIFY: CHECKSIG then VERIFY
  // =========================================================================

  rule <k> OP_CHECKSIGVERIFY => .K ...</k>
       <stack> ListItem(PK:Bytes) ListItem(SIG:Bytes) ST => ST </stack>
       <sighash> SIGHASHBLOB </sighash>
    requires lengthBytes(SIG) >Int 0
     andBool ecdsaVerify(PK, SIG, lookupSighash(SIGHASHBLOB, sigHashType(SIG)))

  rule <k> OP_CHECKSIGVERIFY => #fail("CHECKSIGVERIFY") ...</k>
       <stack> ListItem(PK:Bytes) ListItem(SIG:Bytes) ST => ST </stack>
       <sighash> SIGHASHBLOB </sighash>
    requires lengthBytes(SIG) >Int 0
     andBool notBool ecdsaVerify(PK, SIG, lookupSighash(SIGHASHBLOB, sigHashType(SIG)))

  rule <k> OP_CHECKSIGVERIFY => #fail("CHECKSIGVERIFY") ...</k>
       <stack> ListItem(_PK:Bytes) ListItem(SIG:Bytes) ST => ST </stack>
    requires lengthBytes(SIG) ==Int 0

  // =========================================================================
  // OP_CHECKMULTISIGVERIFY: CHECKMULTISIG then VERIFY
  // =========================================================================

  // Reuse CHECKMULTISIG collection pipeline, then verify the result
  rule <k> OP_CHECKMULTISIGVERIFY
        => OP_CHECKMULTISIG ~> OP_VERIFY ...</k>

endmodule
