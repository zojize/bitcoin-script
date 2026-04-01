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
      <flags> $FLAGS:Int </flags>
    </T>

  // --- Flag checking (Bitcoin Core verification flags as bitmask) ---
  syntax Int ::= "FLAG_P2SH"                         [macro]
               | "FLAG_STRICTENC"                    [macro]
               | "FLAG_DERSIG"                       [macro]
               | "FLAG_LOW_S"                        [macro]
               | "FLAG_NULLDUMMY"                    [macro]
               | "FLAG_SIGPUSHONLY"                  [macro]
               | "FLAG_MINIMALDATA"                  [macro]
               | "FLAG_DISCOURAGE_UPGRADABLE_NOPS"   [macro]
               | "FLAG_CLEANSTACK"                   [macro]
               | "FLAG_CHECKLOCKTIMEVERIFY"          [macro]
               | "FLAG_CHECKSEQUENCEVERIFY"          [macro]
               | "FLAG_NULLFAIL"                     [macro]

  rule FLAG_P2SH                        => 1
  rule FLAG_STRICTENC                   => 2
  rule FLAG_DERSIG                      => 4
  rule FLAG_LOW_S                       => 8
  rule FLAG_NULLDUMMY                   => 16
  rule FLAG_SIGPUSHONLY                 => 32
  rule FLAG_MINIMALDATA                 => 64
  rule FLAG_DISCOURAGE_UPGRADABLE_NOPS  => 128
  rule FLAG_CLEANSTACK                  => 256
  rule FLAG_CHECKLOCKTIMEVERIFY         => 512
  rule FLAG_CHECKSEQUENCEVERIFY         => 1024
  rule FLAG_NULLFAIL                    => 16384

  syntax Bool ::= hasFlag(Int, Int) [function, total]
  rule hasFlag(FLAGS, BIT) => (FLAGS &Int BIT) =/=Int 0

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
  // SIG_PUSHONLY: when flag set, scriptSig must contain only push opcodes
  rule <k> #init => #decodeScript(SIG) ~> #phaseComplete ...</k>
       <scriptSigBytes> SIG </scriptSigBytes>
       <flags> F </flags>
    requires lengthBytes(SIG) >Int 0
     andBool lengthBytes(SIG) <=Int 10000
     andBool (notBool hasFlag(F, FLAG_SIGPUSHONLY) orBool #isPushOnly(SIG))

  rule <k> #init => #fail("SIG_PUSHONLY") ...</k>
       <scriptSigBytes> SIG </scriptSigBytes>
       <flags> F </flags>
    requires lengthBytes(SIG) >Int 0
     andBool hasFlag(F, FLAG_SIGPUSHONLY)
     andBool notBool #isPushOnly(SIG)

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
  // CLEANSTACK: when flag set, stack must have exactly 1 element
  rule <k> #phaseComplete => .K ...</k>
       <phase> scriptPubKey => done </phase>
       <exec> .List </exec>
       <stack> ST </stack>
       <flags> F </flags>
       <scriptPubKeyBytes> PK </scriptPubKeyBytes>
       <timestamp> TS </timestamp>
    requires (notBool #isP2SH(PK) orBool TS <Int 1333238400)
     andBool (notBool hasFlag(F, FLAG_CLEANSTACK) orBool size(ST) ==Int 1)

  rule <k> #phaseComplete => #fail("CLEANSTACK") ...</k>
       <phase> scriptPubKey </phase>
       <exec> .List </exec>
       <stack> ST </stack>
       <flags> F </flags>
       <scriptPubKeyBytes> PK </scriptPubKeyBytes>
       <timestamp> TS </timestamp>
    requires (notBool #isP2SH(PK) orBool TS <Int 1333238400)
     andBool hasFlag(F, FLAG_CLEANSTACK) andBool size(ST) =/=Int 1

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

  // After p2sh-redeem completes: done (CLEANSTACK check)
  rule <k> #phaseComplete => .K ...</k>
       <phase> p2sh-redeem => done </phase>
       <exec> .List </exec>
       <stack> ST </stack>
       <flags> F </flags>
    requires notBool hasFlag(F, FLAG_CLEANSTACK) orBool size(ST) ==Int 1

  rule <k> #phaseComplete => #fail("CLEANSTACK") ...</k>
       <phase> p2sh-redeem </phase>
       <exec> .List </exec>
       <stack> ST </stack>
       <flags> F </flags>
    requires hasFlag(F, FLAG_CLEANSTACK) andBool size(ST) =/=Int 1

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

  // =========================================================================
  // OP_PUSHDATA: push raw bytes onto the stack (emitted by decoder for data pushes)
  // =========================================================================

  // MINIMALDATA: check push encoding at execution time (not decode) so dead branches pass
  rule <k> OP_PUSHDATA(OPC, D) => .K ...</k>
       <stack> ST => ListItem(D) ST </stack>
       <flags> F </flags>
    requires notBool hasFlag(F, FLAG_MINIMALDATA) orBool #isMinimalPush(OPC, D)

  rule <k> OP_PUSHDATA(OPC, D) => #fail("MINIMALDATA") ...</k>
       <flags> F </flags>
    requires hasFlag(F, FLAG_MINIMALDATA) andBool notBool #isMinimalPush(OPC, D)

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
  // Shared syntax declarations (rules defined in submodules)
  // =========================================================================

  // Execution guard (rules in SCRIPT-FLOW)
  syntax KItem ::= "#guardExec" "(" OpCode ")"
  syntax Bool ::= #allTrue(List) [function]

  // Decoder syntax and helpers (rules in SCRIPT-DECODE)
  syntax KItem ::= "#decodeScript" "(" Bytes ")"
                 | "#decode1" "(" Bytes ")"
                 | "#decodePush" "(" Int "," Int "," Bytes ")"

  syntax Int ::= #scriptByte(Bytes) [function]
  rule #scriptByte(B) => Bytes2Int(substrBytes(B, 0, 1), BE, Unsigned)

  syntax Bytes ::= #scriptTail(Bytes) [function]
  rule #scriptTail(B) => substrBytes(B, 1, lengthBytes(B))
  syntax KItem ::= "#countOp"
                 | "#countOps" "(" Int ")"
  syntax Bool ::= #isMinimalPush(Int, Bytes) [function, total]

  // Sig verification syntax (rules in SCRIPT-SIG)
  syntax KItem ::= "#collectPubKeys" "(" Int "," List ")"
                 | "#collectSigs" "(" Int "," List "," List ")"
                 | "#verifyMultisig" "(" List "," List ")"

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
       <flags> F </flags>
       <stack> ListItem(A:Bytes) ListItem(B:Bytes) ST
            => ListItem(intToScriptNum(scriptNumToInt(A) +Int scriptNumToInt(B))) ST </stack>
    requires validNumFlags(A, F) andBool validNumFlags(B, F)

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


endmodule
