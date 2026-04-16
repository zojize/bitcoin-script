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
  syntax Phase ::= "scriptSig" | "scriptPubKey" | "p2sh-redeem" | "witness-v0" | "witness-v1" | "done"

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
      <scriptSigBytes> $SCRIPTSIG:Bytes </scriptSigBytes>
      <scriptPubKeyBytes> $SCRIPTPUBKEY:Bytes </scriptPubKeyBytes>
      <witness> $WITNESS:Bytes </witness>
      <savedStack> .List </savedStack>
      <opCount> 0 </opCount>
      <flags> $FLAGS:Int </flags>
      <txVersion> $TXVERSION:Int </txVersion>
      <nLockTime> $NLOCKTIME:Int </nLockTime>
      <nSequence> $NSEQUENCE:Int </nSequence>
      <witnessUsed> false </witnessUsed>
      <p2shRedeemBytes> .Bytes </p2shRedeemBytes>
      <codesepIdx> 0 </codesepIdx>
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
               | "FLAG_WITNESS"                       [macro]
               | "FLAG_DISCOURAGE_UPGRADABLE_WITNESS" [macro]
               | "FLAG_MINIMALIF"                    [macro]
               | "FLAG_NULLFAIL"                     [macro]
               | "FLAG_WITNESS_PUBKEYTYPE"           [macro]
               | "FLAG_CONST_SCRIPTCODE"             [macro]
               | "FLAG_TAPROOT"                     [macro]

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
  rule FLAG_WITNESS                     => 2048
  rule FLAG_DISCOURAGE_UPGRADABLE_WITNESS => 4096
  rule FLAG_MINIMALIF                   => 8192
  rule FLAG_NULLFAIL                    => 16384
  rule FLAG_WITNESS_PUBKEYTYPE          => 32768
  rule FLAG_CONST_SCRIPTCODE            => 65536
  rule FLAG_TAPROOT                    => 131072

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
       <codesepIdx> _ => 0 </codesepIdx>
       <flags> F </flags>
    requires hasFlag(F, FLAG_P2SH) andBool #isP2SH(PK)
     andBool lengthBytes(PK) <=Int 10000

  rule <k> #phaseComplete => #decodeScript(PK) ~> #phaseComplete ...</k>
       <phase> scriptSig => scriptPubKey </phase>
       <scriptPubKeyBytes> PK </scriptPubKeyBytes>
       <altstack> _ => .List </altstack>
       <exec> .List </exec>
       <opCount> _ => 0 </opCount>
       <codesepIdx> _ => 0 </codesepIdx>
       <flags> F </flags>
    requires notBool (hasFlag(F, FLAG_P2SH) andBool #isP2SH(PK))
     andBool lengthBytes(PK) <=Int 10000

  // After scriptPubKey completes, NOT P2SH, IS witness program with WITNESS flag:
  // Native witness: scriptSig must be empty (WITNESS_MALLEATED)
  rule <k> #phaseComplete => #fail("WITNESS_MALLEATED") ...</k>
       <phase> scriptPubKey </phase>
       <exec> .List </exec>
       <flags> F </flags>
       <scriptPubKeyBytes> PK </scriptPubKeyBytes>
       <scriptSigBytes> SIG </scriptSigBytes>
    requires notBool (hasFlag(F, FLAG_P2SH) andBool #isP2SH(PK))
     andBool hasFlag(F, FLAG_WITNESS) andBool #isWitnessProgram(PK)
     andBool lengthBytes(SIG) >Int 0

  // Native witness: enter witness verification
  rule <k> #phaseComplete => #witnessVerify(#witnessVersion(PK), #witnessProgram(PK)) ...</k>
       <phase> scriptPubKey </phase>
       <exec> .List </exec>
       <flags> F </flags>
       <scriptPubKeyBytes> PK </scriptPubKeyBytes>
       <scriptSigBytes> SIG </scriptSigBytes>
    requires notBool (hasFlag(F, FLAG_P2SH) andBool #isP2SH(PK))
     andBool hasFlag(F, FLAG_WITNESS) andBool #isWitnessProgram(PK)
     andBool lengthBytes(SIG) ==Int 0

  // After scriptPubKey completes, NOT P2SH, NOT witness program: done
  // WITNESS_UNEXPECTED: witness data present but no witness program
  rule <k> #phaseComplete => #fail("WITNESS_UNEXPECTED") ...</k>
       <phase> scriptPubKey </phase>
       <exec> .List </exec>
       <flags> F </flags>
       <scriptPubKeyBytes> PK </scriptPubKeyBytes>
       <witness> W </witness>
       <witnessUsed> false </witnessUsed>
    requires notBool (hasFlag(F, FLAG_P2SH) andBool #isP2SH(PK))
     andBool notBool (hasFlag(F, FLAG_WITNESS) andBool #isWitnessProgram(PK))
     andBool hasFlag(F, FLAG_WITNESS) andBool #witnessCount(W) >Int 0

  // Exec stack must be empty (balanced IF/ENDIF)
  // CLEANSTACK: when flag set, stack must have exactly 1 element
  rule <k> #phaseComplete => .K ...</k>
       <phase> scriptPubKey => done </phase>
       <exec> .List </exec>
       <stack> ST </stack>
       <flags> F </flags>
       <scriptPubKeyBytes> PK </scriptPubKeyBytes>
       <witness> W </witness>
       <witnessUsed> WU </witnessUsed>
    requires notBool (hasFlag(F, FLAG_P2SH) andBool #isP2SH(PK))
     andBool notBool (hasFlag(F, FLAG_WITNESS) andBool #isWitnessProgram(PK))
     andBool (notBool hasFlag(F, FLAG_WITNESS) orBool WU orBool #witnessCount(W) ==Int 0)
     andBool (notBool hasFlag(F, FLAG_CLEANSTACK) orBool size(ST) ==Int 1)

  rule <k> #phaseComplete => #fail("CLEANSTACK") ...</k>
       <phase> scriptPubKey </phase>
       <exec> .List </exec>
       <stack> ST </stack>
       <flags> F </flags>
       <scriptPubKeyBytes> PK </scriptPubKeyBytes>
       <witness> W </witness>
       <witnessUsed> WU </witnessUsed>
    requires notBool (hasFlag(F, FLAG_P2SH) andBool #isP2SH(PK))
     andBool notBool (hasFlag(F, FLAG_WITNESS) andBool #isWitnessProgram(PK))
     andBool (notBool hasFlag(F, FLAG_WITNESS) orBool WU orBool #witnessCount(W) ==Int 0)
     andBool hasFlag(F, FLAG_CLEANSTACK) andBool size(ST) =/=Int 1

  // After scriptPubKey completes, IS P2SH, scriptPubKey succeeded:
  // restore saved stack, pop redeem script, decode and execute it
  // Save redeem bytes for P2SH-wrapped witness detection
  rule <k> #phaseComplete => #decodeScript(REDEEM) ~> #phaseComplete ...</k>
       <phase> scriptPubKey => p2sh-redeem </phase>
       <exec> .List </exec>
       <opCount> _ => 0 </opCount>
       <codesepIdx> _ => 0 </codesepIdx>
       <flags> F </flags>
       <scriptPubKeyBytes> PK </scriptPubKeyBytes>
       <stack> ListItem(V:Bytes) _ => REST </stack>
       <savedStack> ListItem(REDEEM:Bytes) REST </savedStack>
       <scriptSigBytes> SIG </scriptSigBytes>
       <p2shRedeemBytes> _ => REDEEM </p2shRedeemBytes>
    requires hasFlag(F, FLAG_P2SH) andBool #isP2SH(PK)
     andBool #isPushOnly(SIG)
     andBool #isTruthy(V)
     andBool lengthBytes(REDEEM) <=Int 10000

  // After scriptPubKey completes, IS P2SH, but scriptPubKey FAILED (stack top falsy):
  // do not execute redeem script, just finish
  rule <k> #phaseComplete => .K ...</k>
       <phase> scriptPubKey => done </phase>
       <exec> .List </exec>
       <flags> F </flags>
       <stack> ListItem(V:Bytes) _ </stack>
       <scriptPubKeyBytes> PK </scriptPubKeyBytes>
       <scriptSigBytes> SIG </scriptSigBytes>
    requires hasFlag(F, FLAG_P2SH) andBool #isP2SH(PK)
     andBool #isPushOnly(SIG)
     andBool notBool #isTruthy(V)

  // After p2sh-redeem completes: check for P2SH-wrapped witness program
  rule <k> #phaseComplete => #witnessVerify(#witnessVersion(REDEEM), #witnessProgram(REDEEM)) ...</k>
       <phase> p2sh-redeem </phase>
       <exec> .List </exec>
       <flags> F </flags>
       <p2shRedeemBytes> REDEEM </p2shRedeemBytes>
    requires hasFlag(F, FLAG_WITNESS) andBool #isWitnessProgram(REDEEM)

  // After p2sh-redeem completes, NOT witness: done (CLEANSTACK + WITNESS_UNEXPECTED)
  rule <k> #phaseComplete => #fail("WITNESS_UNEXPECTED") ...</k>
       <phase> p2sh-redeem </phase>
       <exec> .List </exec>
       <flags> F </flags>
       <p2shRedeemBytes> REDEEM </p2shRedeemBytes>
       <witness> W </witness>
       <witnessUsed> false </witnessUsed>
    requires notBool (hasFlag(F, FLAG_WITNESS) andBool #isWitnessProgram(REDEEM))
     andBool hasFlag(F, FLAG_WITNESS) andBool #witnessCount(W) >Int 0

  rule <k> #phaseComplete => .K ...</k>
       <phase> p2sh-redeem => done </phase>
       <exec> .List </exec>
       <stack> ST </stack>
       <flags> F </flags>
       <p2shRedeemBytes> REDEEM </p2shRedeemBytes>
       <witness> W </witness>
       <witnessUsed> WU </witnessUsed>
    requires notBool (hasFlag(F, FLAG_WITNESS) andBool #isWitnessProgram(REDEEM))
     andBool (notBool hasFlag(F, FLAG_WITNESS) orBool WU orBool #witnessCount(W) ==Int 0)
     andBool (notBool hasFlag(F, FLAG_CLEANSTACK) orBool size(ST) ==Int 1)

  rule <k> #phaseComplete => #fail("CLEANSTACK") ...</k>
       <phase> p2sh-redeem </phase>
       <exec> .List </exec>
       <stack> ST </stack>
       <flags> F </flags>
       <p2shRedeemBytes> REDEEM </p2shRedeemBytes>
       <witness> W </witness>
       <witnessUsed> WU </witnessUsed>
    requires notBool (hasFlag(F, FLAG_WITNESS) andBool #isWitnessProgram(REDEEM))
     andBool (notBool hasFlag(F, FLAG_WITNESS) orBool WU orBool #witnessCount(W) ==Int 0)
     andBool hasFlag(F, FLAG_CLEANSTACK) andBool size(ST) =/=Int 1

  // =========================================================================
  // Witness program detection (BIP 141)
  // =========================================================================
  // A witness program is: <version_byte> <push_2_to_40_bytes>
  // Version byte: OP_0 (0x00) or OP_1-OP_16 (0x51-0x60)
  // Total script length: 4-42 bytes, second byte + 2 == total length

  syntax Bool ::= #isWitnessProgram(Bytes) [function, total]
  rule #isWitnessProgram(B) => true
    requires lengthBytes(B) >=Int 4 andBool lengthBytes(B) <=Int 42
     andBool (#scriptByte(B) ==Int 0
              orBool (#scriptByte(B) >=Int 81 andBool #scriptByte(B) <=Int 96))
     andBool Bytes2Int(substrBytes(B, 1, 2), BE, Unsigned) +Int 2 ==Int lengthBytes(B)
  rule #isWitnessProgram(_) => false [owise]

  // Extract witness version: OP_0 → 0, OP_N → N
  syntax Int ::= #witnessVersion(Bytes) [function]
  rule #witnessVersion(B) => 0 requires #scriptByte(B) ==Int 0
  rule #witnessVersion(B) => #scriptByte(B) -Int 80
    requires #scriptByte(B) >=Int 81 andBool #scriptByte(B) <=Int 96

  // Extract witness program data (bytes after version + push opcode)
  syntax Bytes ::= #witnessProgram(Bytes) [function]
  rule #witnessProgram(B) => substrBytes(B, 2, lengthBytes(B))

  // =========================================================================
  // Witness blob decoding
  // =========================================================================
  // Blob format: <2-byte BE count> (<2-byte BE item_length> <item_bytes>)*

  // Count of witness items in the blob
  syntax Int ::= #witnessCount(Bytes) [function, total]
  rule #witnessCount(W) => Bytes2Int(substrBytes(W, 0, 2), BE, Unsigned)
    requires lengthBytes(W) >=Int 2
  rule #witnessCount(W) => 0
    requires lengthBytes(W) <Int 2

  // Decode the Nth witness item (0-indexed) from the blob
  // Skips past the 2-byte count header, then iterates to find item N
  syntax Bytes ::= #witnessItemAt(Bytes, Int) [function]
  rule #witnessItemAt(W, N) => #witnessItemSkip(substrBytes(W, 2, lengthBytes(W)), N)
    requires lengthBytes(W) >=Int 2

  // Skip N items, then read the next one
  syntax Bytes ::= #witnessItemSkip(Bytes, Int) [function]
  rule #witnessItemSkip(B, 0) =>
    substrBytes(B, 2, 2 +Int Bytes2Int(substrBytes(B, 0, 2), BE, Unsigned))
    requires lengthBytes(B) >=Int 2
  rule #witnessItemSkip(B, N) =>
    #witnessItemSkip(
      substrBytes(B, 2 +Int Bytes2Int(substrBytes(B, 0, 2), BE, Unsigned), lengthBytes(B)),
      N -Int 1)
    requires N >Int 0 andBool lengthBytes(B) >=Int 2

  // Build a K List of witness items from the blob (indices FROM to TO exclusive)
  syntax List ::= #witnessList(Bytes, Int, Int) [function]
  rule #witnessList(_, FROM, TO) => .List requires FROM >=Int TO
  rule #witnessList(W, FROM, TO) =>
    ListItem(#witnessItemAt(W, FROM)) #witnessList(W, FROM +Int 1, TO)
    requires FROM <Int TO

  // Push witness items onto the stack (items FROM to TO, pushed first-to-last
  // so item FROM ends up at the bottom, item TO-1 at the top)
  syntax KItem ::= "#pushWitnessStack" "(" Bytes "," Int "," Int ")"
  rule <k> #pushWitnessStack(_, FROM, TO) => .K ...</k>
    requires FROM >=Int TO
  rule <k> #pushWitnessStack(W, FROM, TO)
        => #pushWitnessStack(W, FROM +Int 1, TO) ...</k>
       <stack> ST => ListItem(#witnessItemAt(W, FROM)) ST </stack>
    requires FROM <Int TO

  // =========================================================================
  // Witness verification (BIP 141)
  // =========================================================================
  syntax KItem ::= "#witnessVerify" "(" Int "," Bytes ")"
                 | "#witnessComplete"

  // Version 0, empty witness stack → error
  rule <k> #witnessVerify(0, _) => #fail("WITNESS_PROGRAM_WITNESS_EMPTY") ...</k>
       <witness> W </witness>
    requires #witnessCount(W) ==Int 0

  // --- Version 0, 32-byte program (P2WSH) ---
  // Witness script is the last item. SHA256(script) must equal program.
  // Remaining items become the initial stack.
  rule <k> #witnessVerify(0, PROG)
        => #pushWitnessStack(W, 0, #witnessCount(W) -Int 1)
        ~> #decodeScript(#witnessItemAt(W, #witnessCount(W) -Int 1))
        ~> #witnessComplete ...</k>
       <witness> W </witness>
       <stack> _ => .List </stack>
       <altstack> _ => .List </altstack>
       <exec> _ => .List </exec>
       <opCount> _ => 0 </opCount>
       <codesepIdx> _ => 0 </codesepIdx>
       <phase> _ => witness-v0 </phase>
       <witnessUsed> _ => true </witnessUsed>
    requires #witnessCount(W) >Int 0
     andBool lengthBytes(PROG) ==Int 32
     andBool Sha256raw(#witnessItemAt(W, #witnessCount(W) -Int 1)) ==K PROG

  // P2WSH: hash mismatch
  rule <k> #witnessVerify(0, PROG) => #fail("WITNESS_PROGRAM_MISMATCH") ...</k>
       <witness> W </witness>
    requires #witnessCount(W) >Int 0
     andBool lengthBytes(PROG) ==Int 32
     andBool Sha256raw(#witnessItemAt(W, #witnessCount(W) -Int 1)) =/=K PROG

  // --- Version 0, 20-byte program (P2WPKH) ---
  // Witness must have exactly 2 items (sig, pubkey).
  // Synthesize P2PKH: OP_DUP OP_HASH160 <20-byte-program> OP_EQUALVERIFY OP_CHECKSIG
  rule <k> #witnessVerify(0, PROG)
        => #pushWitnessStack(W, 0, 2)
        ~> #decodeScript(Int2Bytes(1, 118, BE) +Bytes Int2Bytes(1, 169, BE)
             +Bytes Int2Bytes(1, 20, BE) +Bytes PROG
             +Bytes Int2Bytes(1, 136, BE) +Bytes Int2Bytes(1, 172, BE))
        ~> #witnessComplete ...</k>
       <witness> W </witness>
       <stack> _ => .List </stack>
       <altstack> _ => .List </altstack>
       <exec> _ => .List </exec>
       <opCount> _ => 0 </opCount>
       <codesepIdx> _ => 0 </codesepIdx>
       <phase> _ => witness-v0 </phase>
       <witnessUsed> _ => true </witnessUsed>
    requires #witnessCount(W) ==Int 2
     andBool lengthBytes(PROG) ==Int 20

  // P2WPKH: wrong witness count
  rule <k> #witnessVerify(0, PROG) => #fail("WITNESS_PROGRAM_MISMATCH") ...</k>
       <witness> W </witness>
    requires #witnessCount(W) =/=Int 2
     andBool #witnessCount(W) >Int 0
     andBool lengthBytes(PROG) ==Int 20

  // --- Version 0, wrong program length ---
  rule <k> #witnessVerify(0, PROG) => #fail("WITNESS_PROGRAM_WRONG_LENGTH") ...</k>
       <witness> W </witness>
    requires #witnessCount(W) >Int 0
     andBool lengthBytes(PROG) =/=Int 20 andBool lengthBytes(PROG) =/=Int 32

  // --- Version 1+ with DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM ---
  // Version 1 with FLAG_TAPROOT set: do NOT discourage (it's activated)
  // Version 1 without FLAG_TAPROOT: discourage if flag set
  // Version 2+: always discourage if flag set
  rule <k> #witnessVerify(V, _) => #fail("DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM") ...</k>
       <flags> F </flags>
    requires V >Int 0
     andBool hasFlag(F, FLAG_DISCOURAGE_UPGRADABLE_WITNESS)
     andBool notBool (V ==Int 1 andBool hasFlag(F, FLAG_TAPROOT))

  // --- Version 1 with FLAG_TAPROOT: enter Taproot verification ---
  rule <k> #witnessVerify(1, PROG) => #taprootVerify(PROG) ...</k>
       <witness> W </witness>
       <flags> F </flags>
    requires hasFlag(F, FLAG_TAPROOT)
     andBool lengthBytes(PROG) ==Int 32
     andBool #witnessCount(W) >Int 0

  // Version 1 with FLAG_TAPROOT but empty witness
  rule <k> #witnessVerify(1, _) => #fail("WITNESS_PROGRAM_WITNESS_EMPTY") ...</k>
       <witness> W </witness>
       <flags> F </flags>
    requires hasFlag(F, FLAG_TAPROOT)
     andBool #witnessCount(W) ==Int 0

  // Version 1 with FLAG_TAPROOT but wrong program length (witness non-empty)
  rule <k> #witnessVerify(1, PROG) => #fail("WITNESS_PROGRAM_WRONG_LENGTH") ...</k>
       <witness> W </witness>
       <flags> F </flags>
    requires hasFlag(F, FLAG_TAPROOT)
     andBool #witnessCount(W) >Int 0
     andBool lengthBytes(PROG) =/=Int 32

  // --- Version 1 without FLAG_TAPROOT: anyone-can-spend ---
  rule <k> #witnessVerify(1, _) => .K ...</k>
       <phase> _ => done </phase>
       <flags> F </flags>
       <witnessUsed> _ => true </witnessUsed>
    requires notBool hasFlag(F, FLAG_TAPROOT)
     andBool notBool hasFlag(F, FLAG_DISCOURAGE_UPGRADABLE_WITNESS)

  // --- Version 2+: future witness versions ---
  rule <k> #witnessVerify(V, _) => .K ...</k>
       <phase> _ => done </phase>
       <flags> F </flags>
       <witnessUsed> _ => true </witnessUsed>
    requires V >Int 1
     andBool notBool hasFlag(F, FLAG_DISCOURAGE_UPGRADABLE_WITNESS)

  // --- Witness execution complete ---
  // Stack must have exactly 1 truthy item (CLEANSTACK always enforced in witness)
  rule <k> #witnessComplete => .K ...</k>
       <phase> witness-v0 => done </phase>
       <exec> .List </exec>
       <stack> ListItem(V:Bytes) .List </stack>
    requires #isTruthy(V)

  rule <k> #witnessComplete => #fail("EVAL_FALSE") ...</k>
       <phase> witness-v0 </phase>
       <exec> .List </exec>
       <stack> ListItem(V:Bytes) .List </stack>
    requires notBool #isTruthy(V)

  rule <k> #witnessComplete => #fail("CLEANSTACK") ...</k>
       <phase> witness-v0 </phase>
       <exec> .List </exec>
       <stack> ST </stack>
    requires size(ST) =/=Int 1

  // =========================================================================
  // Taproot verification (BIP 341)
  // =========================================================================
  syntax KItem ::= "#taprootVerify" "(" Bytes ")"
                 | "#tapscriptComplete"

  // --- Annex detection ---
  // The annex is the last witness item if it starts with 0x50 and witness has 2+ items.
  syntax Bool ::= #hasAnnex(Bytes) [function, total]
  rule #hasAnnex(W) => true
    requires #witnessCount(W) >=Int 2
     andBool lengthBytes(#witnessItemAt(W, #witnessCount(W) -Int 1)) >Int 0
     andBool Bytes2Int(substrBytes(#witnessItemAt(W, #witnessCount(W) -Int 1), 0, 1), BE, Unsigned) ==Int 80
  rule #hasAnnex(_) => false [owise]

  // Effective witness count (excluding annex)
  syntax Int ::= #taprootWitnessCount(Bytes) [function]
  rule #taprootWitnessCount(W) => #witnessCount(W) -Int 1
    requires #hasAnnex(W)
  rule #taprootWitnessCount(W) => #witnessCount(W)
    requires notBool #hasAnnex(W)

  // --- Key path spend ---
  // Single witness item (after stripping annex): Schnorr signature
  // Verify against the output key (32-byte witness program)
  // TODO: full Schnorr sighash + verification
  rule <k> #taprootVerify(_PROG) => #fail("TAPROOT_KEY_PATH_NOT_IMPLEMENTED") ...</k>
       <witness> W </witness>
    requires #taprootWitnessCount(W) ==Int 1

  // --- Script path spend ---
  // Control block: <1-byte leaf_version|parity> <32-byte internal_key> <32-byte merkle_path>*
  // Witness layout: [stack_items..., tapscript, control_block, ?annex]

  // Control block length invalid
  rule <k> #taprootVerify(_PROG) => #fail("TAPROOT_WRONG_CONTROL_SIZE") ...</k>
       <witness> W </witness>
    requires #taprootWitnessCount(W) >Int 1
     andBool ( lengthBytes(#witnessItemAt(W, #taprootWitnessCount(W) -Int 1)) <Int 33
        orBool (lengthBytes(#witnessItemAt(W, #taprootWitnessCount(W) -Int 1)) -Int 33) modInt 32 =/=Int 0 )

  // Control block valid: verify output key and enter tapscript execution
  rule <k> #taprootVerify(PROG)
        => #pushWitnessStack(W, 0, #taprootWitnessCount(W) -Int 2)
        ~> #decodeScript(#witnessItemAt(W, #taprootWitnessCount(W) -Int 2))
        ~> #tapscriptComplete ...</k>
       <witness> W </witness>
       <stack> _ => .List </stack>
       <altstack> _ => .List </altstack>
       <exec> _ => .List </exec>
       <opCount> _ => 0 </opCount>
       <codesepIdx> _ => 0 </codesepIdx>
       <phase> _ => witness-v1 </phase>
       <witnessUsed> _ => true </witnessUsed>
    requires #taprootWitnessCount(W) >Int 1
     andBool #validControlBlock(W, PROG)

  // Control block valid length but output key mismatch
  rule <k> #taprootVerify(PROG) => #fail("WITNESS_PROGRAM_MISMATCH") ...</k>
       <witness> W </witness>
    requires #taprootWitnessCount(W) >Int 1
     andBool lengthBytes(#witnessItemAt(W, #taprootWitnessCount(W) -Int 1)) >=Int 33
     andBool (lengthBytes(#witnessItemAt(W, #taprootWitnessCount(W) -Int 1)) -Int 33) modInt 32 ==Int 0
     andBool notBool #validControlBlock(W, PROG)

  // --- Witness item helpers for taproot ---
  syntax Bytes ::= #taprootCB(Bytes) [function]
  rule #taprootCB(W) => #witnessItemAt(W, #taprootWitnessCount(W) -Int 1)

  syntax Bytes ::= #taprootScript(Bytes) [function]
  rule #taprootScript(W) => #witnessItemAt(W, #taprootWitnessCount(W) -Int 2)

  // --- Control block validation ---
  // Extracts internal key, computes merkle root from path, verifies tweaked key == output
  syntax Bool ::= #validControlBlock(Bytes, Bytes) [function]
  rule #validControlBlock(W, PROG) =>
    TaprootCheckOutput(PROG,
      #cbInternalKey(#taprootCB(W)),
      #walkMerkle(#taprootCB(W), 33,
        #leafHash(#taprootCB(W), #taprootScript(W))))

  // Extract internal key (bytes 1-33 of control block)
  syntax Bytes ::= #cbInternalKey(Bytes) [function]
  rule #cbInternalKey(CB) => substrBytes(CB, 1, 33)

  // Extract leaf version (first byte, mask off parity bit 0)
  syntax Int ::= #cbLeafVersion(Bytes) [function]
  rule #cbLeafVersion(CB) => Bytes2Int(substrBytes(CB, 0, 1), BE, Unsigned) &Int 254

  // --- Leaf hash computation ---
  // TapLeaf = TaggedHash("TapLeaf", leaf_version || compact_size(script_len) || script)
  // For scripts <= 252 bytes, compact_size is 1 byte.
  // For scripts 253-65535 bytes, compact_size is 0xfd + 2 bytes LE.
  syntax Bytes ::= #leafHash(Bytes, Bytes) [function]
  rule #leafHash(CB, SCRIPT) =>
    #taggedHash(#tapLeafTag, Int2Bytes(1, #cbLeafVersion(CB), BE)
      +Bytes #compactSize(lengthBytes(SCRIPT)) +Bytes SCRIPT)

  // Compact size encoding
  syntax Bytes ::= #compactSize(Int) [function]
  rule #compactSize(N) => Int2Bytes(1, N, BE)
    requires N <=Int 252
  rule #compactSize(N) => Int2Bytes(1, 253, BE) +Bytes Int2Bytes(2, N, LE)
    requires N >Int 252 andBool N <=Int 65535

  // --- Merkle path computation ---
  // Walk the merkle path in the control block to compute the merkle root.
  // Path nodes are 32-byte chunks starting at offset 33 in the control block.
  // #walkMerkle(CB, offset, currentHash): offset starts at 33, increments by 32.
  syntax Bytes ::= #walkMerkle(Bytes, Int, Bytes) [function]
  // Done: offset reached end of control block
  rule #walkMerkle(CB, OFF, CURRENT) => CURRENT
    requires OFF >=Int lengthBytes(CB)

  // Process next node: TapBranch = TaggedHash("TapBranch", min(a,b) || max(a,b))
  rule #walkMerkle(CB, OFF, CURRENT) =>
    #walkMerkle(CB, OFF +Int 32,
      #tapBranchHash(CURRENT, substrBytes(CB, OFF, OFF +Int 32)))
    requires OFF +Int 32 <=Int lengthBytes(CB)

  // TapBranch: hash the two children in sorted order
  syntax Bytes ::= #tapBranchHash(Bytes, Bytes) [function]
  rule #tapBranchHash(A, B) => #taggedHash(#tapBranchTag, A +Bytes B)
    requires A <=Bytes B
  rule #tapBranchHash(A, B) => #taggedHash(#tapBranchTag, B +Bytes A)
    requires notBool (A <=Bytes B)

  // Lexicographic byte comparison
  syntax Bool ::= Bytes "<=Bytes" Bytes [function]
  rule A <=Bytes B => Bytes2Int(A, BE, Unsigned) <=Int Bytes2Int(B, BE, Unsigned)

  // --- Tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg) ---
  syntax Bytes ::= #taggedHash(Bytes, Bytes) [function]
  rule #taggedHash(TAG_HASH, MSG) => Sha256raw(TAG_HASH +Bytes TAG_HASH +Bytes MSG)

  // Pre-computed SHA256("TapLeaf") and SHA256("TapBranch") tag hashes
  // These are passed as already-hashed tags to #taggedHash.
  syntax Bytes ::= "#tapLeafTag" [function]
                 | "#tapBranchTag" [function]
  // SHA256("TapLeaf") = aeea8fdc4208983105734b58081d1e2638d35f1cb54008d4d357ca03be78e9ee
  rule #tapLeafTag => b"\xae\xea\x8f\xdc\x42\x08\x98\x31\x05\x73\x4b\x58\x08\x1d\x1e\x26\x38\xd3\x5f\x1c\xb5\x40\x08\xd4\xd3\x57\xca\x03\xbe\x78\xe9\xee"
  // SHA256("TapBranch") = 1941a1f2e56eb95fa2a9f194be5c01f7216f33ed82b091463490d05bf516a015
  rule #tapBranchTag => b"\x19\x41\xa1\xf2\xe5\x6e\xb9\x5f\xa2\xa9\xf1\x94\xbe\x5c\x01\xf7\x21\x6f\x33\xed\x82\xb0\x91\x46\x34\x90\xd0\x5b\xf5\x16\xa0\x15"

  // --- Tapscript execution complete ---
  // Same as witness-v0: exactly 1 truthy item on stack
  rule <k> #tapscriptComplete => .K ...</k>
       <phase> witness-v1 => done </phase>
       <exec> .List </exec>
       <stack> ListItem(V:Bytes) .List </stack>
    requires #isTruthy(V)

  rule <k> #tapscriptComplete => #fail("EVAL_FALSE") ...</k>
       <phase> witness-v1 </phase>
       <exec> .List </exec>
       <stack> ListItem(V:Bytes) .List </stack>
    requires notBool #isTruthy(V)

  rule <k> #tapscriptComplete => #fail("CLEANSTACK") ...</k>
       <phase> witness-v1 </phase>
       <exec> .List </exec>
       <stack> ST </stack>
    requires size(ST) =/=Int 1

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
       <stack> ListItem(V:Bytes) ST => ListItem(Hash160raw(V)) ST </stack>

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
