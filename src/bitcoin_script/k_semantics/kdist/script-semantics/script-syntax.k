module SCRIPT-SYNTAX
  imports INT-SYNTAX
  imports STRING-SYNTAX
  imports BYTES-SYNTAX

  // --- Hex literal token ---
  syntax HexLiteral ::= r"[0-9a-fA-F]+" [token]

  // --- Opcodes ---
  syntax OpCode ::= "OP_DUP"
                  | "OP_ADD"
                  | "OP_EQUAL"
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
                  // New opcodes for P2SH support
                  | "OP_1NEGATE"
                  | "OP_NOP"
                  | "OP_IF" | "OP_NOTIF" | "OP_ELSE" | "OP_ENDIF"
                  | "OP_VERIFY"
                  | "OP_RETURN"
                  // Stack ops
                  | "OP_TOALTSTACK" | "OP_FROMALTSTACK"
                  | "OP_2DROP" | "OP_2DUP" | "OP_3DUP"
                  | "OP_2OVER" | "OP_2ROT" | "OP_2SWAP"
                  | "OP_IFDUP" | "OP_DEPTH" | "OP_DROP"
                  | "OP_NIP" | "OP_OVER" | "OP_PICK" | "OP_ROLL"
                  | "OP_ROT" | "OP_SWAP" | "OP_TUCK"
                  | "OP_SIZE"
                  // Arithmetic
                  | "OP_1ADD" | "OP_1SUB"
                  | "OP_NEGATE" | "OP_ABS"
                  | "OP_NOT" | "OP_0NOTEQUAL"
                  | "OP_SUB"
                  | "OP_BOOLAND" | "OP_BOOLOR"
                  | "OP_NUMEQUAL" | "OP_NUMEQUALVERIFY"
                  | "OP_NUMNOTEQUAL"
                  | "OP_LESSTHAN" | "OP_GREATERTHAN"
                  | "OP_LESSTHANOREQUAL" | "OP_GREATERTHANOREQUAL"
                  | "OP_MIN" | "OP_MAX"
                  | "OP_WITHIN"
                  // Crypto
                  | "OP_RIPEMD160" | "OP_SHA1" | "OP_SHA256"
                  | "OP_HASH256"
                  | "OP_CODESEPARATOR"
                  | "OP_CHECKSIGVERIFY"
                  | "OP_CHECKMULTISIGVERIFY"
                  // NOP variants (OP_NOP2 = CHECKLOCKTIMEVERIFY, OP_NOP3 = CHECKSEQUENCEVERIFY)
                  | "OP_NOP1" | "OP_NOP2" | "OP_NOP3" | "OP_NOP4" | "OP_NOP5"
                  | "OP_NOP6" | "OP_NOP7" | "OP_NOP8" | "OP_NOP9" | "OP_NOP10"
                  // Unknown/undefined/disabled opcodes — immediately fail (no execution rule)
                  | "OP_INVALIDOPCODE"
                  // Reserved opcodes — fail when executed, OK in dead branches
                  | "OP_RESERVED_OP"

  // --- Script is a sequence of opcodes (whitespace-separated) ---
  syntax Script ::= OpCode | Script Script [left]

  // --- Hex script token: 0x-prefixed hex bytes (e.g. 0x76a914...88ac) ---
  syntax HexPgm ::= r"0x[0-9a-fA-F]+" [token]
endmodule
