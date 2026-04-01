requires "script-semantics.k"

// Control flow, execution guards, NOP variants, and special opcodes.
module SCRIPT-FLOW
  imports SCRIPT-SEMANTICS

  // =========================================================================
  // #allTrue: check if all exec-stack entries are true
  // =========================================================================

  // #allTrue syntax declared in SCRIPT-SEMANTICS
  rule #allTrue(.List) => true
  rule #allTrue(ListItem(true) REST) => #allTrue(REST)
  rule #allTrue(ListItem(false) _) => false

  // =========================================================================
  // #guardExec: centralized execution guard
  // =========================================================================
  // All non-flow-control opcodes are wrapped in #guardExec by the decoder.
  // When executing (#allTrue), unwrap to the opcode; when skipping, discard.

  // #guardExec syntax declared in SCRIPT-SEMANTICS
  rule <k> #guardExec(OP) => OP ...</k>
       <exec> EX </exec>
    requires #allTrue(EX)

  rule <k> #guardExec(_) => .K ...</k>
       <exec> EX </exec>
    requires notBool #allTrue(EX)

  // =========================================================================
  // IF/ELSE/ENDIF conditional execution
  // =========================================================================
  // The <exec> cell holds a list of booleans tracking nested IF state.
  // Execution proceeds only when all entries are true (#allTrue).

  // --- When currently executing (#allTrue(<exec>) is true) ---

  // MINIMALIF: in witness v0, when flag set, IF/NOTIF top must be empty or 0x01
  rule <k> OP_IF => #fail("MINIMALIF") ...</k>
       <stack> ListItem(V:Bytes) ST => ST </stack>
       <exec> EX </exec>
       <flags> F </flags>
       <phase> witness-v0 </phase>
    requires #allTrue(EX)
     andBool hasFlag(F, FLAG_MINIMALIF)
     andBool lengthBytes(V) >Int 0
     andBool V =/=K Int2Bytes(1, 1, BE)

  rule <k> OP_NOTIF => #fail("MINIMALIF") ...</k>
       <stack> ListItem(V:Bytes) ST => ST </stack>
       <exec> EX </exec>
       <flags> F </flags>
       <phase> witness-v0 </phase>
    requires #allTrue(EX)
     andBool hasFlag(F, FLAG_MINIMALIF)
     andBool lengthBytes(V) >Int 0
     andBool V =/=K Int2Bytes(1, 1, BE)

  // OP_IF: pop top, push #isTruthy(top) onto <exec>
  // Exclude MINIMALIF violation (witness-v0 + flag + non-minimal value)
  rule <k> OP_IF => .K ...</k>
       <stack> ListItem(V:Bytes) ST => ST </stack>
       <exec> EX => ListItem(#isTruthy(V)) EX </exec>
       <flags> F </flags>
       <phase> PH </phase>
    requires #allTrue(EX)
     andBool notBool (PH ==K witness-v0 andBool hasFlag(F, FLAG_MINIMALIF)
                      andBool lengthBytes(V) >Int 0 andBool V =/=K Int2Bytes(1, 1, BE))

  // OP_NOTIF: pop top, push negation onto <exec>
  rule <k> OP_NOTIF => .K ...</k>
       <stack> ListItem(V:Bytes) ST => ST </stack>
       <exec> EX => ListItem(notBool #isTruthy(V)) EX </exec>
       <flags> F </flags>
       <phase> PH </phase>
    requires #allTrue(EX)
     andBool notBool (PH ==K witness-v0 andBool hasFlag(F, FLAG_MINIMALIF)
                      andBool lengthBytes(V) >Int 0 andBool V =/=K Int2Bytes(1, 1, BE))

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
  // OP_NOP: do nothing
  // =========================================================================

  rule <k> OP_NOP => .K ...</k>

  // =========================================================================
  // OP_CHECKLOCKTIMEVERIFY (BIP 65) — OP_NOP2 when flag not set
  // =========================================================================
  // When CHECKLOCKTIMEVERIFY flag is set: validate stack top against nLockTime.
  // Does NOT pop the stack value.

  // Flag not set: behave as NOP (with DISCOURAGE_UPGRADABLE_NOPS check)
  rule <k> OP_NOP2 => .K ...</k>
       <flags> F </flags>
    requires notBool hasFlag(F, FLAG_CHECKLOCKTIMEVERIFY)
     andBool notBool hasFlag(F, FLAG_DISCOURAGE_UPGRADABLE_NOPS)

  rule <k> OP_NOP2 => #fail("DISCOURAGE_UPGRADABLE_NOPS") ...</k>
       <flags> F </flags>
    requires notBool hasFlag(F, FLAG_CHECKLOCKTIMEVERIFY)
     andBool hasFlag(F, FLAG_DISCOURAGE_UPGRADABLE_NOPS)

  // SCRIPTNUM: CScriptNum validation with nMaxNumSize=5
  rule <k> OP_NOP2 => #fail("SCRIPTNUM") ...</k>
       <stack> ListItem(V:Bytes) _ST </stack>
       <flags> F </flags>
    requires hasFlag(F, FLAG_CHECKLOCKTIMEVERIFY)
     andBool (notBool validNum5(V) orBool (hasFlag(F, FLAG_MINIMALDATA) andBool notBool #isMinimalNum(V)))

  // NEGATIVE_LOCKTIME: stack top must be non-negative
  rule <k> OP_NOP2 => #fail("NEGATIVE_LOCKTIME") ...</k>
       <stack> ListItem(V:Bytes) _ST </stack>
       <flags> F </flags>
    requires hasFlag(F, FLAG_CHECKLOCKTIMEVERIFY)
     andBool validNum5(V) andBool (notBool hasFlag(F, FLAG_MINIMALDATA) orBool #isMinimalNum(V))
     andBool scriptNumToInt(V) <Int 0

  // UNSATISFIED_LOCKTIME: type mismatch (one >= 500000000, other < 500000000)
  rule <k> OP_NOP2 => #fail("UNSATISFIED_LOCKTIME") ...</k>
       <stack> ListItem(V:Bytes) _ST </stack>
       <flags> F </flags>
       <nLockTime> LT </nLockTime>
    requires hasFlag(F, FLAG_CHECKLOCKTIMEVERIFY)
     andBool validNum5(V) andBool (notBool hasFlag(F, FLAG_MINIMALDATA) orBool #isMinimalNum(V))
     andBool scriptNumToInt(V) >=Int 0
     andBool (  (scriptNumToInt(V) <Int 500000000 andBool LT >=Int 500000000)
         orBool (scriptNumToInt(V) >=Int 500000000 andBool LT <Int 500000000) )

  // UNSATISFIED_LOCKTIME: stack top > nLockTime
  rule <k> OP_NOP2 => #fail("UNSATISFIED_LOCKTIME") ...</k>
       <stack> ListItem(V:Bytes) _ST </stack>
       <flags> F </flags>
       <nLockTime> LT </nLockTime>
    requires hasFlag(F, FLAG_CHECKLOCKTIMEVERIFY)
     andBool validNum5(V) andBool (notBool hasFlag(F, FLAG_MINIMALDATA) orBool #isMinimalNum(V))
     andBool scriptNumToInt(V) >=Int 0
     andBool (  (scriptNumToInt(V) <Int 500000000 andBool LT <Int 500000000)
         orBool (scriptNumToInt(V) >=Int 500000000 andBool LT >=Int 500000000) )
     andBool scriptNumToInt(V) >Int LT

  // UNSATISFIED_LOCKTIME: input is finalized (nSequence == 0xFFFFFFFF)
  rule <k> OP_NOP2 => #fail("UNSATISFIED_LOCKTIME") ...</k>
       <stack> ListItem(V:Bytes) _ST </stack>
       <flags> F </flags>
       <nLockTime> LT </nLockTime>
       <nSequence> SEQ </nSequence>
    requires hasFlag(F, FLAG_CHECKLOCKTIMEVERIFY)
     andBool validNum5(V) andBool (notBool hasFlag(F, FLAG_MINIMALDATA) orBool #isMinimalNum(V))
     andBool scriptNumToInt(V) >=Int 0
     andBool scriptNumToInt(V) <=Int LT
     andBool (  (scriptNumToInt(V) <Int 500000000 andBool LT <Int 500000000)
         orBool (scriptNumToInt(V) >=Int 500000000 andBool LT >=Int 500000000) )
     andBool SEQ ==Int 4294967295

  // CLTV passes: all checks pass, continue (does NOT pop stack)
  rule <k> OP_NOP2 => .K ...</k>
       <stack> ListItem(V:Bytes) _ST </stack>
       <flags> F </flags>
       <nLockTime> LT </nLockTime>
       <nSequence> SEQ </nSequence>
    requires hasFlag(F, FLAG_CHECKLOCKTIMEVERIFY)
     andBool validNum5(V) andBool (notBool hasFlag(F, FLAG_MINIMALDATA) orBool #isMinimalNum(V))
     andBool scriptNumToInt(V) >=Int 0
     andBool scriptNumToInt(V) <=Int LT
     andBool (  (scriptNumToInt(V) <Int 500000000 andBool LT <Int 500000000)
         orBool (scriptNumToInt(V) >=Int 500000000 andBool LT >=Int 500000000) )
     andBool SEQ =/=Int 4294967295

  // =========================================================================
  // OP_CHECKSEQUENCEVERIFY (BIP 112) — OP_NOP3 when flag not set
  // =========================================================================
  // When CHECKSEQUENCEVERIFY flag is set: validate stack top against nSequence.
  // Does NOT pop the stack value.
  // Constants: SEQUENCE_LOCKTIME_DISABLE_FLAG = 1 << 31 = 2147483648
  //            SEQUENCE_LOCKTIME_TYPE_FLAG    = 1 << 22 = 4194304
  //            SEQUENCE_LOCKTIME_MASK         = 0x0000FFFF = 65535

  // Flag not set: behave as NOP (with DISCOURAGE_UPGRADABLE_NOPS check)
  rule <k> OP_NOP3 => .K ...</k>
       <flags> F </flags>
    requires notBool hasFlag(F, FLAG_CHECKSEQUENCEVERIFY)
     andBool notBool hasFlag(F, FLAG_DISCOURAGE_UPGRADABLE_NOPS)

  rule <k> OP_NOP3 => #fail("DISCOURAGE_UPGRADABLE_NOPS") ...</k>
       <flags> F </flags>
    requires notBool hasFlag(F, FLAG_CHECKSEQUENCEVERIFY)
     andBool hasFlag(F, FLAG_DISCOURAGE_UPGRADABLE_NOPS)

  // SCRIPTNUM: CScriptNum validation with nMaxNumSize=5
  rule <k> OP_NOP3 => #fail("SCRIPTNUM") ...</k>
       <stack> ListItem(V:Bytes) _ST </stack>
       <flags> F </flags>
    requires hasFlag(F, FLAG_CHECKSEQUENCEVERIFY)
     andBool (notBool validNum5(V) orBool (hasFlag(F, FLAG_MINIMALDATA) andBool notBool #isMinimalNum(V)))

  // NEGATIVE_LOCKTIME: stack top (as CScriptNum) is negative
  rule <k> OP_NOP3 => #fail("NEGATIVE_LOCKTIME") ...</k>
       <stack> ListItem(V:Bytes) _ST </stack>
       <flags> F </flags>
    requires hasFlag(F, FLAG_CHECKSEQUENCEVERIFY)
     andBool validNum5(V) andBool (notBool hasFlag(F, FLAG_MINIMALDATA) orBool #isMinimalNum(V))
     andBool scriptNumToInt(V) <Int 0

  // Disable flag set (bit 31 of the integer value): treat as NOP
  rule <k> OP_NOP3 => .K ...</k>
       <stack> ListItem(V:Bytes) _ST </stack>
       <flags> F </flags>
    requires hasFlag(F, FLAG_CHECKSEQUENCEVERIFY)
     andBool validNum5(V) andBool (notBool hasFlag(F, FLAG_MINIMALDATA) orBool #isMinimalNum(V))
     andBool scriptNumToInt(V) >=Int 0
     andBool scriptNumToInt(V) &Int 2147483648 =/=Int 0

  // UNSATISFIED_LOCKTIME: tx version < 2
  rule <k> OP_NOP3 => #fail("UNSATISFIED_LOCKTIME") ...</k>
       <stack> ListItem(V:Bytes) _ST </stack>
       <flags> F </flags>
       <txVersion> VER </txVersion>
    requires hasFlag(F, FLAG_CHECKSEQUENCEVERIFY)
     andBool validNum5(V) andBool (notBool hasFlag(F, FLAG_MINIMALDATA) orBool #isMinimalNum(V))
     andBool scriptNumToInt(V) >=Int 0
     andBool scriptNumToInt(V) &Int 2147483648 ==Int 0
     andBool VER <Int 2

  // UNSATISFIED_LOCKTIME: nSequence disable flag set (tx input opted out)
  rule <k> OP_NOP3 => #fail("UNSATISFIED_LOCKTIME") ...</k>
       <stack> ListItem(V:Bytes) _ST </stack>
       <flags> F </flags>
       <txVersion> VER </txVersion>
       <nSequence> SEQ </nSequence>
    requires hasFlag(F, FLAG_CHECKSEQUENCEVERIFY)
     andBool validNum5(V) andBool (notBool hasFlag(F, FLAG_MINIMALDATA) orBool #isMinimalNum(V))
     andBool scriptNumToInt(V) >=Int 0
     andBool scriptNumToInt(V) &Int 2147483648 ==Int 0
     andBool VER >=Int 2
     andBool SEQ &Int 2147483648 =/=Int 0

  // UNSATISFIED_LOCKTIME: type flag mismatch (one time-based, other block-based)
  rule <k> OP_NOP3 => #fail("UNSATISFIED_LOCKTIME") ...</k>
       <stack> ListItem(V:Bytes) _ST </stack>
       <flags> F </flags>
       <txVersion> VER </txVersion>
       <nSequence> SEQ </nSequence>
    requires hasFlag(F, FLAG_CHECKSEQUENCEVERIFY)
     andBool validNum5(V) andBool (notBool hasFlag(F, FLAG_MINIMALDATA) orBool #isMinimalNum(V))
     andBool scriptNumToInt(V) >=Int 0
     andBool scriptNumToInt(V) &Int 2147483648 ==Int 0
     andBool VER >=Int 2
     andBool SEQ &Int 2147483648 ==Int 0
     andBool (scriptNumToInt(V) &Int 4194304) =/=Int (SEQ &Int 4194304)

  // UNSATISFIED_LOCKTIME: masked value > masked nSequence
  rule <k> OP_NOP3 => #fail("UNSATISFIED_LOCKTIME") ...</k>
       <stack> ListItem(V:Bytes) _ST </stack>
       <flags> F </flags>
       <txVersion> VER </txVersion>
       <nSequence> SEQ </nSequence>
    requires hasFlag(F, FLAG_CHECKSEQUENCEVERIFY)
     andBool validNum5(V) andBool (notBool hasFlag(F, FLAG_MINIMALDATA) orBool #isMinimalNum(V))
     andBool scriptNumToInt(V) >=Int 0
     andBool scriptNumToInt(V) &Int 2147483648 ==Int 0
     andBool VER >=Int 2
     andBool SEQ &Int 2147483648 ==Int 0
     andBool (scriptNumToInt(V) &Int 4194304) ==Int (SEQ &Int 4194304)
     andBool (scriptNumToInt(V) &Int 4259839) >Int (SEQ &Int 4259839)

  // CSV passes: all checks pass
  rule <k> OP_NOP3 => .K ...</k>
       <stack> ListItem(V:Bytes) _ST </stack>
       <flags> F </flags>
       <txVersion> VER </txVersion>
       <nSequence> SEQ </nSequence>
    requires hasFlag(F, FLAG_CHECKSEQUENCEVERIFY)
     andBool validNum5(V) andBool (notBool hasFlag(F, FLAG_MINIMALDATA) orBool #isMinimalNum(V))
     andBool scriptNumToInt(V) >=Int 0
     andBool scriptNumToInt(V) &Int 2147483648 ==Int 0
     andBool VER >=Int 2
     andBool SEQ &Int 2147483648 ==Int 0
     andBool (scriptNumToInt(V) &Int 4194304) ==Int (SEQ &Int 4194304)
     andBool (scriptNumToInt(V) &Int 4259839) <=Int (SEQ &Int 4259839)

  // =========================================================================
  // OP_NOP1, OP_NOP4-OP_NOP10: pure no-ops (DISCOURAGE_UPGRADABLE_NOPS)
  // =========================================================================
  rule <k> OP_NOP1  => .K ...</k> <flags> F </flags> requires notBool hasFlag(F, FLAG_DISCOURAGE_UPGRADABLE_NOPS)
  rule <k> OP_NOP4  => .K ...</k> <flags> F </flags> requires notBool hasFlag(F, FLAG_DISCOURAGE_UPGRADABLE_NOPS)
  rule <k> OP_NOP5  => .K ...</k> <flags> F </flags> requires notBool hasFlag(F, FLAG_DISCOURAGE_UPGRADABLE_NOPS)
  rule <k> OP_NOP6  => .K ...</k> <flags> F </flags> requires notBool hasFlag(F, FLAG_DISCOURAGE_UPGRADABLE_NOPS)
  rule <k> OP_NOP7  => .K ...</k> <flags> F </flags> requires notBool hasFlag(F, FLAG_DISCOURAGE_UPGRADABLE_NOPS)
  rule <k> OP_NOP8  => .K ...</k> <flags> F </flags> requires notBool hasFlag(F, FLAG_DISCOURAGE_UPGRADABLE_NOPS)
  rule <k> OP_NOP9  => .K ...</k> <flags> F </flags> requires notBool hasFlag(F, FLAG_DISCOURAGE_UPGRADABLE_NOPS)
  rule <k> OP_NOP10 => .K ...</k> <flags> F </flags> requires notBool hasFlag(F, FLAG_DISCOURAGE_UPGRADABLE_NOPS)

  rule <k> OP_NOP1  => #fail("DISCOURAGE_UPGRADABLE_NOPS") ...</k> <flags> F </flags> requires hasFlag(F, FLAG_DISCOURAGE_UPGRADABLE_NOPS)
  rule <k> OP_NOP4  => #fail("DISCOURAGE_UPGRADABLE_NOPS") ...</k> <flags> F </flags> requires hasFlag(F, FLAG_DISCOURAGE_UPGRADABLE_NOPS)
  rule <k> OP_NOP5  => #fail("DISCOURAGE_UPGRADABLE_NOPS") ...</k> <flags> F </flags> requires hasFlag(F, FLAG_DISCOURAGE_UPGRADABLE_NOPS)
  rule <k> OP_NOP6  => #fail("DISCOURAGE_UPGRADABLE_NOPS") ...</k> <flags> F </flags> requires hasFlag(F, FLAG_DISCOURAGE_UPGRADABLE_NOPS)
  rule <k> OP_NOP7  => #fail("DISCOURAGE_UPGRADABLE_NOPS") ...</k> <flags> F </flags> requires hasFlag(F, FLAG_DISCOURAGE_UPGRADABLE_NOPS)
  rule <k> OP_NOP8  => #fail("DISCOURAGE_UPGRADABLE_NOPS") ...</k> <flags> F </flags> requires hasFlag(F, FLAG_DISCOURAGE_UPGRADABLE_NOPS)
  rule <k> OP_NOP9  => #fail("DISCOURAGE_UPGRADABLE_NOPS") ...</k> <flags> F </flags> requires hasFlag(F, FLAG_DISCOURAGE_UPGRADABLE_NOPS)
  rule <k> OP_NOP10 => #fail("DISCOURAGE_UPGRADABLE_NOPS") ...</k> <flags> F </flags> requires hasFlag(F, FLAG_DISCOURAGE_UPGRADABLE_NOPS)

  // =========================================================================
  // OP_VERIFY: pop top, continue if truthy, fail if falsy
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

endmodule
