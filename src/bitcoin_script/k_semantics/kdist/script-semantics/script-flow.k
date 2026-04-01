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
  // OP_NOP: do nothing
  // =========================================================================

  rule <k> OP_NOP => .K ...</k>

  // OP_NOP1-NOP10: no-ops, but fail with DISCOURAGE_UPGRADABLE_NOPS flag
  rule <k> OP_NOP1  => .K ...</k> <flags> F </flags> requires notBool hasFlag(F, FLAG_DISCOURAGE_UPGRADABLE_NOPS)
  rule <k> OP_NOP2  => .K ...</k> <flags> F </flags> requires notBool hasFlag(F, FLAG_DISCOURAGE_UPGRADABLE_NOPS)
  rule <k> OP_NOP3  => .K ...</k> <flags> F </flags> requires notBool hasFlag(F, FLAG_DISCOURAGE_UPGRADABLE_NOPS)
  rule <k> OP_NOP4  => .K ...</k> <flags> F </flags> requires notBool hasFlag(F, FLAG_DISCOURAGE_UPGRADABLE_NOPS)
  rule <k> OP_NOP5  => .K ...</k> <flags> F </flags> requires notBool hasFlag(F, FLAG_DISCOURAGE_UPGRADABLE_NOPS)
  rule <k> OP_NOP6  => .K ...</k> <flags> F </flags> requires notBool hasFlag(F, FLAG_DISCOURAGE_UPGRADABLE_NOPS)
  rule <k> OP_NOP7  => .K ...</k> <flags> F </flags> requires notBool hasFlag(F, FLAG_DISCOURAGE_UPGRADABLE_NOPS)
  rule <k> OP_NOP8  => .K ...</k> <flags> F </flags> requires notBool hasFlag(F, FLAG_DISCOURAGE_UPGRADABLE_NOPS)
  rule <k> OP_NOP9  => .K ...</k> <flags> F </flags> requires notBool hasFlag(F, FLAG_DISCOURAGE_UPGRADABLE_NOPS)
  rule <k> OP_NOP10 => .K ...</k> <flags> F </flags> requires notBool hasFlag(F, FLAG_DISCOURAGE_UPGRADABLE_NOPS)

  rule <k> OP_NOP1  => #fail("DISCOURAGE_UPGRADABLE_NOPS") ...</k> <flags> F </flags> requires hasFlag(F, FLAG_DISCOURAGE_UPGRADABLE_NOPS)
  rule <k> OP_NOP2  => #fail("DISCOURAGE_UPGRADABLE_NOPS") ...</k> <flags> F </flags> requires hasFlag(F, FLAG_DISCOURAGE_UPGRADABLE_NOPS)
  rule <k> OP_NOP3  => #fail("DISCOURAGE_UPGRADABLE_NOPS") ...</k> <flags> F </flags> requires hasFlag(F, FLAG_DISCOURAGE_UPGRADABLE_NOPS)
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
