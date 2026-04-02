// Formal proofs about Bitcoin Script arithmetic opcodes.
//
// These claims prove arithmetic properties for ALL valid CScriptNum
// inputs (4-byte signed integers, range -2^31+1 to 2^31-1) using
// the simplification lemmas in lemmas.k.

module ARITHMETIC-SPEC
  imports SCRIPT-SEMANTICS
  imports SCRIPT-SIG
  imports SCRIPT-FLOW
  imports SCRIPT-ARITH
  imports SCRIPT-STACK
  imports SCRIPT-DECODE
  imports LEMMAS

  // Proved: OP_1ADD produces N+1 for all valid N
  claim [1add-correct]:
      <k> OP_1ADD => .K ... </k>
      <stack> ListItem(intToScriptNum(N)) REST
           => ListItem(intToScriptNum(N +Int 1)) REST
      </stack>
      <flags> _F </flags>
    requires N >=Int -2147483647 andBool N <=Int 2147483647

  // Proved: OP_NEGATE produces -N for all valid N
  claim [negate-correct]:
      <k> OP_NEGATE => .K ... </k>
      <stack> ListItem(intToScriptNum(N)) REST
           => ListItem(intToScriptNum(0 -Int N)) REST
      </stack>
      <flags> _F </flags>
    requires N >=Int -2147483647 andBool N <=Int 2147483647

  // Proved: OP_ADD produces A+B for all valid A, B
  // Note: A is top of stack, B is second; result is A+B (top-first order)
  claim [add-correct]:
      <k> OP_ADD => .K ... </k>
      <stack> ListItem(intToScriptNum(A)) ListItem(intToScriptNum(B)) REST
           => ListItem(intToScriptNum(A +Int B)) REST
      </stack>
      <flags> _F </flags>
    requires A >=Int -2147483647 andBool A <=Int 2147483647
     andBool B >=Int -2147483647 andBool B <=Int 2147483647

endmodule
