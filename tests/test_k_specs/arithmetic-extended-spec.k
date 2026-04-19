// Extended symbolic proofs about Bitcoin Script arithmetic opcodes.
//
// Complements arithmetic-spec.k with OP_SUB, OP_ABS, OP_MIN, OP_MAX.
// All claims prove correctness for ALL valid CScriptNum inputs
// (4-byte signed integers, range -2^31+1 to 2^31-1).

module ARITHMETIC-EXTENDED-SPEC
  imports SCRIPT-VERIFICATION

  // Proved: OP_SUB produces A - B for all valid A, B
  // Stack order: B is top, A is second; result is A - B
  claim [sub-correct]:
      <k> OP_SUB => .K ... </k>
      <stack> ListItem(intToScriptNum(B)) ListItem(intToScriptNum(A)) REST
           => ListItem(intToScriptNum(A -Int B)) REST
      </stack>
      <flags> _F </flags>
    requires A >=Int -2147483647 andBool A <=Int 2147483647
     andBool B >=Int -2147483647 andBool B <=Int 2147483647

  // Proved: OP_ABS of non-negative N returns N unchanged
  claim [abs-positive]:
      <k> OP_ABS => .K ... </k>
      <stack> ListItem(intToScriptNum(N)) REST
           => ListItem(intToScriptNum(N)) REST
      </stack>
      <flags> _F </flags>
    requires N >=Int 0 andBool N <=Int 2147483647

  // Proved: OP_ABS of negative N returns -N (positive)
  claim [abs-negative]:
      <k> OP_ABS => .K ... </k>
      <stack> ListItem(intToScriptNum(N)) REST
           => ListItem(intToScriptNum(0 -Int N)) REST
      </stack>
      <flags> _F </flags>
    requires N >=Int -2147483647 andBool N <Int 0

  // Proved: OP_MIN returns the smaller of A and B
  claim [min-correct]:
      <k> OP_MIN => .K ... </k>
      <stack> ListItem(intToScriptNum(B)) ListItem(intToScriptNum(A)) REST
           => ListItem(intToScriptNum(minInt(A, B))) REST
      </stack>
      <flags> _F </flags>
    requires A >=Int -2147483647 andBool A <=Int 2147483647
     andBool B >=Int -2147483647 andBool B <=Int 2147483647

  // Proved: OP_MAX returns the larger of A and B
  claim [max-correct]:
      <k> OP_MAX => .K ... </k>
      <stack> ListItem(intToScriptNum(B)) ListItem(intToScriptNum(A)) REST
           => ListItem(intToScriptNum(maxInt(A, B))) REST
      </stack>
      <flags> _F </flags>
    requires A >=Int -2147483647 andBool A <=Int 2147483647
     andBool B >=Int -2147483647 andBool B <=Int 2147483647

endmodule
