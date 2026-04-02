// Formal proofs about Bitcoin Script arithmetic opcodes.
//
// Note: Symbolic claims over intToScriptNum (the CScriptNum encoding
// function) require byte-level lemmas that aren't yet defined. These
// claims are structurally correct but the Haskell backend prover gets
// stuck on byte reasoning without auxiliary lemmas.
//
// The claims below document the intended properties. Adding lemmas like:
//   rule intToScriptNum(A +Int B) ==K intToScriptNum(C)
//     requires C ==Int A +Int B [simplification]
// would enable these proofs.

module ARITHMETIC-SPEC
  imports SCRIPT-SEMANTICS
  imports SCRIPT-SIG
  imports SCRIPT-FLOW
  imports SCRIPT-ARITH
  imports SCRIPT-STACK
  imports SCRIPT-DECODE

  // OP_ADD is commutative: A + B == B + A
  // (requires intToScriptNum lemmas to prove)
  claim [add-commutative]:
      <k> OP_ADD => .K ... </k>
      <stack> ListItem(intToScriptNum(B)) ListItem(intToScriptNum(A)) REST
           => ListItem(intToScriptNum(A +Int B)) REST
      </stack>
    requires A >=Int -2147483647 andBool A <=Int 2147483647
     andBool B >=Int -2147483647 andBool B <=Int 2147483647

  // OP_1ADD: incrementing produces N+1
  claim [1add-correct]:
      <k> OP_1ADD => .K ... </k>
      <stack> ListItem(intToScriptNum(N)) REST
           => ListItem(intToScriptNum(N +Int 1)) REST
      </stack>
    requires N >=Int -2147483647 andBool N <=Int 2147483647

  // OP_NEGATE twice is identity
  claim [double-negate-identity]:
      <k> OP_NEGATE ~> OP_NEGATE => .K ... </k>
      <stack> ListItem(intToScriptNum(N)) REST
           => ListItem(intToScriptNum(N)) REST
      </stack>
    requires N >=Int -2147483647 andBool N <=Int 2147483647

endmodule
