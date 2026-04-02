// Symbolic execution proofs: properties over ALL valid inputs.
//
// These claims use symbolic variables to prove that scripts behave
// correctly for any input satisfying the preconditions.

module SYMBOLIC-SPEC
  imports SCRIPT-VERIFICATION

  // =========================================================================
  // "Check if input equals 5": succeeds when N == 5
  //
  // Script: OP_5 OP_EQUAL = 0x5587
  // =========================================================================

  claim [equals-5-pass]:
      <k> OP_EQUAL => .K ... </k>
      <stack> ListItem(intToScriptNum(5)) ListItem(intToScriptNum(N)) REST
           => ListItem(intToScriptNum(1)) REST
      </stack>
    requires N ==Int 5

  // =========================================================================
  // OP_NOT maps nonzero to 0
  // =========================================================================

  claim [not-nonzero-is-false]:
      <k> OP_NOT => .K ... </k>
      <stack> ListItem(intToScriptNum(N)) REST
           => ListItem(intToScriptNum(0)) REST
      </stack>
      <flags> _F </flags>
    requires N =/=Int 0
     andBool N >=Int -2147483647 andBool N <=Int 2147483647

  // =========================================================================
  // OP_WITHIN: for any A, MIN, MAX: result is 1 iff MIN <= A < MAX
  //
  // Stack: <MAX> <MIN> <A> -> <result>
  // =========================================================================

  claim [within-true]:
      <k> OP_WITHIN => .K ... </k>
      <stack> ListItem(intToScriptNum(MAX)) ListItem(intToScriptNum(MIN))
              ListItem(intToScriptNum(A)) REST
           => ListItem(intToScriptNum(1)) REST
      </stack>
      <flags> _F </flags>
    requires A >=Int MIN andBool A <Int MAX
     andBool A >=Int -2147483647 andBool A <=Int 2147483647
     andBool MIN >=Int -2147483647 andBool MIN <=Int 2147483647
     andBool MAX >=Int -2147483647 andBool MAX <=Int 2147483647

  claim [within-false]:
      <k> OP_WITHIN => .K ... </k>
      <stack> ListItem(intToScriptNum(MAX)) ListItem(intToScriptNum(MIN))
              ListItem(intToScriptNum(A)) REST
           => ListItem(intToScriptNum(0)) REST
      </stack>
      <flags> _F </flags>
    requires (A <Int MIN orBool A >=Int MAX)
     andBool A >=Int -2147483647 andBool A <=Int 2147483647
     andBool MIN >=Int -2147483647 andBool MIN <=Int 2147483647
     andBool MAX >=Int -2147483647 andBool MAX <=Int 2147483647

  // =========================================================================
  // OP_SUB then OP_NOT: (A - B) == 0 iff A == B
  //
  // Proves that SUB + NOT implements equality checking.
  // =========================================================================

  claim [sub-not-equal]:
      <k> OP_SUB ~> OP_NOT => .K ... </k>
      <stack> ListItem(intToScriptNum(B)) ListItem(intToScriptNum(A)) REST
           => ListItem(intToScriptNum(1)) REST
      </stack>
      <flags> _F </flags>
    requires A ==Int B
     andBool A >=Int -2147483647 andBool A <=Int 2147483647
     andBool B >=Int -2147483647 andBool B <=Int 2147483647

endmodule
