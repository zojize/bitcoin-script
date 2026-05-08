requires "script-semantics.k"

// Arithmetic, boolean, and comparison opcodes for Bitcoin Script.
// All opcodes enforce the 4-byte CScriptNum input limit via validNum() guards.
// If an input exceeds 4 bytes, no rule matches and execution gets stuck (= script error).
module SCRIPT-ARITH
  imports SCRIPT-SEMANTICS
  imports INT
  imports BYTES
  imports BOOL

  // =========================================================================
  // Unary arithmetic opcodes (pop 1, push 1)
  // =========================================================================

  // OP_1ADD: increment top element
  rule <k> OP_1ADD => .K ...</k>
       <flags> F </flags>
       <stack> ListItem(V:Bytes) ST
            => ListItem(intToScriptNum(scriptNumToInt(V) +Int 1)) ST </stack>
    requires validNumFlags(V, F)
  rule <k> OP_1ADD => #fail(#numError(V, F)) ...</k>
       <flags> F </flags>
       <stack> ListItem(V:Bytes) _ST </stack>
    requires notBool validNumFlags(V, F)

  // OP_1SUB: decrement top element
  rule <k> OP_1SUB => .K ...</k>
       <flags> F </flags>
       <stack> ListItem(V:Bytes) ST
            => ListItem(intToScriptNum(scriptNumToInt(V) -Int 1)) ST </stack>
    requires validNumFlags(V, F)
  rule <k> OP_1SUB => #fail(#numError(V, F)) ...</k>
       <flags> F </flags>
       <stack> ListItem(V:Bytes) _ST </stack>
    requires notBool validNumFlags(V, F)

  // OP_NEGATE: negate top element
  rule <k> OP_NEGATE => .K ...</k>
       <flags> F </flags>
       <stack> ListItem(V:Bytes) ST
            => ListItem(intToScriptNum(0 -Int scriptNumToInt(V))) ST </stack>
    requires validNumFlags(V, F)
  rule <k> OP_NEGATE => #fail(#numError(V, F)) ...</k>
       <flags> F </flags>
       <stack> ListItem(V:Bytes) _ST </stack>
    requires notBool validNumFlags(V, F)

  // OP_ABS: absolute value of top element
  rule <k> OP_ABS => .K ...</k>
       <flags> F </flags>
       <stack> ListItem(V:Bytes) ST
            => ListItem(intToScriptNum(absInt(scriptNumToInt(V)))) ST </stack>
    requires validNumFlags(V, F)
  rule <k> OP_ABS => #fail(#numError(V, F)) ...</k>
       <flags> F </flags>
       <stack> ListItem(V:Bytes) _ST </stack>
    requires notBool validNumFlags(V, F)

  // OP_NOT: boolean NOT (0 -> 1, nonzero -> 0)
  rule <k> OP_NOT => .K ...</k>
       <flags> F </flags>
       <stack> ListItem(V:Bytes) ST
            => ListItem(#boolToBytes(scriptNumToInt(V) ==Int 0)) ST </stack>
    requires validNumFlags(V, F)
  rule <k> OP_NOT => #fail(#numError(V, F)) ...</k>
       <flags> F </flags>
       <stack> ListItem(V:Bytes) _ST </stack>
    requires notBool validNumFlags(V, F)

  // OP_0NOTEQUAL: (0 -> 0, nonzero -> 1)
  rule <k> OP_0NOTEQUAL => .K ...</k>
       <flags> F </flags>
       <stack> ListItem(V:Bytes) ST
            => ListItem(#boolToBytes(scriptNumToInt(V) =/=Int 0)) ST </stack>
    requires validNumFlags(V, F)
  rule <k> OP_0NOTEQUAL => #fail(#numError(V, F)) ...</k>
       <flags> F </flags>
       <stack> ListItem(V:Bytes) _ST </stack>
    requires notBool validNumFlags(V, F)

  // =========================================================================
  // Binary arithmetic opcodes (pop 2, push 1)
  // =========================================================================

  // OP_ADD: a + b (b is top, a is second)
  rule <k> OP_ADD => .K ...</k>
       <flags> F </flags>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) ST
            => ListItem(intToScriptNum(scriptNumToInt(A) +Int scriptNumToInt(B))) ST </stack>
    requires validNumFlags(A, F) andBool validNumFlags(B, F)
  rule <k> OP_ADD => #fail(#numError2(A, B, F)) ...</k>
       <flags> F </flags>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) _ST </stack>
    requires notBool (validNumFlags(A, F) andBool validNumFlags(B, F))

  // OP_SUB: a - b (where b is top, a is second)
  rule <k> OP_SUB => .K ...</k>
       <flags> F </flags>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) ST
            => ListItem(intToScriptNum(scriptNumToInt(A) -Int scriptNumToInt(B))) ST </stack>
    requires validNumFlags(A, F) andBool validNumFlags(B, F)
  rule <k> OP_SUB => #fail(#numError2(A, B, F)) ...</k>
       <flags> F </flags>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) _ST </stack>
    requires notBool (validNumFlags(A, F) andBool validNumFlags(B, F))

  // OP_BOOLAND: both nonzero -> 1, otherwise 0
  rule <k> OP_BOOLAND => .K ...</k>
       <flags> F </flags>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) ST
            => ListItem(#boolToBytes(
                 scriptNumToInt(A) =/=Int 0 andBool scriptNumToInt(B) =/=Int 0
               )) ST </stack>
    requires validNumFlags(A, F) andBool validNumFlags(B, F)
  rule <k> OP_BOOLAND => #fail(#numError2(A, B, F)) ...</k>
       <flags> F </flags>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) _ST </stack>
    requires notBool (validNumFlags(A, F) andBool validNumFlags(B, F))

  // OP_BOOLOR: either nonzero -> 1, both zero -> 0
  rule <k> OP_BOOLOR => .K ...</k>
       <flags> F </flags>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) ST
            => ListItem(#boolToBytes(
                 scriptNumToInt(A) =/=Int 0 orBool scriptNumToInt(B) =/=Int 0
               )) ST </stack>
    requires validNumFlags(A, F) andBool validNumFlags(B, F)
  rule <k> OP_BOOLOR => #fail(#numError2(A, B, F)) ...</k>
       <flags> F </flags>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) _ST </stack>
    requires notBool (validNumFlags(A, F) andBool validNumFlags(B, F))

  // OP_NUMEQUAL: push 1 if numerically equal, 0 otherwise
  rule <k> OP_NUMEQUAL => .K ...</k>
       <flags> F </flags>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) ST
            => ListItem(#boolToBytes(scriptNumToInt(A) ==Int scriptNumToInt(B))) ST </stack>
    requires validNumFlags(A, F) andBool validNumFlags(B, F)
  rule <k> OP_NUMEQUAL => #fail(#numError2(A, B, F)) ...</k>
       <flags> F </flags>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) _ST </stack>
    requires notBool (validNumFlags(A, F) andBool validNumFlags(B, F))

  // OP_NUMNOTEQUAL: push 1 if not equal, 0 if equal
  rule <k> OP_NUMNOTEQUAL => .K ...</k>
       <flags> F </flags>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) ST
            => ListItem(#boolToBytes(scriptNumToInt(A) =/=Int scriptNumToInt(B))) ST </stack>
    requires validNumFlags(A, F) andBool validNumFlags(B, F)
  rule <k> OP_NUMNOTEQUAL => #fail(#numError2(A, B, F)) ...</k>
       <flags> F </flags>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) _ST </stack>
    requires notBool (validNumFlags(A, F) andBool validNumFlags(B, F))

  // OP_LESSTHAN: push 1 if a < b, 0 otherwise
  rule <k> OP_LESSTHAN => .K ...</k>
       <flags> F </flags>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) ST
            => ListItem(#boolToBytes(scriptNumToInt(A) <Int scriptNumToInt(B))) ST </stack>
    requires validNumFlags(A, F) andBool validNumFlags(B, F)
  rule <k> OP_LESSTHAN => #fail(#numError2(A, B, F)) ...</k>
       <flags> F </flags>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) _ST </stack>
    requires notBool (validNumFlags(A, F) andBool validNumFlags(B, F))

  // OP_GREATERTHAN: push 1 if a > b, 0 otherwise
  rule <k> OP_GREATERTHAN => .K ...</k>
       <flags> F </flags>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) ST
            => ListItem(#boolToBytes(scriptNumToInt(A) >Int scriptNumToInt(B))) ST </stack>
    requires validNumFlags(A, F) andBool validNumFlags(B, F)
  rule <k> OP_GREATERTHAN => #fail(#numError2(A, B, F)) ...</k>
       <flags> F </flags>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) _ST </stack>
    requires notBool (validNumFlags(A, F) andBool validNumFlags(B, F))

  // OP_LESSTHANOREQUAL: push 1 if a <= b, 0 otherwise
  rule <k> OP_LESSTHANOREQUAL => .K ...</k>
       <flags> F </flags>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) ST
            => ListItem(#boolToBytes(scriptNumToInt(A) <=Int scriptNumToInt(B))) ST </stack>
    requires validNumFlags(A, F) andBool validNumFlags(B, F)
  rule <k> OP_LESSTHANOREQUAL => #fail(#numError2(A, B, F)) ...</k>
       <flags> F </flags>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) _ST </stack>
    requires notBool (validNumFlags(A, F) andBool validNumFlags(B, F))

  // OP_GREATERTHANOREQUAL: push 1 if a >= b, 0 otherwise
  rule <k> OP_GREATERTHANOREQUAL => .K ...</k>
       <flags> F </flags>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) ST
            => ListItem(#boolToBytes(scriptNumToInt(A) >=Int scriptNumToInt(B))) ST </stack>
    requires validNumFlags(A, F) andBool validNumFlags(B, F)
  rule <k> OP_GREATERTHANOREQUAL => #fail(#numError2(A, B, F)) ...</k>
       <flags> F </flags>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) _ST </stack>
    requires notBool (validNumFlags(A, F) andBool validNumFlags(B, F))

  // OP_MIN: push the smaller of two values
  rule <k> OP_MIN => .K ...</k>
       <flags> F </flags>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) ST
            => ListItem(intToScriptNum(minInt(scriptNumToInt(A), scriptNumToInt(B)))) ST </stack>
    requires validNumFlags(A, F) andBool validNumFlags(B, F)
  rule <k> OP_MIN => #fail(#numError2(A, B, F)) ...</k>
       <flags> F </flags>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) _ST </stack>
    requires notBool (validNumFlags(A, F) andBool validNumFlags(B, F))

  // OP_MAX: push the larger of two values
  rule <k> OP_MAX => .K ...</k>
       <flags> F </flags>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) ST
            => ListItem(intToScriptNum(maxInt(scriptNumToInt(A), scriptNumToInt(B)))) ST </stack>
    requires validNumFlags(A, F) andBool validNumFlags(B, F)
  rule <k> OP_MAX => #fail(#numError2(A, B, F)) ...</k>
       <flags> F </flags>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) _ST </stack>
    requires notBool (validNumFlags(A, F) andBool validNumFlags(B, F))

  // =========================================================================
  // OP_NUMEQUALVERIFY: NUMEQUAL then VERIFY
  // =========================================================================

  rule <k> OP_NUMEQUALVERIFY => .K ...</k>
       <flags> F </flags>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) ST => ST </stack>
    requires validNumFlags(A, F) andBool validNumFlags(B, F)
     andBool scriptNumToInt(A) ==Int scriptNumToInt(B)

  rule <k> OP_NUMEQUALVERIFY => #fail("NUMEQUALVERIFY") ...</k>
       <flags> F </flags>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) ST => ST </stack>
    requires validNumFlags(A, F) andBool validNumFlags(B, F)
     andBool scriptNumToInt(A) =/=Int scriptNumToInt(B)

  rule <k> OP_NUMEQUALVERIFY => #fail(#numError2(A, B, F)) ...</k>
       <flags> F </flags>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) _ST </stack>
    requires notBool (validNumFlags(A, F) andBool validNumFlags(B, F))

  // =========================================================================
  // OP_WITHIN: (x min max -- out), true if min <= x < max
  // =========================================================================

  rule <k> OP_WITHIN => .K ...</k>
       <flags> F </flags>
       <stack> ListItem(MAX:Bytes) ListItem(MIN:Bytes) ListItem(X:Bytes) ST
            => ListItem(#boolToBytes(
                 scriptNumToInt(X) >=Int scriptNumToInt(MIN)
                   andBool scriptNumToInt(X) <Int scriptNumToInt(MAX)
               )) ST </stack>
    requires validNumFlags(X, F) andBool validNumFlags(MIN, F) andBool validNumFlags(MAX, F)
  rule <k> OP_WITHIN => #fail(#numError3(X, MIN, MAX, F)) ...</k>
       <flags> F </flags>
       <stack> ListItem(MAX:Bytes) ListItem(MIN:Bytes) ListItem(X:Bytes) _ST </stack>
    requires notBool (validNumFlags(X, F) andBool validNumFlags(MIN, F) andBool validNumFlags(MAX, F))

endmodule
