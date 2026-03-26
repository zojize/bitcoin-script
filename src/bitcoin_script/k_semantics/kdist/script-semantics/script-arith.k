requires "script-semantics.k"

// Arithmetic, boolean, and comparison opcodes for Bitcoin Script.
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
       <stack> ListItem(V:Bytes) ST
            => ListItem(intToScriptNum(scriptNumToInt(V) +Int 1)) ST </stack>
       <exec> EX </exec>
    requires #allTrue(EX)

  // OP_1SUB: decrement top element
  rule <k> OP_1SUB => .K ...</k>
       <stack> ListItem(V:Bytes) ST
            => ListItem(intToScriptNum(scriptNumToInt(V) -Int 1)) ST </stack>
       <exec> EX </exec>
    requires #allTrue(EX)

  // OP_NEGATE: negate top element
  rule <k> OP_NEGATE => .K ...</k>
       <stack> ListItem(V:Bytes) ST
            => ListItem(intToScriptNum(0 -Int scriptNumToInt(V))) ST </stack>
       <exec> EX </exec>
    requires #allTrue(EX)

  // OP_ABS: absolute value of top element
  rule <k> OP_ABS => .K ...</k>
       <stack> ListItem(V:Bytes) ST
            => ListItem(intToScriptNum(absInt(scriptNumToInt(V)))) ST </stack>
       <exec> EX </exec>
    requires #allTrue(EX)

  // OP_NOT: boolean NOT (0 -> 1, nonzero -> 0)
  rule <k> OP_NOT => .K ...</k>
       <stack> ListItem(V:Bytes) ST
            => ListItem(intToScriptNum(1)) ST </stack>
       <exec> EX </exec>
    requires scriptNumToInt(V) ==Int 0
     andBool #allTrue(EX)

  rule <k> OP_NOT => .K ...</k>
       <stack> ListItem(V:Bytes) ST
            => ListItem(intToScriptNum(0)) ST </stack>
       <exec> EX </exec>
    requires scriptNumToInt(V) =/=Int 0
     andBool #allTrue(EX)

  // OP_0NOTEQUAL: (0 -> 0, nonzero -> 1)
  rule <k> OP_0NOTEQUAL => .K ...</k>
       <stack> ListItem(V:Bytes) ST
            => ListItem(intToScriptNum(0)) ST </stack>
       <exec> EX </exec>
    requires scriptNumToInt(V) ==Int 0
     andBool #allTrue(EX)

  rule <k> OP_0NOTEQUAL => .K ...</k>
       <stack> ListItem(V:Bytes) ST
            => ListItem(intToScriptNum(1)) ST </stack>
       <exec> EX </exec>
    requires scriptNumToInt(V) =/=Int 0
     andBool #allTrue(EX)

  // =========================================================================
  // Binary arithmetic opcodes (pop 2, push 1)
  // =========================================================================

  // OP_SUB: a - b (where b is top, a is second)
  rule <k> OP_SUB => .K ...</k>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) ST
            => ListItem(intToScriptNum(scriptNumToInt(A) -Int scriptNumToInt(B))) ST </stack>
       <exec> EX </exec>
    requires #allTrue(EX)

  // OP_BOOLAND: both nonzero -> 1, otherwise 0
  rule <k> OP_BOOLAND => .K ...</k>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) ST
            => ListItem(intToScriptNum(1)) ST </stack>
       <exec> EX </exec>
    requires scriptNumToInt(A) =/=Int 0 andBool scriptNumToInt(B) =/=Int 0
     andBool #allTrue(EX)

  rule <k> OP_BOOLAND => .K ...</k>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) ST
            => ListItem(intToScriptNum(0)) ST </stack>
       <exec> EX </exec>
    requires (scriptNumToInt(A) ==Int 0 orBool scriptNumToInt(B) ==Int 0)
     andBool #allTrue(EX)

  // OP_BOOLOR: either nonzero -> 1, both zero -> 0
  rule <k> OP_BOOLOR => .K ...</k>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) ST
            => ListItem(intToScriptNum(1)) ST </stack>
       <exec> EX </exec>
    requires (scriptNumToInt(A) =/=Int 0 orBool scriptNumToInt(B) =/=Int 0)
     andBool #allTrue(EX)

  rule <k> OP_BOOLOR => .K ...</k>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) ST
            => ListItem(intToScriptNum(0)) ST </stack>
       <exec> EX </exec>
    requires scriptNumToInt(A) ==Int 0 andBool scriptNumToInt(B) ==Int 0
     andBool #allTrue(EX)

  // OP_NUMEQUAL: push 1 if numerically equal, 0 otherwise
  rule <k> OP_NUMEQUAL => .K ...</k>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) ST
            => ListItem(intToScriptNum(1)) ST </stack>
       <exec> EX </exec>
    requires scriptNumToInt(A) ==Int scriptNumToInt(B)
     andBool #allTrue(EX)

  rule <k> OP_NUMEQUAL => .K ...</k>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) ST
            => ListItem(intToScriptNum(0)) ST </stack>
       <exec> EX </exec>
    requires scriptNumToInt(A) =/=Int scriptNumToInt(B)
     andBool #allTrue(EX)

  // OP_NUMNOTEQUAL: push 1 if not equal, 0 if equal
  rule <k> OP_NUMNOTEQUAL => .K ...</k>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) ST
            => ListItem(intToScriptNum(1)) ST </stack>
       <exec> EX </exec>
    requires scriptNumToInt(A) =/=Int scriptNumToInt(B)
     andBool #allTrue(EX)

  rule <k> OP_NUMNOTEQUAL => .K ...</k>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) ST
            => ListItem(intToScriptNum(0)) ST </stack>
       <exec> EX </exec>
    requires scriptNumToInt(A) ==Int scriptNumToInt(B)
     andBool #allTrue(EX)

  // OP_LESSTHAN: push 1 if a < b, 0 otherwise
  rule <k> OP_LESSTHAN => .K ...</k>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) ST
            => ListItem(intToScriptNum(1)) ST </stack>
       <exec> EX </exec>
    requires scriptNumToInt(A) <Int scriptNumToInt(B)
     andBool #allTrue(EX)

  rule <k> OP_LESSTHAN => .K ...</k>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) ST
            => ListItem(intToScriptNum(0)) ST </stack>
       <exec> EX </exec>
    requires scriptNumToInt(A) >=Int scriptNumToInt(B)
     andBool #allTrue(EX)

  // OP_GREATERTHAN: push 1 if a > b, 0 otherwise
  rule <k> OP_GREATERTHAN => .K ...</k>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) ST
            => ListItem(intToScriptNum(1)) ST </stack>
       <exec> EX </exec>
    requires scriptNumToInt(A) >Int scriptNumToInt(B)
     andBool #allTrue(EX)

  rule <k> OP_GREATERTHAN => .K ...</k>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) ST
            => ListItem(intToScriptNum(0)) ST </stack>
       <exec> EX </exec>
    requires scriptNumToInt(A) <=Int scriptNumToInt(B)
     andBool #allTrue(EX)

  // OP_LESSTHANOREQUAL: push 1 if a <= b, 0 otherwise
  rule <k> OP_LESSTHANOREQUAL => .K ...</k>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) ST
            => ListItem(intToScriptNum(1)) ST </stack>
       <exec> EX </exec>
    requires scriptNumToInt(A) <=Int scriptNumToInt(B)
     andBool #allTrue(EX)

  rule <k> OP_LESSTHANOREQUAL => .K ...</k>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) ST
            => ListItem(intToScriptNum(0)) ST </stack>
       <exec> EX </exec>
    requires scriptNumToInt(A) >Int scriptNumToInt(B)
     andBool #allTrue(EX)

  // OP_GREATERTHANOREQUAL: push 1 if a >= b, 0 otherwise
  rule <k> OP_GREATERTHANOREQUAL => .K ...</k>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) ST
            => ListItem(intToScriptNum(1)) ST </stack>
       <exec> EX </exec>
    requires scriptNumToInt(A) >=Int scriptNumToInt(B)
     andBool #allTrue(EX)

  rule <k> OP_GREATERTHANOREQUAL => .K ...</k>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) ST
            => ListItem(intToScriptNum(0)) ST </stack>
       <exec> EX </exec>
    requires scriptNumToInt(A) <Int scriptNumToInt(B)
     andBool #allTrue(EX)

  // OP_MIN: push the smaller of two values
  rule <k> OP_MIN => .K ...</k>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) ST
            => ListItem(intToScriptNum(minInt(scriptNumToInt(A), scriptNumToInt(B)))) ST </stack>
       <exec> EX </exec>
    requires #allTrue(EX)

  // OP_MAX: push the larger of two values
  rule <k> OP_MAX => .K ...</k>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) ST
            => ListItem(intToScriptNum(maxInt(scriptNumToInt(A), scriptNumToInt(B)))) ST </stack>
       <exec> EX </exec>
    requires #allTrue(EX)

  // =========================================================================
  // OP_NUMEQUALVERIFY: NUMEQUAL then VERIFY
  // =========================================================================

  rule <k> OP_NUMEQUALVERIFY => .K ...</k>
       <stack> ListItem(B:Bytes) ListItem(A:Bytes) ST => ST </stack>
       <exec> EX </exec>
    requires scriptNumToInt(A) ==Int scriptNumToInt(B)
     andBool #allTrue(EX)

  // Not equal: execution gets stuck (no rule matches)

  // =========================================================================
  // OP_WITHIN: (x min max -- out), true if min <= x < max
  // =========================================================================

  rule <k> OP_WITHIN => .K ...</k>
       <stack> ListItem(MAX:Bytes) ListItem(MIN:Bytes) ListItem(X:Bytes) ST
            => ListItem(intToScriptNum(1)) ST </stack>
       <exec> EX </exec>
    requires scriptNumToInt(X) >=Int scriptNumToInt(MIN)
     andBool scriptNumToInt(X) <Int scriptNumToInt(MAX)
     andBool #allTrue(EX)

  rule <k> OP_WITHIN => .K ...</k>
       <stack> ListItem(MAX:Bytes) ListItem(MIN:Bytes) ListItem(X:Bytes) ST
            => ListItem(intToScriptNum(0)) ST </stack>
       <exec> EX </exec>
    requires (scriptNumToInt(X) <Int scriptNumToInt(MIN)
      orBool scriptNumToInt(X) >=Int scriptNumToInt(MAX))
     andBool #allTrue(EX)

endmodule
