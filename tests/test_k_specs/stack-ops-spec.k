// Symbolic proofs about Bitcoin Script stack manipulation opcodes.
//
// Each claim proves that a stack opcode correctly transforms the stack
// for ALL possible byte values, using symbolic Bytes variables.

module STACK-OPS-SPEC
  imports SCRIPT-VERIFICATION

  // OP_SWAP: swap top two elements
  // [A, B, REST] -> [B, A, REST]
  claim [swap-correct]:
      <k> OP_SWAP => .K ... </k>
      <stack> ListItem(A:Bytes) ListItem(B:Bytes) REST
           => ListItem(B) ListItem(A) REST
      </stack>
      <flags> _F </flags>

  // OP_ROT: rotate top three elements
  // [C, B, A, REST] -> [A, C, B, REST]
  claim [rot-correct]:
      <k> OP_ROT => .K ... </k>
      <stack> ListItem(C:Bytes) ListItem(B:Bytes) ListItem(A:Bytes) REST
           => ListItem(A) ListItem(C) ListItem(B) REST
      </stack>
      <flags> _F </flags>

  // OP_OVER: copy second-to-top element to top
  // [A, B, REST] -> [B, A, B, REST]
  claim [over-correct]:
      <k> OP_OVER => .K ... </k>
      <stack> ListItem(A:Bytes) ListItem(B:Bytes) REST
           => ListItem(B) ListItem(A) ListItem(B) REST
      </stack>
      <flags> _F </flags>

  // OP_NIP: remove second-to-top element
  // [A, B, REST] -> [A, REST]
  claim [nip-correct]:
      <k> OP_NIP => .K ... </k>
      <stack> ListItem(A:Bytes) ListItem(_B:Bytes) REST
           => ListItem(A) REST
      </stack>
      <flags> _F </flags>

  // OP_TUCK: insert copy of top element before second
  // [A, B, REST] -> [A, B, A, REST]
  claim [tuck-correct]:
      <k> OP_TUCK => .K ... </k>
      <stack> ListItem(A:Bytes) ListItem(B:Bytes) REST
           => ListItem(A) ListItem(B) ListItem(A) REST
      </stack>
      <flags> _F </flags>

  // OP_TOALTSTACK ~> OP_FROMALTSTACK: roundtrip through altstack
  // Stack [V, REST] -> altstack -> back to [V, REST]
  claim [toalt-fromalt-roundtrip]:
      <k> OP_TOALTSTACK ~> OP_FROMALTSTACK => .K ... </k>
      <stack> ListItem(V:Bytes) REST
           => ListItem(V) REST
      </stack>
      <altstack> AST => AST </altstack>
      <flags> _F </flags>

endmodule
