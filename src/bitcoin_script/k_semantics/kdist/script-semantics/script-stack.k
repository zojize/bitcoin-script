requires "script-semantics.k"

// Stack manipulation opcodes for Bitcoin Script.
module SCRIPT-STACK
  imports SCRIPT-SEMANTICS
  imports LIST
  imports INT
  imports BYTES

  // =========================================================================
  // OP_DROP: remove top stack element
  // =========================================================================

  rule <k> OP_DROP => .K ...</k>
       <stack> ListItem(_) ST => ST </stack>

  // =========================================================================
  // OP_2DROP: remove top two stack elements
  // =========================================================================

  rule <k> OP_2DROP => .K ...</k>
       <stack> ListItem(_) ListItem(_) ST => ST </stack>

  // =========================================================================
  // OP_2DUP: duplicate top two stack elements
  // =========================================================================

  rule <k> OP_2DUP => .K ...</k>
       <stack> ListItem(A) ListItem(B) ST
            => ListItem(A) ListItem(B) ListItem(A) ListItem(B) ST </stack>

  // =========================================================================
  // OP_3DUP: duplicate top three stack elements
  // =========================================================================

  rule <k> OP_3DUP => .K ...</k>
       <stack> ListItem(A) ListItem(B) ListItem(C) ST
            => ListItem(A) ListItem(B) ListItem(C) ListItem(A) ListItem(B) ListItem(C) ST </stack>

  // =========================================================================
  // OP_NIP: remove second-to-top stack element
  // =========================================================================

  rule <k> OP_NIP => .K ...</k>
       <stack> ListItem(A) ListItem(_) ST => ListItem(A) ST </stack>

  // =========================================================================
  // OP_OVER: copy second-to-top element to top
  // =========================================================================

  rule <k> OP_OVER => .K ...</k>
       <stack> ListItem(A) ListItem(B) ST
            => ListItem(B) ListItem(A) ListItem(B) ST </stack>

  // =========================================================================
  // OP_2OVER: copy 3rd and 4th items to top
  // =========================================================================

  rule <k> OP_2OVER => .K ...</k>
       <stack> ListItem(A) ListItem(B) ListItem(C) ListItem(D) ST
            => ListItem(C) ListItem(D) ListItem(A) ListItem(B) ListItem(C) ListItem(D) ST </stack>

  // =========================================================================
  // OP_PICK: copy item N deep to top (0-indexed)
  // =========================================================================

  syntax KItem ::= "#pick" "(" Int "," List "," List ")"

  rule <k> OP_PICK => #pick(scriptNumToInt(N), .List, ST) ...</k>
       <stack> ListItem(N:Bytes) ST => .List </stack>
       <flags> FL </flags>
    requires validNumFlags(N, FL)

  // Found the item at depth 0
  rule <k> #pick(0, Skipped, ListItem(V) REST) => .K ...</k>
       <stack> _ => ListItem(V) Skipped ListItem(V) REST </stack>

  // Keep skipping
  rule <k> #pick(I, Skipped, ListItem(V) REST)
        => #pick(I -Int 1, Skipped ListItem(V), REST) ...</k>
    requires I >Int 0

  // =========================================================================
  // OP_ROLL: move item N deep to top (0-indexed)
  // =========================================================================

  syntax KItem ::= "#roll" "(" Int "," List "," List ")"

  rule <k> OP_ROLL => #roll(scriptNumToInt(N), .List, ST) ...</k>
       <stack> ListItem(N:Bytes) ST => .List </stack>
       <flags> FL </flags>
    requires validNumFlags(N, FL)

  // Found the item at depth 0 — remove from original position
  rule <k> #roll(0, Skipped, ListItem(V) REST) => .K ...</k>
       <stack> _ => ListItem(V) Skipped REST </stack>

  // Keep skipping
  rule <k> #roll(I, Skipped, ListItem(V) REST)
        => #roll(I -Int 1, Skipped ListItem(V), REST) ...</k>
    requires I >Int 0

  // =========================================================================
  // OP_ROT: rotate top three items (a b c -> b c a)
  // =========================================================================

  rule <k> OP_ROT => .K ...</k>
       <stack> ListItem(C) ListItem(B) ListItem(A) ST
            => ListItem(A) ListItem(C) ListItem(B) ST </stack>

  // =========================================================================
  // OP_2ROT: rotate top six items (a b c d e f -> c d e f a b)
  // =========================================================================

  rule <k> OP_2ROT => .K ...</k>
       <stack> ListItem(F) ListItem(E) ListItem(D) ListItem(C) ListItem(B) ListItem(A) ST
            => ListItem(B) ListItem(A) ListItem(F) ListItem(E) ListItem(D) ListItem(C) ST </stack>

  // =========================================================================
  // OP_SWAP: swap top two elements
  // =========================================================================

  rule <k> OP_SWAP => .K ...</k>
       <stack> ListItem(A) ListItem(B) ST => ListItem(B) ListItem(A) ST </stack>

  // =========================================================================
  // OP_2SWAP: swap top two pairs (a b c d -> c d a b)
  // =========================================================================

  rule <k> OP_2SWAP => .K ...</k>
       <stack> ListItem(D) ListItem(C) ListItem(B) ListItem(A) ST
            => ListItem(B) ListItem(A) ListItem(D) ListItem(C) ST </stack>

  // =========================================================================
  // OP_TUCK: insert copy of top element before second
  // =========================================================================

  rule <k> OP_TUCK => .K ...</k>
       <stack> ListItem(A) ListItem(B) ST
            => ListItem(A) ListItem(B) ListItem(A) ST </stack>

  // =========================================================================
  // OP_IFDUP: duplicate top if truthy
  // =========================================================================

  rule <k> OP_IFDUP => .K ...</k>
       <stack> ListItem(V:Bytes) ST => ListItem(V) ListItem(V) ST </stack>
    requires #isTruthy(V)

  rule <k> OP_IFDUP => .K ...</k>
       <stack> ListItem(V:Bytes) ST => ListItem(V) ST </stack>
    requires notBool #isTruthy(V)

  // =========================================================================
  // OP_DEPTH: push stack depth as CScriptNum
  // =========================================================================

  rule <k> OP_DEPTH => .K ...</k>
       <stack> ST => ListItem(intToScriptNum(size(ST))) ST </stack>

  // =========================================================================
  // OP_SIZE: push length of top element (without removing it)
  // =========================================================================

  rule <k> OP_SIZE => .K ...</k>
       <stack> ListItem(V:Bytes) ST
            => ListItem(intToScriptNum(lengthBytes(V))) ListItem(V) ST </stack>

  // =========================================================================
  // OP_TOALTSTACK: move top element to altstack
  // =========================================================================

  rule <k> OP_TOALTSTACK => .K ...</k>
       <stack> ListItem(V) ST => ST </stack>
       <altstack> AST => ListItem(V) AST </altstack>

  // =========================================================================
  // OP_FROMALTSTACK: move top of altstack to stack
  // =========================================================================

  rule <k> OP_FROMALTSTACK => .K ...</k>
       <stack> ST => ListItem(V) ST </stack>
       <altstack> ListItem(V) AST => AST </altstack>

endmodule
