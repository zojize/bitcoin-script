// Formal proofs about P2PKH (Pay-to-Public-Key-Hash) script behavior.
//
// P2PKH is the most common Bitcoin script type. These specs focus on
// structural properties and error paths that don't need signature verification.

module P2PKH-SPEC
  imports SCRIPT-SEMANTICS
  imports SCRIPT-SIG
  imports SCRIPT-FLOW
  imports SCRIPT-ARITH
  imports SCRIPT-STACK
  imports SCRIPT-DECODE

  // =========================================================================
  // Claim 1: OP_DUP duplicates the top stack element
  // =========================================================================

  claim [dup-duplicates-top]:
      <k> OP_DUP => .K ... </k>
      <stack> ListItem(V:Bytes) REST
           => ListItem(V) ListItem(V) REST
      </stack>

  // =========================================================================
  // Claim 2: EQUALVERIFY passes when top two elements are equal
  // =========================================================================

  claim [equalverify-pass]:
      <k> OP_EQUALVERIFY => .K ... </k>
      <stack> ListItem(V:Bytes) ListItem(V:Bytes) REST
           => REST
      </stack>

  // =========================================================================
  // Claim 3: EQUALVERIFY fails when top two elements differ
  // =========================================================================

  claim [equalverify-fail]:
      <k> OP_EQUALVERIFY => #fail("EQUALVERIFY") ... </k>
      <stack> ListItem(A:Bytes) ListItem(B:Bytes) REST => REST </stack>
    requires A =/=K B

endmodule
