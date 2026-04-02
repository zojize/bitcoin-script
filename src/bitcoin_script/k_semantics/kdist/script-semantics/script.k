requires "script-semantics.k"
requires "script-decode.k"
requires "script-flow.k"
requires "script-sig.k"
requires "script-stack.k"
requires "script-arith.k"

// Kompile entry point for Bitcoin Script (LLVM execution backend).
module SCRIPT
  imports SCRIPT-SEMANTICS
  imports SCRIPT-DECODE
  imports SCRIPT-FLOW
  imports SCRIPT-SIG
  imports SCRIPT-STACK
  imports SCRIPT-ARITH
endmodule
