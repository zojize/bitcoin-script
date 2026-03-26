requires "script-semantics.k"
requires "script-stack.k"
requires "script-arith.k"

// Kompile entry point for Bitcoin Script.
module SCRIPT
  imports SCRIPT-SEMANTICS
  imports SCRIPT-STACK
  imports SCRIPT-ARITH
endmodule
