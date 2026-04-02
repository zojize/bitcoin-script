requires "script-semantics.k"
requires "script-decode.k"
requires "script-flow.k"
requires "script-sig.k"
requires "script-stack.k"
requires "script-arith.k"
requires "lemmas.k"

// Kompile entry point for Bitcoin Script.
module SCRIPT
  imports SCRIPT-SEMANTICS
  imports SCRIPT-DECODE
  imports SCRIPT-FLOW
  imports SCRIPT-SIG
  imports SCRIPT-STACK
  imports SCRIPT-ARITH
  imports LEMMAS
endmodule
