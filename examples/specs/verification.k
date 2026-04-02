// Shared imports for Bitcoin Script verification specs.
// All spec modules should import this module.
//
// No `requires` needed — kprove resolves modules from the compiled definition
// passed via --definition.

module BITCOIN-SCRIPT-VERIFICATION
  imports SCRIPT-SEMANTICS
  imports SCRIPT-SIG
  imports SCRIPT-FLOW
  imports SCRIPT-ARITH
  imports SCRIPT-STACK
  imports SCRIPT-DECODE
endmodule
