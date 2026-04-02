requires "script.k"
requires "lemmas.k"

// Kompile entry point for proofs (Haskell backend).
// Includes all execution semantics plus simplification lemmas.
module SCRIPT-VERIFICATION
  imports SCRIPT
  imports LEMMAS
endmodule
