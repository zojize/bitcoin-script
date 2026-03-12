# engine

The script execution virtual machine. Takes raw scripts and evaluates them against a stack to produce pass/fail results.

- `stack.py` — `ScriptStack` with main and alt stacks. Handles Bitcoin's non-standard integer encoding (variable-length little-endian signed-magnitude) via `element_to_int`/`int_to_element` conversions.
- `engine.py` — `ScriptEngine`, the main interpreter. Runs `verify(script_sig, script_pubkey)` by executing scriptSig, copying the stack, then executing scriptPubKey. Manages IF/ELSE/ENDIF condition nesting and enforces size limits.
- `operations.py` — Opcode handler functions dispatched by the engine. Covers stack manipulation, arithmetic, equality, and crypto operations. Signature-checking ops receive transaction context.
- `flags.py` — `ScriptVerifyFlag` IntFlag enum mirroring Bitcoin Core's verification flags (P2SH, DERSIG, WITNESS, CLEANSTACK, etc.).
- `errors.py` — Exception hierarchy: `ScriptError` base with specific subtypes for stack underflow, disabled opcodes, size limits, verify failures, signature errors, and unbalanced conditionals.
