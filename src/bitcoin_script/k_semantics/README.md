# k_semantics

Future K Framework integration for formal verification of Bitcoin Script semantics. Requires the `kframework` (pyk) package.

- `kore_bridge.py` — `KoreBridge` converts between Python interpreter state (`ScriptStack`, `Script`) and K's KORE term format, enabling comparison of Python execution against the formal K semantics.
- `definition.py` — `KDefinition` manages compiled K definitions: compiling `.k` source files with `kompile` and executing programs against the formal semantics via pyk.
