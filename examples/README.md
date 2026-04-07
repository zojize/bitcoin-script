# Examples

Demonstrations of what formal K semantics uniquely enable — things you
can't do (or can't trust) with just an interpreter.

## Python examples

### `fuzz_scripts.py` — Differential fuzzing with a formal oracle

Generate random Bitcoin Scripts and run them through the K semantics to
build ground-truth results. Any alternative interpreter that disagrees
with K on any input has a consensus bug.

This is uniquely valuable because K gives you an independent, formally
derived reference — the only other option is Bitcoin Core's C++ code,
which is an implementation, not a specification.

```sh
uv run python examples/fuzz_scripts.py 200       # 200 random scripts
uv run python examples/fuzz_scripts.py 1000 123  # 1000 scripts, seed 123
```

### `trace_execution.py` — Full formal state at each rewrite step

K's bounded execution (`depth=N`) exposes the complete formal
configuration at each rewrite step: stack, altstack, execution guard
stack, phase, flags, opcount, error state. This isn't just "stepping
through" like a debugger — it's the full term being rewritten.

```sh
uv run python examples/trace_execution.py
```

### `verify_block.py` — Mainnet verification against formal semantics

Replay real Bitcoin blocks through the K semantics. Every transaction
input's script execution is formally verified — confirming the K model
agrees with Bitcoin's actual consensus history.

```sh
uv run python examples/verify_block.py 170       # block 170 (first real tx)
uv run python examples/verify_block.py 170 180   # range
```

## K proof specs

Formal verification specs live in `tests/test_k_specs/` and run via
pytest in CI. See [tests/test_k_specs/README.md](../tests/test_k_specs/README.md).

## Running

```sh
cd examples
just              # list recipes
just all          # run all Python examples
just prove-all    # prove K specs via pytest
just fuzz 500     # fuzz 500 scripts
```
