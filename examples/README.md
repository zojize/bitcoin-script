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

## K proof specs (`specs/`)

K claims that can be mechanically verified by the Haskell backend prover
(`kprove`). See [specs/README.md](specs/README.md) for details.

Currently provable:
- `p2pkh-spec.k` — OP_DUP, EQUALVERIFY correctness (3 claims)
- `timelock-spec.k` — CLTV pass/NOP behavior (2 claims)

Blocked on byte-level simplification lemmas:
- `arithmetic-spec.k` — OP_ADD commutativity, OP_NEGATE identity
- `htlc-spec.k` — HTLC spending path correctness

See [specs/README.md](specs/README.md) for what's needed to unblock these.

## Running

```sh
cd examples
just              # list recipes
just all          # run all Python examples
just prove-all    # prove all K specs
just fuzz 500     # fuzz 500 scripts
```
