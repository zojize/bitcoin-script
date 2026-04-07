exclude := "src/bitcoin_script/k_semantics/kdist/plugin/deps"

# List available recipes
default:
    @just --list

# Run ruff formatter
format:
    uv run ruff format --exclude '{{ exclude }}' src/ tests/

# Run ruff formatter (check only)
format-check:
    uv run ruff format --check --exclude '{{ exclude }}' src/ tests/

# Run ruff linter with autofix
lint:
    uv run ruff check --fix --exclude '{{ exclude }}' src/ tests/

# Run ruff linter (check only)
lint-check:
    uv run ruff check --exclude '{{ exclude }}' src/ tests/

# Run pyright type checker
typecheck:
    uv run pyright

# Run all checks (lint, format, typecheck)
check: lint-check format-check typecheck

# Run tests (excluding rpc and k markers)
test *args:
    uv run pytest {{ args }}

# Run K Framework tests (execution via LLVM)
test-k *args:
    uv run pytest -m k -k "not test_prove" {{ args }}

# Run K proof specs (verification via Haskell)
test-prove *args:
    uv run pytest tests/test_k_specs/ -m k {{ args }}

# Run all tests including K Framework
test-all *args:
    uv run pytest -m '' {{ args }}

# Fix lint and format issues
fix: lint format
