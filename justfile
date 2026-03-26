exclude := "src/bitcoin_script/k_semantics/kdist/plugin/deps"

# List available recipes
default:
    @just --list

# Run ruff formatter
format:
    ruff format --exclude '{{ exclude }}' src/ tests/

# Run ruff formatter (check only)
format-check:
    ruff format --check --exclude '{{ exclude }}' src/ tests/

# Run ruff linter with autofix
lint:
    ruff check --fix --exclude '{{ exclude }}' src/ tests/

# Run ruff linter (check only)
lint-check:
    ruff check --exclude '{{ exclude }}' src/ tests/

# Run pyright type checker
typecheck:
    pyright

# Run all checks (lint, format, typecheck)
check: lint-check format-check typecheck

# Run tests (excluding rpc and k markers)
test *args:
    pytest {{ args }}

# Run K Framework tests
test-k *args:
    pytest -m k {{ args }}

# Run all tests including K Framework
test-all *args:
    pytest -m '' {{ args }}

# Fix lint and format issues
fix: lint format
