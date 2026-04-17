# Bitcoin Script Presentation

Slidev presentation demoing the Bitcoin Script formal verification project.

## Prerequisites

- Node.js 18+
- Python 3.14 with `uv` (for the REPL backend)

## Quick Start

```bash
# Install JS dependencies (from presentation/ directory)
npm install

# Start the slide deck
npx slidev --open
```

This opens the slides at http://localhost:3030.

## Interactive REPL Backend

Slide 8 includes a live Bitcoin Script REPL. It works in two modes:

- **With backend** (full opcode support via the Python engine):

  ```bash
  # From the project root directory
  uv run python presentation/server.py
  ```

  The API server runs on http://localhost:8787. The REPL component auto-detects
  it and shows a green "K BACKEND" indicator.

- **Without backend** (client-side simulation for basic arithmetic/stack ops):

  The REPL falls back automatically if the backend isn't running, showing an
  amber "Local Sim" indicator. Good enough for simple demos like `OP_1 OP_2 OP_ADD`.

## API Endpoints

| Method | Path       | Description                          |
|--------|------------|--------------------------------------|
| GET    | `/health`  | Health check, returns backend status |
| POST   | `/execute` | Execute an ASM script string         |

Example:

```bash
curl -X POST http://localhost:8787/execute \
  -H 'Content-Type: application/json' \
  -d '{"asm": "OP_1 OP_2 OP_ADD"}'
```

## Slide Overview

| # | Title                    | Content                                       |
|---|--------------------------|-----------------------------------------------|
| 1 | Cover                    | Title, key stats                              |
| 2 | What is Bitcoin Script?  | Language overview + P2PKH example              |
| 3 | Why Formal Semantics?    | Problem statement + K Framework approach       |
| 4 | K Semantics Architecture | K configuration cell + module breakdown        |
| 5 | Test Coverage            | 1,217 script_tests, 133 tx_valid, 16 flags    |
| 6 | Benchmark                | 225K inputs, 0.64ms avg, 1.7x overhead        |
| 7 | CLI & Tooling            | Command reference + REPL session               |
| 8 | Live Demo                | Interactive REPL (Vue component + backend API) |
| 9 | Roadmap                  | Near-term + long-term goals                    |
| 10| Thank You                | GitHub link                                    |

## Presenter Mode

Press `P` during the presentation or navigate to http://localhost:3030/presenter
for presenter mode with notes and timer.

## Export to PDF

```bash
npm add -D playwright-chromium
npx slidev export
```
