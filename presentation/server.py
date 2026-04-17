"""Lightweight API server for the Bitcoin Script REPL in the Slidev presentation.

Start with:
    uv run python presentation/server.py              # Python backend (default)
    uv run python presentation/server.py --backend k   # K Framework backend

Provides POST /execute endpoint that accepts ASM script strings
and returns stack/result.
"""

from __future__ import annotations

import argparse
import json
import mimetypes
import os
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

# Global state: active backend and K instance (lazy-loaded)
_active_backend: str = "python"
_k_instance: object | None = None  # KBitcoinScript, lazily loaded
_STATIC_DIR: Path | None = None  # Set to presentation/dist/ if it exists


def _get_k() -> object:
    """Lazy-load KBitcoinScript. Raises on failure."""
    global _k_instance
    if _k_instance is None:
        from bitcoin_script.k_semantics import KBitcoinScript

        _k_instance = KBitcoinScript()
    return _k_instance


class ReplHandler(BaseHTTPRequestHandler):
    """Handle REPL API requests."""

    def _cors_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _json_response(self, status: int, data: dict) -> None:
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self._cors_headers()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self._cors_headers()
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._json_response(
                200,
                {
                    "status": "ok",
                    "backend": _active_backend,
                    "backends": _available_backends(),
                },
            )
        elif _STATIC_DIR is not None:
            self._serve_static()
        else:
            self._json_response(404, {"error": "not found"})

    def _serve_static(self) -> None:
        """Serve static files from the Slidev build directory."""
        assert _STATIC_DIR is not None
        # Strip query string
        path = self.path.split("?")[0]

        # Map URL path to file
        if path == "/":
            path = "/index.html"

        file_path = _STATIC_DIR / path.lstrip("/")

        # SPA fallback: if the file doesn't exist, serve index.html
        # (Slidev uses client-side routing for /1, /2, etc.)
        if not file_path.is_file():
            file_path = _STATIC_DIR / "index.html"

        if not file_path.is_file():
            self._json_response(404, {"error": "not found"})
            return

        content_type, _ = mimetypes.guess_type(str(file_path))
        if content_type is None:
            content_type = "application/octet-stream"

        body = file_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self._cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        global _active_backend
        content_length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(content_length)

        try:
            body = json.loads(raw)
        except json.JSONDecodeError:
            self._json_response(400, {"error": "invalid JSON"})
            return

        if self.path == "/execute":
            asm_str = body.get("asm", "").strip()
            if not asm_str:
                self._json_response(400, {"error": "empty script"})
                return
            backend = body.get("backend", _active_backend)
            try:
                if backend == "k":
                    result = execute_asm_k(asm_str)
                else:
                    result = execute_asm_python(asm_str)
                result["backend"] = backend
                self._json_response(200, result)
            except Exception as e:
                self._json_response(500, {"error": str(e)})

        elif self.path == "/backend":
            new_backend = body.get("backend", "").strip()
            if new_backend not in ("python", "k"):
                self._json_response(400, {"error": f"unknown backend: {new_backend}"})
                return
            if new_backend == "k" and not _k_available():
                self._json_response(
                    400, {"error": "K backend not available (run kdist build first)"}
                )
                return
            _active_backend = new_backend
            self._json_response(200, {"backend": _active_backend})

        else:
            self._json_response(404, {"error": "not found"})

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        print(f"[repl-api] {args[0]}" if args else "")


# ---------------------------------------------------------------------------
# K backend availability check
# ---------------------------------------------------------------------------


def _k_available() -> bool:
    """Check if K Framework semantics are built."""
    try:
        from bitcoin_script.k_semantics.semantics import ScriptDist

        dist = ScriptDist.load()
        return (dist.llvm_dir / "compiled.json").exists()
    except Exception:
        return False


def _available_backends() -> list[str]:
    backends = ["python"]
    if _k_available():
        backends.append("k")
    return backends


# ---------------------------------------------------------------------------
# K backend execution
# ---------------------------------------------------------------------------


def execute_asm_k(asm: str) -> dict:
    """Execute an ASM script via K Framework formal semantics."""
    from bitcoin_script.asm import parse_asm

    try:
        raw_script = parse_asm(asm)
    except Exception as e:
        return {"error": f"Parse error: {e}", "result": "FAIL", "stack": []}

    try:
        k = _get_k()
        result = k.verify_script(script_pubkey=raw_script, flags=0)  # type: ignore[union-attr]

        err = k.error(result)  # type: ignore[union-attr]
        stuck = k.is_stuck(result)  # type: ignore[union-attr]
        stack_bytes = k.stack(result)  # type: ignore[union-attr]
        ok = k.success(result)  # type: ignore[union-attr]

        stack_items = [_format_item(s) for s in stack_bytes]

        if err:
            return {"error": err, "result": "FAIL", "stack": stack_items}
        if stuck:
            return {
                "error": "Execution stuck (pattern match failure)",
                "result": "FAIL",
                "stack": stack_items,
            }

        return {
            "result": "PASS" if ok else "FAIL",
            "stack": stack_items,
            "hex": raw_script.hex(),
            "size": len(raw_script),
        }
    except Exception as e:
        return {"error": f"K execution error: {e}", "result": "FAIL", "stack": []}


# ---------------------------------------------------------------------------
# Python backend execution
# ---------------------------------------------------------------------------


def execute_asm_python(asm: str) -> dict:
    """Execute an ASM script string via a simple stack machine.

    Uses a standalone interpreter to avoid engine bugs with CScript iteration.
    Supports arithmetic, stack ops, and basic flow control — enough for demos.
    """
    from bitcoin_script.asm import parse_asm

    try:
        raw_script = parse_asm(asm)
    except Exception as e:
        return {"error": f"Parse error: {e}", "result": "FAIL", "stack": []}

    from bitcoin.core.script import CScript, CScriptOp

    script = CScript(raw_script)
    stack: list[bytes] = []
    error = ""

    try:
        for opcode, data, _idx in script.raw_iter():
            if data is not None:
                stack.append(bytes(data))
                continue

            op = CScriptOp(opcode)
            name = str(op)

            # Number push opcodes: OP_0 through OP_16, OP_1NEGATE
            if opcode == 0x00:
                stack.append(b"")
            elif opcode == 0x4F:  # OP_1NEGATE
                stack.append(b"\x81")
            elif 0x51 <= opcode <= 0x60:  # OP_1..OP_16
                stack.append(bytes([opcode - 0x50]))
            elif name == "OP_ADD":
                b, a = _pop_int(stack), _pop_int(stack)
                stack.append(_encode_int(a + b))
            elif name == "OP_SUB":
                b, a = _pop_int(stack), _pop_int(stack)
                stack.append(_encode_int(a - b))
            elif name == "OP_MUL":
                b, a = _pop_int(stack), _pop_int(stack)
                stack.append(_encode_int(a * b))
            elif name == "OP_NEGATE":
                stack.append(_encode_int(-_pop_int(stack)))
            elif name == "OP_ABS":
                stack.append(_encode_int(abs(_pop_int(stack))))
            elif name == "OP_NOT":
                stack.append(_encode_int(1 if _pop_int(stack) == 0 else 0))
            elif name == "OP_0NOTEQUAL":
                stack.append(_encode_int(0 if _pop_int(stack) == 0 else 1))
            elif name == "OP_EQUAL":
                b, a = stack.pop(), stack.pop()
                stack.append(b"\x01" if a == b else b"")
            elif name == "OP_EQUALVERIFY":
                b, a = stack.pop(), stack.pop()
                if a != b:
                    raise ValueError("EQUALVERIFY failed")
            elif name == "OP_VERIFY":
                if not _is_truthy(stack.pop()):
                    raise ValueError("VERIFY failed")
            elif name == "OP_DUP":
                stack.append(stack[-1])
            elif name == "OP_DROP":
                stack.pop()
            elif name == "OP_2DUP":
                stack.append(stack[-2])
                stack.append(stack[-2])
            elif name == "OP_NIP":
                del stack[-2]
            elif name == "OP_OVER":
                stack.append(stack[-2])
            elif name == "OP_SWAP":
                stack[-1], stack[-2] = stack[-2], stack[-1]
            elif name == "OP_ROT":
                stack[-3], stack[-2], stack[-1] = stack[-2], stack[-1], stack[-3]
            elif name == "OP_DEPTH":
                stack.append(_encode_int(len(stack)))
            elif name == "OP_SIZE":
                stack.append(_encode_int(len(stack[-1])))
            elif name == "OP_RETURN":
                raise ValueError("OP_RETURN")
            elif name == "OP_NOP":
                pass
            elif name in (
                "OP_HASH160",
                "OP_HASH256",
                "OP_SHA256",
                "OP_SHA1",
                "OP_RIPEMD160",
            ):
                import hashlib

                val = stack.pop()
                if name == "OP_SHA256":
                    stack.append(hashlib.sha256(val).digest())
                elif name == "OP_SHA1":
                    stack.append(hashlib.sha1(val).digest())  # noqa: S324
                elif name == "OP_RIPEMD160":
                    stack.append(hashlib.new("ripemd160", val).digest())
                elif name == "OP_HASH160":
                    stack.append(
                        hashlib.new(
                            "ripemd160", hashlib.sha256(val).digest()
                        ).digest()
                    )
                elif name == "OP_HASH256":
                    stack.append(
                        hashlib.sha256(hashlib.sha256(val).digest()).digest()
                    )
            elif name in ("OP_NUMEQUAL", "OP_NUMEQUALVERIFY"):
                b, a = _pop_int(stack), _pop_int(stack)
                eq = a == b
                if name == "OP_NUMEQUALVERIFY" and not eq:
                    raise ValueError("NUMEQUALVERIFY failed")
                if name == "OP_NUMEQUAL":
                    stack.append(_encode_int(1 if eq else 0))
            elif name == "OP_LESSTHAN":
                b, a = _pop_int(stack), _pop_int(stack)
                stack.append(_encode_int(1 if a < b else 0))
            elif name == "OP_GREATERTHAN":
                b, a = _pop_int(stack), _pop_int(stack)
                stack.append(_encode_int(1 if a > b else 0))
            elif name == "OP_MIN":
                b, a = _pop_int(stack), _pop_int(stack)
                stack.append(_encode_int(min(a, b)))
            elif name == "OP_MAX":
                b, a = _pop_int(stack), _pop_int(stack)
                stack.append(_encode_int(max(a, b)))
            elif name == "OP_WITHIN":
                mx, mn, x = _pop_int(stack), _pop_int(stack), _pop_int(stack)
                stack.append(_encode_int(1 if mn <= x < mx else 0))
            else:
                error = f"Unsupported opcode: {name}"
                break
    except (IndexError, ValueError) as e:
        error = str(e) if str(e) else "stack underflow"

    stack_items = [_format_item(s) for s in stack]
    if error:
        return {"error": error, "result": "FAIL", "stack": stack_items}

    ok = len(stack) > 0 and _is_truthy(stack[-1])
    return {
        "result": "PASS" if ok else "FAIL",
        "stack": stack_items,
        "hex": raw_script.hex(),
        "size": len(raw_script),
    }


# ---------------------------------------------------------------------------
# CScriptNum helpers
# ---------------------------------------------------------------------------


def _decode_int(data: bytes) -> int:
    """Decode a CScriptNum-encoded byte string to int."""
    if len(data) == 0:
        return 0
    val = int.from_bytes(data[:-1] if len(data) > 1 else b"\x00", "little")
    val |= (data[-1] & 0x7F) << (8 * (len(data) - 1))
    if data[-1] & 0x80:
        val = -val
    return val


def _encode_int(n: int) -> bytes:
    """Encode an int as CScriptNum bytes."""
    if n == 0:
        return b""
    neg = n < 0
    n = abs(n)
    result = []
    while n > 0:
        result.append(n & 0xFF)
        n >>= 8
    if result[-1] & 0x80:
        result.append(0x80 if neg else 0x00)
    elif neg:
        result[-1] |= 0x80
    return bytes(result)


def _pop_int(stack: list[bytes]) -> int:
    return _decode_int(stack.pop())


def _is_truthy(data: bytes) -> bool:
    """Check if stack element is truthy (non-zero, ignoring negative zero)."""
    if len(data) == 0:
        return False
    for i, b in enumerate(data):
        if b != 0:
            if i == len(data) - 1 and b == 0x80:
                return False  # negative zero
            return True
    return False


def _format_item(elem: bytes) -> str:
    if len(elem) == 0:
        return "(empty)"
    if len(elem) <= 4:
        return f"0x{elem.hex()} ({_decode_int(elem)})"
    return f"0x{elem.hex()}"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(description="Bitcoin Script REPL API server")
    parser.add_argument(
        "--backend",
        choices=["python", "k"],
        default="python",
        help="Default execution backend (default: python)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("PORT", "8787")),
        help="Port to listen on (default: $PORT or 8787)",
    )
    args = parser.parse_args()

    global _active_backend, _STATIC_DIR
    _active_backend = args.backend

    # Serve static slides if dist/ exists
    dist_dir = Path(__file__).resolve().parent / "dist"
    if dist_dir.is_dir() and (dist_dir / "index.html").exists():
        _STATIC_DIR = dist_dir
        print(f"Serving static slides from {dist_dir}")
    else:
        print("No dist/ found — API-only mode (run 'npx slidev build' to enable)")

    if args.backend == "k":
        if not _k_available():
            print("Error: K semantics not built. Run: uv run kdist build --force")
            sys.exit(1)
        print("Loading K Framework semantics...")
        _get_k()  # pre-load
        print("K backend ready.")

    backends = _available_backends()
    server = HTTPServer(("0.0.0.0", args.port), ReplHandler)
    print(f"Bitcoin Script REPL API running on http://localhost:{args.port}")
    print(f"  Active backend: {_active_backend}")
    print(f"  Available backends: {', '.join(backends)}")
    print(f"  POST /execute  — execute ASM script")
    print(f"  POST /backend  — switch backend")
    print(f"  GET  /health   — health check")
    print()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.server_close()


if __name__ == "__main__":
    main()
