from __future__ import annotations

import ctypes
import logging
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from collections.abc import Callable
from typing import final, Final

from pyk.kast.outer import KDefinition
from pyk.kore.syntax import DV, App, Pattern, String

_LOGGER: Final = logging.getLogger(__name__)


class _KRuntime:
    """Thin ctypes wrapper around interpreter.dylib (llvm-lib target).

    Calls the same compiled LLVM code that the subprocess interpreter uses,
    but via direct FFI — no process spawn, no pybind11 wrappers.
    """

    def __init__(self, lib_path: Path) -> None:
        self._lib = ctypes.CDLL(str(lib_path))
        self._define_api()
        self._lib.init_static_objects()

    def _define_api(self) -> None:
        L = self._lib
        L.init_static_objects.restype = None
        L.init_static_objects.argtypes = []
        L.kore_pattern_parse.restype = ctypes.c_void_p
        L.kore_pattern_parse.argtypes = [ctypes.c_char_p]
        L.kore_pattern_construct.restype = ctypes.c_void_p
        L.kore_pattern_construct.argtypes = [ctypes.c_void_p]
        L.take_steps.restype = ctypes.c_void_p
        L.take_steps.argtypes = [ctypes.c_int64, ctypes.c_void_p]
        L.kore_pattern_from_block.restype = ctypes.c_void_p
        L.kore_pattern_from_block.argtypes = [ctypes.c_void_p]
        L.kore_pattern_dump.restype = ctypes.c_char_p
        L.kore_pattern_dump.argtypes = [ctypes.c_void_p]
        L.kore_pattern_free.restype = None
        L.kore_pattern_free.argtypes = [ctypes.c_void_p]
        L.free_all_kore_mem.restype = None
        L.free_all_kore_mem.argtypes = []

    def run(self, kore_text: str, *, depth: int = -1) -> str:
        """Parse KORE text, execute, return result KORE text."""
        parsed = self._lib.kore_pattern_parse(kore_text.encode("utf-8"))
        block = self._lib.kore_pattern_construct(parsed)
        result_block = self._lib.take_steps(depth, block)
        result_pat = self._lib.kore_pattern_from_block(result_block)
        result_bytes: bytes = self._lib.kore_pattern_dump(result_pat)
        self._lib.kore_pattern_free(parsed)
        self._lib.kore_pattern_free(result_pat)
        self._lib.free_all_kore_mem()
        return result_bytes.decode("utf-8")


@final
@dataclass(frozen=True)
class ScriptDist:
    """Locate compiled K definition artifacts for Bitcoin Script."""

    source_dir: Path
    llvm_dir: Path
    llvm_lib_dir: Path

    def __init__(
        self,
        *,
        source_dir: str | Path,
        llvm_dir: str | Path,
        llvm_lib_dir: str | Path,
    ) -> None:
        from pyk.utils import check_dir_path

        for name, val in [
            ("source_dir", source_dir),
            ("llvm_dir", llvm_dir),
            ("llvm_lib_dir", llvm_lib_dir),
        ]:
            path = Path(val)
            check_dir_path(path)
            object.__setattr__(self, name, path)

    @staticmethod
    def load() -> ScriptDist:
        ScriptDist._rebuild_if_stale()
        return ScriptDist(
            source_dir=ScriptDist._find("source"),
            llvm_dir=ScriptDist._find("llvm"),
            llvm_lib_dir=ScriptDist._find("llvm-lib"),
        )

    @staticmethod
    def _rebuild_if_stale() -> None:
        """Rebuild K artifacts if .k source files are newer than the compiled output."""
        import subprocess

        src_dir = Path(__file__).parent / "kdist" / "script-semantics"
        k_sources = list(src_dir.rglob("*.k"))
        if not k_sources:
            return

        needs_rebuild = False
        try:
            from pyk.kdist import kdist  # pyright: ignore[reportPrivateImportUsage]

            llvm_dir = kdist.get("bitcoin-script-semantics.llvm")
            compiled = llvm_dir / "compiled.bin"
            if not compiled.exists():
                needs_rebuild = True
            else:
                newest_source = max(f.stat().st_mtime for f in k_sources)
                needs_rebuild = newest_source > compiled.stat().st_mtime
        except Exception:
            needs_rebuild = True

        if not needs_rebuild:
            return

        _LOGGER.info("K source files changed, rebuilding...")
        subprocess.run(
            [
                "kdist",
                "build",
                "--force",
                "bitcoin-script-semantics.source",
                "bitcoin-script-semantics.llvm",
            ],
            check=True,
        )

    @staticmethod
    def _find(target: str) -> Path:
        """Find a kdist target via env var or pyk.kdist.

        Checks BTC_SCRIPT_K_<TARGET>_DIR first, then falls back to kdist.
        """
        from os import getenv

        from pyk.utils import check_dir_path
        from pyk.kdist import kdist  # pyright: ignore[reportPrivateImportUsage]

        env_dir = getenv(f"BTC_SCRIPT_K_{target.replace('-', '_').upper()}_DIR")
        if env_dir:
            path = Path(env_dir)
            check_dir_path(path)
            _LOGGER.info(f"Using target at {path}")
            return path

        return kdist.get(f"bitcoin-script-semantics.{target}")


@final
@dataclass(frozen=True)
class KBitcoinScript:
    """Main interface for K-Python communication for Bitcoin Script.

    All scripts are passed as raw bytes via config variables.
    The K semantics handles multi-phase execution (scriptSig -> scriptPubKey -> P2SH redeem).
    """

    dist: ScriptDist

    def __init__(self, dist: ScriptDist | None = None) -> None:
        if dist is None:
            dist = ScriptDist.load()
        object.__setattr__(self, "dist", dist)

    @cached_property
    def definition(self) -> KDefinition:
        from pyk.kast.outer import read_kast_definition

        return read_kast_definition(self.dist.llvm_dir / "compiled.json")

    @cached_property
    def _runtime(self) -> _KRuntime | None:
        """Load the FFI runtime from interpreter.dylib, or None if unavailable."""
        dylib = self.dist.llvm_lib_dir / "interpreter.dylib"
        if not dylib.exists():
            _LOGGER.debug("interpreter.dylib not found, using subprocess fallback")
            return None
        try:
            rt = _KRuntime(dylib)
            _LOGGER.info("Loaded FFI runtime from %s", dylib)
            return rt
        except Exception:
            _LOGGER.warning(
                "Failed to load FFI runtime, using subprocess", exc_info=True
            )
            return None

    def run(
        self,
        pattern: Pattern,
        *,
        depth: int | None = None,
    ) -> Pattern:
        """Execute a KORE pattern via the LLVM backend.

        Uses direct FFI to interpreter.dylib when available (4-10x faster),
        falling back to subprocess execution.
        """
        rt = self._runtime
        if rt is not None:
            import sys

            from pyk.kore.parser import KoreParser

            d = -1 if depth is None else depth
            result_text = rt.run(pattern.text, depth=d)
            old_limit = sys.getrecursionlimit()
            sys.setrecursionlimit(max(old_limit, 50_000))
            try:
                return KoreParser(result_text).pattern()
            finally:
                sys.setrecursionlimit(old_limit)

        from pyk.ktool.krun import llvm_interpret

        return llvm_interpret(
            definition_dir=self.dist.llvm_dir, pattern=pattern, depth=depth
        )

    def verify_script(
        self,
        script_pubkey: bytes,
        *,
        script_sig: bytes = b"",
        sighash: bytes = b"",
        witness: bytes = b"",
        flags: int = 0,
        tx_version: int = 1,
        n_locktime: int = 0,
        n_sequence: int = 0xFFFFFFFF,
    ) -> Pattern:
        """Build and run a full script verification.

        Args:
            script_pubkey: The scriptPubKey bytes.
            script_sig: The scriptSig bytes (empty for scriptPubKey-only execution).
            sighash: 32-byte transaction digest for signature verification.
            witness: Witness data (encoded witness stack blob).
            flags: Verification flags bitmask (Bitcoin Core SCRIPT_VERIFY_* values).
            tx_version: Spending transaction version (for BIP-68 CSV: must be >= 2).
            n_locktime: Spending transaction nLockTime (for BIP-65 CLTV).
            n_sequence: Spending input nSequence (for BIP-65 CLTV / BIP-68 CSV).

        Returns:
            The final KORE pattern after execution.
        """
        pat = self.pattern(
            script_sig=script_sig,
            script_pubkey=script_pubkey,
            sighash=sighash,
            witness=witness,
            flags=flags,
            tx_version=tx_version,
            n_locktime=n_locktime,
            n_sequence=n_sequence,
        )
        return self.run(pat)

    def pattern(
        self,
        *,
        script_sig: bytes = b"",
        script_pubkey: bytes = b"",
        sighash: bytes = b"",
        witness: bytes = b"",
        flags: int = 0,
        tx_version: int = 1,
        n_locktime: int = 0,
        n_sequence: int = 0xFFFFFFFF,
    ) -> Pattern:
        """Build an initial KORE configuration.

        Args:
            script_sig: The scriptSig bytes (empty for scriptPubKey-only execution).
            script_pubkey: The scriptPubKey bytes.
            sighash: 32-byte transaction digest for signature verification.
            witness: Witness data (encoded witness stack blob).
            flags: Verification flags bitmask (Bitcoin Core SCRIPT_VERIFY_* values).
            tx_version: Spending transaction version (for BIP-68 CSV: must be >= 2).
            n_locktime: Spending transaction nLockTime (for BIP-65 CLTV).
            n_sequence: Spending input nSequence (for BIP-65 CLTV / BIP-68 CSV).

        Returns:
            The initial KORE pattern.
        """
        from pyk.kore.prelude import SORT_K_ITEM, inj, top_cell_initializer
        from pyk.kore.syntax import DV, SortApp, String

        # We need to provide all config variables, each injected into SortKItem

        sort_bytes = SortApp("SortBytes")
        sort_int = SortApp("SortInt")

        def _bytes_var(data: bytes) -> Pattern:
            return inj(
                sort_bytes, SORT_K_ITEM, DV(sort_bytes, String(data.decode("latin-1")))
            )

        def _int_var(val: int) -> Pattern:
            return inj(sort_int, SORT_K_ITEM, DV(sort_int, String(str(val))))

        return top_cell_initializer(
            {
                "$SCRIPTSIG": _bytes_var(script_sig),
                "$SCRIPTPUBKEY": _bytes_var(script_pubkey),
                "$SIGHASH": _bytes_var(sighash),
                "$WITNESS": _bytes_var(witness),
                "$FLAGS": _int_var(flags),
                "$TXVERSION": _int_var(tx_version),
                "$NLOCKTIME": _int_var(n_locktime),
                "$NSEQUENCE": _int_var(n_sequence),
            }
        )

    def parse(self, script_text: str) -> Pattern:
        """Parse script text into a KORE term via the LLVM parser."""
        from subprocess import CalledProcessError

        from pyk.kore.parser import KoreParser
        from pyk.utils import run_process_2

        parser = self.dist.llvm_dir / "parser_PGM"
        args = [str(parser), "/dev/stdin"]

        try:
            kore_text = run_process_2(args, input=script_text).stdout
        except CalledProcessError as err:
            raise ValueError(err.stderr) from err

        return KoreParser(kore_text).pattern()

    def pretty(self, pattern: Pattern, *, color: bool = False) -> str:
        """Pretty-print a KORE pattern."""
        from pyk.kore.tools import kore_print

        return kore_print(pattern, definition_dir=self.dist.llvm_dir, color=color)

    def stack(self, pattern: Pattern) -> list[bytes]:
        """Extract the final stack from a result configuration.

        Returns stack elements as bytes values (top of stack first).
        """
        match _find_cell(pattern, "Lbl'-LT-'stack'-GT-'"):
            case App(args=[first, *_]):
                return _list_items(first)
            case App():
                return []
            case _:
                raise ValueError(
                    f"Cannot find stack cell in pattern:\n{self.pretty(pattern)}"
                )

    def is_stuck(self, pattern: Pattern) -> bool:
        """Check if execution got stuck (k cell is not empty)."""
        match _find_cell(pattern, "Lbl'-LT-'k'-GT-'"):
            case App(args=[App(symbol="dotk"), *_]):
                return False
            case _:
                return True

    def error(self, pattern: Pattern) -> str | None:
        """Extract the error code from the <error> cell, or None if no error.

        Returns the error string set by #fail(), or None if the error cell
        is empty. A non-None result means an explicit error was raised.
        If the result is None but is_stuck() is True, the failure was implicit
        (e.g., stack underflow via pattern-matching failure).
        """
        match _find_cell(pattern, "Lbl'-LT-'error'-GT-'"):
            case App(args=[DV(value=String(value=s)), *_]):
                return s if s else None
            case _:
                return None

    def success(self, pattern: Pattern) -> bool:
        """Check if script execution succeeded.

        A script succeeds when: no error was raised, the k cell is empty,
        and the top stack element is truthy (non-zero, non-empty).
        """
        if self.error(pattern) is not None:
            return False
        if self.is_stuck(pattern):
            return False
        match self.stack(pattern):
            case [bytes(top), *_]:
                return len(top) > 0
            case _:
                return False

    def debug(self, pattern: Pattern) -> Callable[[int | None], None]:
        """Return a closure for step-by-step debugging in a REPL.

        Example::

            step = k.debug(pattern)
            step()            # single step
            step(5)           # 5 steps
            step(depth=None)  # run to completion
        """

        def step(depth: int | None = 1) -> None:
            nonlocal pattern
            pattern = self.run(pattern, depth=depth)
            print(self.pretty(pattern, color=True))

        return step


def _find_cell(pattern: Pattern, symbol: str) -> App | None:
    """Find a cell by its KORE symbol name (iterative DFS)."""
    stack: list[Pattern] = [pattern]
    while stack:
        node = stack.pop()
        match node:
            case App(symbol=s) if s == symbol:
                return node
            case App(args=args):
                stack.extend(reversed(args))
    return None


def _list_items(pattern: Pattern) -> list[bytes]:
    """Walk a KORE List pattern and extract elements."""
    items: list[bytes] = []
    _collect_list_items(pattern, items)
    return items


def _collect_list_items(pattern: Pattern, items: list[bytes]) -> None:
    """Collect ListItem elements from a KORE List pattern (iterative)."""
    from pyk.kore.syntax import App, DV, LeftAssoc

    worklist: list[Pattern] = [pattern]
    while worklist:
        node = worklist.pop()
        match node:
            case LeftAssoc(args=args):
                worklist.extend(reversed(args))
            case App(symbol="Lbl'Stop'List"):
                pass
            case App(symbol="LblListItem", args=[inner, *_]):
                if isinstance(inner, App) and inner.symbol.startswith("inj"):
                    inner = inner.args[0]
                if isinstance(inner, DV):
                    items.append(inner.value.value.encode("latin-1"))
            case App(symbol="Lbl'Unds'List'Unds'", args=args):
                worklist.extend(reversed(args))
