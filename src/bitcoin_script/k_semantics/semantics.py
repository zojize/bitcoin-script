from __future__ import annotations

import logging
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from collections.abc import Callable
from typing import final, Final

from pyk.kast.outer import KDefinition
from pyk.kore.syntax import App, Pattern

_LOGGER: Final = logging.getLogger(__name__)


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

        source_dir = Path(source_dir)
        check_dir_path(source_dir)

        llvm_dir = Path(llvm_dir)
        check_dir_path(llvm_dir)

        llvm_lib_dir = Path(llvm_lib_dir)
        check_dir_path(llvm_lib_dir)

        object.__setattr__(self, "source_dir", source_dir)
        object.__setattr__(self, "llvm_dir", llvm_dir)
        object.__setattr__(self, "llvm_lib_dir", llvm_lib_dir)

    @staticmethod
    def load() -> ScriptDist:
        return ScriptDist(
            source_dir=ScriptDist._find("source"),
            llvm_dir=ScriptDist._find("llvm"),
            llvm_lib_dir=ScriptDist._find("llvm-lib"),
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
    """Main interface for K-Python communication for Bitcoin Script."""

    dist: ScriptDist

    def __init__(self, dist: ScriptDist | None = None) -> None:
        if dist is None:
            dist = ScriptDist.load()
        object.__setattr__(self, "dist", dist)

    @cached_property
    def definition(self) -> KDefinition:
        from pyk.kast.outer import read_kast_definition

        return read_kast_definition(self.dist.llvm_dir / "compiled.json")

    def run(
        self,
        pattern: Pattern,
        *,
        depth: int | None = None,
    ) -> Pattern:
        """Execute a KORE pattern via the LLVM backend."""
        from pyk.ktool.krun import llvm_interpret

        return llvm_interpret(
            definition_dir=self.dist.llvm_dir, pattern=pattern, depth=depth
        )

    def pattern(self, script_text: str) -> Pattern:
        """Build an initial KORE configuration from script ASM text.

        Args:
            script_text: Script as ASM text (e.g. "OP_DUP OP_ADD").
        """
        from pyk.kore.prelude import SORT_K_ITEM, inj, top_cell_initializer
        from pyk.kore.syntax import SortApp

        pgm_pattern = self.parse(script_text)

        return top_cell_initializer(
            {
                "$PGM": inj(SortApp("SortScript"), SORT_K_ITEM, pgm_pattern),
            }
        )

    def parse(self, script_text: str) -> Pattern:
        """Parse script ASM text into a KORE term via the LLVM parser."""
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

    def success(self, pattern: Pattern) -> bool:
        """Check if script execution succeeded.

        A script succeeds when the k cell is empty and the top
        stack element is truthy (non-zero, non-empty).
        """
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
    """Recursively find a cell by its KORE symbol name."""
    match pattern:
        case App(symbol=s) if s == symbol:
            return pattern
        case App(args=args):
            for arg in args:
                if (result := _find_cell(arg, symbol)) is not None:
                    return result
    return None


def _list_items(pattern: Pattern) -> list[bytes]:
    """Walk a KORE List pattern and extract elements."""
    items: list[bytes] = []
    _collect_list_items(pattern, items)
    return items


def _collect_list_items(pattern: Pattern, items: list[bytes]) -> None:
    """Recursively collect ListItem elements from a KORE List pattern."""
    from pyk.kore.syntax import App, DV, LeftAssoc

    match pattern:
        case LeftAssoc(args=args):
            for arg in args:
                _collect_list_items(arg, items)

        case App(symbol="Lbl'Stop'List"):
            pass

        # ListItem(inj{Sort, SortKItem}(DV(Sort, value)))
        case App(symbol="LblListItem", args=[inner, *_]):
            # Unwrap injection: inj{...}(inner)
            if isinstance(inner, App) and inner.symbol.startswith("inj"):
                inner = inner.args[0]
            if isinstance(inner, DV):
                items.append(inner.value.value.encode("latin-1"))

        # List concatenation: Lbl'Unds'List'Unds'{}(left, right)
        case App(symbol="Lbl'Unds'List'Unds'", args=args):
            for arg in args:
                _collect_list_items(arg, items)
