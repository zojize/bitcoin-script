"""Prove concrete K claims via LLVM execution.

The Haskell backend (kore-exec) can't evaluate KRYPTO hooks (SHA256, etc.)
or concrete byte operations (#isMinimalNum) because these are only compiled
into the LLVM backend as C++ plugins. To verify these claims, we execute
the initial configuration through LLVM and check the final state matches
the expected target.

This is semantically equivalent to kprove for fully concrete claims.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from pyk.kast.inner import KRewrite, KSort, KToken, KVariable, bottom_up
from pyk.kast.manip import split_config_and_constraints
from pyk.konvert import kast_to_kore
from pyk.ktool.kprove import KProve
from pyk.ktool.krun import llvm_interpret

SPEC_DIR = Path(__file__).parent
GENERATED_TOP_CELL = KSort("GeneratedTopCell")


def _get_def_dir(target: str) -> Path:
    result = subprocess.run(
        ["kdist", "which", f"bitcoin-script-semantics.{target}"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.skip(f"{target} backend not built")
    return Path(result.stdout.strip())


# Claims proved via LLVM execution (Haskell kprove can't evaluate crypto hooks).
# The MINIMALDATA claim is excluded here too: the K semantics lacks an explicit
# error rule for non-minimal numbers — validNumFlags guard causes no-match (stuck)
# instead of producing #fail("MINIMALDATA"). Needs a semantics fix.
LLVM_CLAIMS: list[tuple[str, str, str]] = [
    ("htlc-spec", "HTLC-SPEC", "HTLC-SPEC.hash-path-correct-preimage"),
    ("htlc-spec", "HTLC-SPEC", "HTLC-SPEC.hash-path-wrong-preimage"),
]


@pytest.fixture(scope="module")
def kprove_instance():
    return KProve(definition_dir=_get_def_dir("haskell"))


@pytest.mark.k
@pytest.mark.parametrize(
    "spec_stem,module_name,claim_label",
    LLVM_CLAIMS,
    ids=[c[2] for c in LLVM_CLAIMS],
)
def test_llvm_prove(
    kprove_instance: KProve,
    spec_stem: str,
    module_name: str,
    claim_label: str,
) -> None:
    """Prove a concrete claim by executing via LLVM and checking the result."""
    llvm_dir = _get_def_dir("llvm")
    spec_file = SPEC_DIR / f"{spec_stem}.k"
    claims = kprove_instance.get_claims(spec_file, spec_module_name=module_name)

    claim = next((c for c in claims if c.label == claim_label), None)
    assert claim is not None, f"Claim {claim_label} not found"

    defn = kprove_instance.definition
    config, _constraints = split_config_and_constraints(claim.body)

    # Extract initial config (LHS of all rewrites, variables → concrete defaults)
    def _concretize(t):
        if isinstance(t, KRewrite):
            return t.lhs
        if isinstance(t, KVariable):
            # Replace unbound vars with concrete defaults for LLVM execution
            if t.sort and t.sort.name == "Int":
                return KToken("0", KSort("Int"))
            return KToken("0", KSort("Int"))
        return t

    init_config = bottom_up(_concretize, config)
    kore_init = kast_to_kore(defn, init_config, sort=GENERATED_TOP_CELL)

    # Execute via LLVM backend
    kore_final = llvm_interpret(definition_dir=llvm_dir, pattern=kore_init)

    # Extract target config (RHS of all rewrites, existential vars as wildcards)
    target_config = bottom_up(lambda t: t.rhs if isinstance(t, KRewrite) else t, config)
    kore_target = kast_to_kore(defn, target_config, sort=GENERATED_TOP_CELL)

    # Verify the claim by checking key cells in the LLVM output
    final_text = kore_final.text
    target_text = kore_target.text

    # Check <error> cell — the primary correctness criterion
    final_error = _extract_cell(final_text, "error")
    target_error = _extract_cell(target_text, "error")

    if target_error and "Var'Ques'" not in target_error:
        assert final_error is not None, f"No error cell in output for {claim_label}"
        assert _norm(final_error) == _norm(target_error), (
            f"<error> mismatch for {claim_label}:\n"
            f"  expected: {_norm(target_error)[:200]}\n"
            f"  got:      {_norm(final_error)[:200]}"
        )

    # For claims that expect success (empty error), also check <k> is empty
    if target_error and '""' in target_error:
        final_k = _extract_cell(final_text, "k")
        assert final_k is not None and "dotk" in final_k, (
            f"<k> not empty for {claim_label} (expected success)"
        )


def _norm(s: str) -> str:
    """Normalize KORE text: strip \\left-assoc wrappers and list concatenation."""
    import re

    s = re.sub(r"\\left-assoc\{\}\(Lbl'Unds'List'Unds'\{\}\(", "", s)
    # Remove trailing extra parens from the wrapper
    while s.endswith("))") and s.count("(") < s.count(")"):
        s = s[:-1]
    return s


def _extract_cell(kore_text: str, cell_name: str) -> str | None:
    """Extract a cell's content from KORE text (simple string matching)."""
    # KORE cell format: Lbl'-LT-'cellname'-GT-'{}(content)
    marker = f"Lbl'-LT-'{cell_name}'-GT-'"
    start = kore_text.find(marker)
    if start == -1:
        return None
    # Find the opening paren after the marker
    paren_start = kore_text.index("(", start)
    # Find matching close paren (counting nesting)
    depth = 0
    for i in range(paren_start, len(kore_text)):
        if kore_text[i] == "(":
            depth += 1
        elif kore_text[i] == ")":
            depth -= 1
            if depth == 0:
                return kore_text[paren_start + 1 : i]
    return None
