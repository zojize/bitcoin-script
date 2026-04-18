"""Run K proof specs via kprove and verify they prove (#Top).

Each *-spec.k file in this directory is discovered automatically and run
through kprove against the Haskell backend definition. Claims that need
the kore-rpc-booster (crypto hooks) are excluded via EXCLUDE_CLAIMS.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

SPEC_DIR = Path(__file__).parent

# Claims that need kore-rpc-booster for crypto hook evaluation
EXCLUDE_CLAIMS: dict[str, list[str]] = {
    "htlc-spec": [
        "HTLC-SPEC.hash-path-correct-preimage",
        "HTLC-SPEC.hash-path-wrong-preimage",
    ],
    "historical-bugs-spec": [
        "HISTORICAL-BUGS-SPEC.non-minimal-zero-rejected-with-flag",
    ],
}

# Discover all spec files
SPEC_FILES = sorted(SPEC_DIR.glob("*-spec.k"))


def _get_haskell_def() -> Path:
    from bitcoin_script.k_semantics.semantics import ScriptDist

    try:
        ScriptDist.rebuild_if_stale(("haskell",))
    except subprocess.CalledProcessError as e:
        pytest.skip(f"Haskell backend build failed: {e}")

    result = subprocess.run(
        ["kdist", "which", "bitcoin-script-semantics.haskell"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.skip("Haskell backend not available")
    return Path(result.stdout.strip())


@pytest.mark.k
@pytest.mark.parametrize(
    "spec_file",
    SPEC_FILES,
    ids=[f.stem for f in SPEC_FILES],
)
def test_prove_spec(spec_file: Path) -> None:
    """Prove all claims in a spec file via kprove."""
    haskell_def = _get_haskell_def()

    cmd = ["kprove", "--definition", str(haskell_def), str(spec_file)]

    # Exclude claims that need the booster
    excludes = EXCLUDE_CLAIMS.get(spec_file.stem, [])
    if excludes:
        cmd.extend(["--exclude", ",".join(excludes)])

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

    assert "#Top" in result.stdout, (
        f"Proof failed for {spec_file.stem}:\n"
        f"stdout: {result.stdout[-500:]}\n"
        f"stderr: {result.stderr[-500:]}"
    )
