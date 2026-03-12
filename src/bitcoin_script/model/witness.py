"""Witness data structures for SegWit transactions."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class WitnessProgram:
    """A parsed witness program from a scriptPubKey."""

    version: int  # 0-16
    program: bytes  # 2-40 bytes

    @classmethod
    def from_script(cls, script_bytes: bytes) -> WitnessProgram | None:
        """Extract witness program if script matches the witness pattern.

        A witness program is: OP_n (version) followed by a 2-40 byte push.
        Returns None if the script is not a witness program.
        """
        ...
