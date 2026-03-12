"""Bitcoin Script representation and parsing."""

from __future__ import annotations

from enum import Enum, auto

from bitcoin_script.opcodes.opcode import Opcode
from bitcoin_script.types import ScriptBytes


class ScriptType(Enum):
    """Standard Bitcoin script template types."""

    P2PKH = auto()
    P2SH = auto()
    P2WPKH = auto()
    P2WSH = auto()
    P2PK = auto()
    MULTISIG = auto()
    NULL_DATA = auto()
    NONSTANDARD = auto()


class Script:
    """Thin wrapper around raw script bytes with iteration and display."""

    _raw: ScriptBytes

    def __init__(self, raw: ScriptBytes) -> None:
        """Initialize a Script from raw bytes."""
        ...

    def __iter__(self) -> ScriptIterator:
        """Iterate over (Opcode, data_bytes | None) pairs."""
        ...

    def __len__(self) -> int:
        """Return the length in bytes."""
        ...

    def __bytes__(self) -> bytes:
        """Return the raw script bytes."""
        ...

    @classmethod
    def from_hex(cls, hex_str: str) -> Script:
        """Create a Script from a hex-encoded string."""
        ...

    def to_hex(self) -> str:
        """Return hex-encoded representation."""
        ...

    def to_asm(self) -> str:
        """Return human-readable assembly representation.

        Example: "OP_DUP OP_HASH160 <14-bytes> OP_EQUALVERIFY OP_CHECKSIG"
        """
        ...


class ScriptIterator:
    """Yields (Opcode, data_bytes | None) tuples from raw script bytes."""

    def __init__(self, raw: bytes) -> None:
        """Initialize iterator over raw script bytes."""
        ...

    def __iter__(self) -> ScriptIterator:
        """Return self."""
        ...

    def __next__(self) -> tuple[Opcode, bytes | None]:
        """Yield the next (opcode, data) pair.

        For data push opcodes, data contains the pushed bytes.
        For non-push opcodes, data is None.

        Raises:
            StopIteration: When the script is fully consumed.
        """
        ...
