"""Tests for Script and ScriptIterator."""

from bitcoin_script.model.script import Script, ScriptIterator, ScriptType
from bitcoin_script.opcodes.opcode import Opcode


class TestScript:
    def test_from_hex(self) -> None:
        """Should construct a Script from hex string."""
        ...

    def test_to_hex_roundtrip(self) -> None:
        """from_hex and to_hex should roundtrip."""
        ...

    def test_len_returns_byte_length(self) -> None:
        """len() should return the number of raw bytes."""
        ...

    def test_bytes_returns_raw(self) -> None:
        """bytes() should return the raw script bytes."""
        ...

    def test_to_asm_p2pkh(self) -> None:
        """to_asm should produce readable P2PKH assembly."""
        ...


class TestScriptIterator:
    def test_iterate_simple_opcodes(self) -> None:
        """Should yield (Opcode, None) for non-push opcodes."""
        ...

    def test_iterate_data_push(self) -> None:
        """Should yield (Opcode, data) for push opcodes."""
        ...

    def test_iterate_empty_script(self) -> None:
        """Empty script should yield nothing."""
        ...

    def test_iterate_pushdata1(self) -> None:
        """PUSHDATA1 should read 1-byte length prefix."""
        ...


class TestScriptType:
    def test_all_types_defined(self) -> None:
        """All standard script types should be defined."""
        ...
