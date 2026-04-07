"""Bitcoin Script execution stack."""

from __future__ import annotations

from bitcoin_script.engine.errors import StackUnderflowError
from bitcoin_script.types import StackElement


class ScriptStack:
    """Main and alt stack for Bitcoin Script execution.

    Bitcoin Script uses a variable-length little-endian signed-magnitude
    encoding for integers (not two's complement). Empty bytes means zero.
    """

    _main: list[StackElement]
    _alt: list[StackElement]

    def __init__(self) -> None:
        """Initialize empty main and alt stacks."""
        self._main = []
        self._alt = []

    # --- Main stack operations ---

    def push(self, element: StackElement) -> None:
        """Push an element onto the main stack."""
        self._main.append(element)

    def pop(self) -> StackElement:
        """Pop and return the top element from the main stack.

        Raises:
            StackUnderflowError: If the main stack is empty.
        """
        if not self._main:
            raise StackUnderflowError("Stack underflow")
        return self._main.pop()

    def peek(self, index: int = -1) -> StackElement:
        """Return the element at the given index without removing it.

        Args:
            index: Stack index (-1 = top, -2 = second from top, etc.)

        Raises:
            StackUnderflowError: If the index is out of range.
        """
        try:
            return self._main[index]
        except IndexError:
            raise StackUnderflowError("Stack underflow")

    def size(self) -> int:
        """Return the number of elements on the main stack."""
        return len(self._main)

    def is_empty(self) -> bool:
        """Return True if the main stack is empty."""
        return not self._main

    # --- Alt stack operations ---

    def push_alt(self, element: StackElement) -> None:
        """Push an element onto the alt stack."""
        self._alt.append(element)

    def pop_alt(self) -> StackElement:
        """Pop and return the top element from the alt stack.

        Raises:
            StackUnderflowError: If the alt stack is empty.
        """
        if not self._alt:
            raise StackUnderflowError("Alt stack underflow")
        return self._alt.pop()

    # --- Type conversions (Bitcoin Script encoding) ---

    @staticmethod
    def element_to_bool(element: StackElement) -> bool:
        """Interpret a stack element as a boolean.

        False is represented by empty bytes or any bytes where all are 0x00,
        except for negative zero (0x80 in the last byte).
        Everything else is True.
        """
        if not element:
            return False
        for i, byte in enumerate(element):
            if byte != 0:
                # Last byte with only the sign bit set is negative zero -> False
                if i == len(element) - 1 and byte == 0x80:
                    return False
                return True
        return False

    @staticmethod
    def element_to_int(element: StackElement) -> int:
        """Decode a stack element as a script number.

        Uses Bitcoin's variable-length little-endian signed-magnitude format.
        The most significant bit of the last byte is the sign bit.
        """
        if not element:
            return 0
        result = 0
        for i, byte in enumerate(element):
            result |= byte << (8 * i)
        # Sign bit is the high bit of the last byte
        if element[-1] & 0x80:
            result ^= 0x80 << (8 * (len(element) - 1))  # clear sign bit
            return -result
        return result

    @staticmethod
    def int_to_element(value: int) -> StackElement:
        """Encode an integer as a stack element.

        Uses Bitcoin's variable-length little-endian signed-magnitude format.
        """
        if value == 0:
            return b""
        negative = value < 0
        abs_val = abs(value)
        result: list[int] = []
        while abs_val > 0:
            result.append(abs_val & 0xFF)
            abs_val >>= 8
        if result[-1] & 0x80:
            # High bit already set: add an extra byte for the sign
            result.append(0x80 if negative else 0x00)
        elif negative:
            result[-1] |= 0x80
        return bytes(result)

    @staticmethod
    def bool_to_element(value: bool) -> StackElement:
        """Encode a boolean as a stack element.

        True = b'\\x01', False = b''
        """
        return b"\x01" if value else b""
