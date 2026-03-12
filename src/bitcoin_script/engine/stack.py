"""Bitcoin Script execution stack."""

from __future__ import annotations

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
        ...

    # --- Main stack operations ---

    def push(self, element: StackElement) -> None:
        """Push an element onto the main stack."""
        ...

    def pop(self) -> StackElement:
        """Pop and return the top element from the main stack.

        Raises:
            StackUnderflowError: If the main stack is empty.
        """
        ...

    def peek(self, index: int = -1) -> StackElement:
        """Return the element at the given index without removing it.

        Args:
            index: Stack index (-1 = top, -2 = second from top, etc.)

        Raises:
            StackUnderflowError: If the index is out of range.
        """
        ...

    def size(self) -> int:
        """Return the number of elements on the main stack."""
        ...

    def is_empty(self) -> bool:
        """Return True if the main stack is empty."""
        ...

    # --- Alt stack operations ---

    def push_alt(self, element: StackElement) -> None:
        """Push an element onto the alt stack."""
        ...

    def pop_alt(self) -> StackElement:
        """Pop and return the top element from the alt stack.

        Raises:
            StackUnderflowError: If the alt stack is empty.
        """
        ...

    # --- Type conversions (Bitcoin Script encoding) ---

    @staticmethod
    def element_to_bool(element: StackElement) -> bool:
        """Interpret a stack element as a boolean.

        False is represented by empty bytes or any bytes where all are 0x00,
        except for negative zero (0x80 in the last byte).
        Everything else is True.
        """
        ...

    @staticmethod
    def element_to_int(element: StackElement) -> int:
        """Decode a stack element as a script number.

        Uses Bitcoin's variable-length little-endian signed-magnitude format.
        The most significant bit of the last byte is the sign bit.
        """
        ...

    @staticmethod
    def int_to_element(value: int) -> StackElement:
        """Encode an integer as a stack element.

        Uses Bitcoin's variable-length little-endian signed-magnitude format.
        """
        ...

    @staticmethod
    def bool_to_element(value: bool) -> StackElement:
        """Encode a boolean as a stack element.

        True = b'\\x01', False = b''
        """
        ...
