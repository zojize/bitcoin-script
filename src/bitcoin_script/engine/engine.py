"""Main Bitcoin Script interpreter engine."""

from __future__ import annotations

from bitcoin.core import CTransaction
from bitcoin.core.script import CScript

from bitcoin_script.engine.flags import ScriptVerifyFlag
from bitcoin_script.engine.stack import ScriptStack


class ScriptEngine:
    """Bitcoin Script virtual machine.

    Evaluates scriptSig and scriptPubKey to determine if a transaction
    input is authorized to spend its referenced output.
    """

    _stack: ScriptStack
    _flags: ScriptVerifyFlag
    _tx: CTransaction | None
    _input_index: int
    _input_value: int

    def __init__(
        self,
        flags: ScriptVerifyFlag = ScriptVerifyFlag.NONE,
    ) -> None:
        """Initialize the script engine.

        Args:
            flags: Verification flags controlling which rules are enforced.
        """
        ...

    def verify(
        self,
        script_sig: CScript,
        script_pubkey: CScript,
        tx: CTransaction | None = None,
        input_index: int = 0,
        input_value: int = 0,
    ) -> bool:
        """Full script verification: run scriptSig, copy stack, run scriptPubKey.

        Handles P2SH deserialization and SegWit witness programs if the
        appropriate flags are set.

        Args:
            script_sig: The unlocking script.
            script_pubkey: The locking script.
            tx: The spending transaction (needed for signature verification).
            input_index: Index of the input being verified.
            input_value: Value of the output being spent (for segwit sighash).

        Returns:
            True if script execution succeeds, False otherwise.
        """
        ...

    def execute(self, script: CScript) -> bool:
        """Execute a single script on the current stack.

        Processes each opcode sequentially, managing the condition stack
        for IF/ELSE/ENDIF flow control.

        Args:
            script: The script to execute.

        Returns:
            True if execution completes with a truthy top-of-stack.
        """
        ...

    def _execute_opcode(
        self,
        opcode_byte: int,
        data: bytes | None,
    ) -> None:
        """Dispatch and execute a single opcode.

        Args:
            opcode_byte: The raw opcode byte value.
            data: Associated push data, or None for non-push opcodes.
        """
        ...

    def reset(self) -> None:
        """Clear stack and internal state for reuse."""
        ...
