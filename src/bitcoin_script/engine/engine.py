"""Main Bitcoin Script interpreter engine."""

from __future__ import annotations

import hashlib

from bitcoin.core import CTransaction
from bitcoin.core.script import CScript

from bitcoin_script.engine.errors import (
    OpCountError,
    OpDisabledError,
    PushSizeError,
    ScriptError,
    ScriptInvalidError,
    ScriptSizeError,
    StackSizeError,
    UnbalancedConditionalError,
    VerifyFailedError,
)
from bitcoin_script.engine.flags import ScriptVerifyFlag
from bitcoin_script.engine.operations import (
    get_handler,
    op_checkmultisig,
    op_checkmultisigverify,
    op_checksig,
    op_checksigverify,
)
from bitcoin_script.engine.stack import ScriptStack

# ---- Consensus limits -------------------------------------------------------
_MAX_SCRIPT_SIZE = 10_000
_MAX_OPS_PER_SCRIPT = 201
_MAX_STACK_SIZE = 1_000
_MAX_ELEMENT_SIZE = 520

# ---- Opcode byte constants --------------------------------------------------
_OP_0 = 0x00
_OP_1NEGATE = 0x4F
_OP_RESERVED = 0x50
_OP_1 = 0x51
_OP_16 = 0x60
_OP_NOP = 0x61
_OP_VER = 0x62
_OP_IF = 0x63
_OP_NOTIF = 0x64
_OP_VERIF = 0x65
_OP_VERNOTIF = 0x66
_OP_ELSE = 0x67
_OP_ENDIF = 0x68
_OP_RETURN = 0x6A
_OP_TOALTSTACK = 0x6B
_OP_FROMALTSTACK = 0x6C
_OP_CODESEPARATOR = 0xAB
_OP_CHECKSIG = 0xAC
_OP_CHECKSIGVERIFY = 0xAD
_OP_CHECKMULTISIG = 0xAE
_OP_CHECKMULTISIGVERIFY = 0xAF
_OP_CHECKLOCKTIMEVERIFY = 0xB1
_OP_CHECKSEQUENCEVERIFY = 0xB2

# NOP-family opcodes (pass silently)
_NOPS = {0x61, 0xB0, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9}

# Always-invalid opcodes (OP_VERIF, OP_VERNOTIF)
_ALWAYS_INVALID = {0x65, 0x66}

# SegWit sigversion constants (matches bitcoin-core / python-bitcoinlib)
_SIGVERSION_BASE = 0
_SIGVERSION_WITNESS_V0 = 1


# ---- Script-type helpers ----------------------------------------------------


def _is_p2sh(script: CScript) -> bool:
    r = bytes(script)
    return len(r) == 23 and r[0] == 0xA9 and r[1] == 0x14 and r[-1] == 0x87


def _is_p2wpkh(script: CScript) -> bool:
    r = bytes(script)
    return len(r) == 22 and r[0] == 0x00 and r[1] == 0x14


def _is_p2wsh(script: CScript) -> bool:
    r = bytes(script)
    return len(r) == 34 and r[0] == 0x00 and r[1] == 0x20


# ---- Engine -----------------------------------------------------------------


class ScriptEngine:
    """Bitcoin Script virtual machine.

    Evaluates scriptSig and scriptPubKey (plus optional witness) to determine
    if a transaction input is authorized to spend its referenced output.

    Supports: P2PKH, P2PK, bare multisig, P2SH, P2WPKH, P2WSH,
              nested P2SH-P2WPKH, nested P2SH-P2WSH.
    """

    _stack: ScriptStack
    _flags: ScriptVerifyFlag
    _tx: CTransaction | None
    _input_index: int
    _input_value: int
    _script_code: bytes
    _sigversion: int  # _SIGVERSION_BASE or _SIGVERSION_WITNESS_V0

    def __init__(
        self,
        flags: ScriptVerifyFlag = ScriptVerifyFlag.NONE,
    ) -> None:
        self._flags = flags
        self._stack = ScriptStack()
        self._tx = None
        self._input_index = 0
        self._input_value = 0
        self._script_code = b""
        self._sigversion = _SIGVERSION_BASE

    def reset(self) -> None:
        """Clear stack and internal state for reuse."""
        self._stack = ScriptStack()
        self._tx = None
        self._input_index = 0
        self._input_value = 0
        self._script_code = b""
        self._sigversion = _SIGVERSION_BASE

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    def verify(
        self,
        script_sig: CScript,
        script_pubkey: CScript,
        tx: CTransaction | None = None,
        input_index: int = 0,
        input_value: int = 0,
        witness: list[bytes] | None = None,
    ) -> bool:
        """Full script verification including P2SH and SegWit.

        Args:
            script_sig:    The unlocking script (must be empty for native SegWit).
            script_pubkey: The locking script.
            tx:            Spending transaction (required for sig-checking opcodes).
            input_index:   Index of the input being verified.
            input_value:   Value of the UTXO being spent, in satoshis (required for SegWit sighash).
            witness:       Witness stack items for SegWit inputs (list of bytes).

        Returns:
            True if the input is valid, False otherwise.
        """
        self.reset()
        self._tx = tx
        self._input_index = input_index
        self._input_value = input_value

        witness = witness or []
        witness_flag = bool(self._flags & ScriptVerifyFlag.WITNESS)
        p2sh_flag = bool(self._flags & ScriptVerifyFlag.P2SH)
        sig_bytes = bytes(script_sig)

        # ---- Size guards ----
        if (
            len(sig_bytes) > _MAX_SCRIPT_SIZE
            or len(bytes(script_pubkey)) > _MAX_SCRIPT_SIZE
        ):
            return False

        # ================================================================
        # Native P2WPKH  (OP_0 <20-byte-hash>)
        # ================================================================
        if witness_flag and _is_p2wpkh(script_pubkey):
            if sig_bytes:  # scriptSig MUST be empty for native SegWit
                return False
            return self._verify_p2wpkh(script_pubkey, witness)

        # ================================================================
        # Native P2WSH  (OP_0 <32-byte-hash>)
        # ================================================================
        if witness_flag and _is_p2wsh(script_pubkey):
            if sig_bytes:
                return False
            return self._verify_p2wsh(script_pubkey, witness)

        # ================================================================
        # Legacy (P2PKH, P2PK, multisig, P2SH, nested SegWit)
        # ================================================================
        self._script_code = bytes(script_pubkey)

        # Phase 1: execute scriptSig
        try:
            self._run_script(script_sig)
        except ScriptError:
            return False

        # Save stack snapshot for P2SH re-execution
        p2sh_active = p2sh_flag and _is_p2sh(script_pubkey)
        saved_stack = list(self._stack._main) if p2sh_active else None

        # Phase 2: execute scriptPubKey
        self._script_code = bytes(script_pubkey)
        try:
            self._run_script(script_pubkey)
        except ScriptError:
            return False

        if self._stack.is_empty():
            return False
        if not ScriptStack.element_to_bool(self._stack.peek()):
            return False

        # ================================================================
        # P2SH re-execution
        # ================================================================
        if p2sh_active and saved_stack:
            redeem_bytes = saved_stack[-1]

            # Check for nested SegWit BEFORE executing as a script
            if witness_flag:
                redeem_script = CScript(redeem_bytes)
                if _is_p2wpkh(redeem_script):
                    # P2SH-P2WPKH
                    return self._verify_p2wpkh(redeem_script, witness)
                if _is_p2wsh(redeem_script):
                    # P2SH-P2WSH
                    return self._verify_p2wsh(redeem_script, witness)

            # Plain P2SH: restore stack (minus redeem script) and run redeem script
            self._stack._main = list(saved_stack[:-1])
            self._script_code = redeem_bytes
            try:
                self._run_script(CScript(redeem_bytes))
            except ScriptError:
                return False

            if self._stack.is_empty():
                return False
            if not ScriptStack.element_to_bool(self._stack.peek()):
                return False

        return True

    def execute(self, script: CScript) -> bool:
        """Execute a single script on the current stack.

        Returns:
            True if execution completes with a truthy top-of-stack.
        """
        self._run_script(script)
        if self._stack.is_empty():
            return False
        return ScriptStack.element_to_bool(self._stack.peek())

    # -------------------------------------------------------------------------
    # SegWit execution helpers
    # -------------------------------------------------------------------------

    def _verify_p2wpkh(self, script_pubkey: CScript, witness: list[bytes]) -> bool:
        """Execute a P2WPKH or P2SH-P2WPKH input.

        Witness must be exactly [<sig>, <pubkey>].
        Script code for BIP143 sighash is the P2PKH-equivalent script.
        """
        if len(witness) != 2:
            return False

        sig, pubkey = witness[0], witness[1]
        pubkey_hash = bytes(script_pubkey)[2:]  # skip OP_0 + push byte

        # Verify the pubkey matches the stored hash
        actual_hash = hashlib.new("ripemd160", hashlib.sha256(pubkey).digest()).digest()
        if actual_hash != pubkey_hash:
            return False

        # BIP143 script code: OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG
        from bitcoin_script.script_types.p2wpkh import witness_to_script_code

        script_code = witness_to_script_code(pubkey_hash)

        # Set up a clean stack with the witness items
        self._stack = ScriptStack()
        self._stack.push(sig)
        self._stack.push(pubkey)

        self._script_code = script_code
        self._sigversion = _SIGVERSION_WITNESS_V0

        try:
            self._run_script(CScript(script_code))
        except ScriptError:
            return False
        finally:
            self._sigversion = _SIGVERSION_BASE

        return not self._stack.is_empty() and ScriptStack.element_to_bool(
            self._stack.peek()
        )

    def _verify_p2wsh(self, script_pubkey: CScript, witness: list[bytes]) -> bool:
        """Execute a P2WSH or P2SH-P2WSH input.

        The last witness item is the witness script; the rest are stack inputs.
        The witness script is hashed with SHA-256 and compared against the
        32-byte hash in scriptPubKey.
        """
        if not witness:
            return False

        witness_script_bytes = witness[-1]
        witness_stack_items = witness[:-1]

        script_hash = bytes(script_pubkey)[2:]  # 32-byte SHA256 hash

        # P2WSH uses single SHA-256 (not double)
        actual_hash = hashlib.sha256(witness_script_bytes).digest()
        if actual_hash != script_hash:
            return False

        # Set up stack with witness items (in order, first item at the bottom)
        self._stack = ScriptStack()
        for item in witness_stack_items:
            self._stack.push(item)

        self._script_code = witness_script_bytes
        self._sigversion = _SIGVERSION_WITNESS_V0

        try:
            self._run_script(CScript(witness_script_bytes))
        except ScriptError:
            return False
        finally:
            self._sigversion = _SIGVERSION_BASE

        return not self._stack.is_empty() and ScriptStack.element_to_bool(
            self._stack.peek()
        )

    # -------------------------------------------------------------------------
    # Core execution loop
    # -------------------------------------------------------------------------

    def _run_script(self, script: CScript) -> None:
        """Run a script on self._stack.  Raises ScriptError on failure."""
        script_bytes = bytes(script)
        if len(script_bytes) > _MAX_SCRIPT_SIZE:
            raise ScriptSizeError("Script exceeds 10,000 bytes")

        cond_stack: list[bool] = []
        op_count = 0

        try:
            for opcode, data, _sop_idx in script:  # type: ignore[misc]
                executing = not cond_stack or all(cond_stack)

                # ---- Data-push opcodes (data is not None, including OP_0 -> b'') ----
                if data is not None:
                    if executing:
                        push_data = bytes(data)  # type: ignore[arg-type]
                        if len(push_data) > _MAX_ELEMENT_SIZE:
                            raise PushSizeError("Push data exceeds 520 bytes")
                        self._stack.push(push_data)
                    continue

                # ---- Op counter (all non-push opcodes with value > OP_16) ----
                if opcode > _OP_16:
                    op_count += 1
                    if op_count > _MAX_OPS_PER_SCRIPT:
                        raise OpCountError("Exceeded 201 ops per script")

                # ---- Stack-size guard ----
                if self._stack.size() + len(self._stack._alt) > _MAX_STACK_SIZE:
                    raise StackSizeError("Stack exceeds 1000 elements")

                # ---- Conditional-flow opcodes (processed regardless of branch) ----
                if opcode == _OP_IF:
                    val = executing and ScriptStack.element_to_bool(self._stack.pop())
                    cond_stack.append(val)
                    continue

                if opcode == _OP_NOTIF:
                    val = executing and (
                        not ScriptStack.element_to_bool(self._stack.pop())
                    )
                    cond_stack.append(val)
                    continue

                if opcode == _OP_ELSE:
                    if not cond_stack:
                        raise UnbalancedConditionalError("ELSE without IF")
                    if len(cond_stack) == 1 or all(cond_stack[:-1]):
                        cond_stack[-1] = not cond_stack[-1]
                    continue

                if opcode == _OP_ENDIF:
                    if not cond_stack:
                        raise UnbalancedConditionalError("ENDIF without IF")
                    cond_stack.pop()
                    continue

                # ---- Skip non-executing branches ----
                if not executing:
                    continue

                # ---- Small-integer push opcodes ----
                if opcode == _OP_1NEGATE:
                    self._stack.push(ScriptStack.int_to_element(-1))
                    continue
                if _OP_1 <= opcode <= _OP_16:
                    self._stack.push(ScriptStack.int_to_element(opcode - 0x50))
                    continue

                # ---- Everything else ----
                self._execute_opcode(opcode, data)

        except ScriptError:
            raise
        except Exception as exc:
            raise ScriptInvalidError(f"Script error: {exc}") from exc

        if cond_stack:
            raise UnbalancedConditionalError("Unterminated IF")

    def _execute_opcode(self, opcode_byte: int, data: bytes | None) -> None:
        """Dispatch a single opcode."""

        # Always-invalid
        if opcode_byte in _ALWAYS_INVALID:
            raise ScriptInvalidError(f"Always-invalid opcode 0x{opcode_byte:02x}")

        # OP_RETURN
        if opcode_byte == _OP_RETURN:
            raise ScriptInvalidError("OP_RETURN")

        # NOPs
        if opcode_byte in _NOPS:
            return

        # OP_RESERVED / OP_VER / OP_RESERVED1 / OP_RESERVED2
        if opcode_byte in (0x50, 0x62, 0x89, 0x8A):
            raise ScriptInvalidError(f"OP_RESERVED 0x{opcode_byte:02x}")

        # Alt stack
        if opcode_byte == _OP_TOALTSTACK:
            self._stack.push_alt(self._stack.pop())
            return
        if opcode_byte == _OP_FROMALTSTACK:
            self._stack.push(self._stack.pop_alt())
            return

        # CODESEPARATOR — in legacy scripts this updates the script_code;
        # we acknowledge it but skip the full split for now.
        if opcode_byte == _OP_CODESEPARATOR:
            return

        # CHECKLOCKTIMEVERIFY / CHECKSEQUENCEVERIFY (BIP65 / BIP112)
        # Full time/sequence validation requires block context; here we just
        # ensure the stack is non-empty (consensus minimum check).
        if opcode_byte in (_OP_CHECKLOCKTIMEVERIFY, _OP_CHECKSEQUENCEVERIFY):
            if self._stack.is_empty():
                raise VerifyFailedError(f"0x{opcode_byte:02x}: empty stack")
            return

        # Signature-checking opcodes (need tx context + sigversion)
        if opcode_byte in (
            _OP_CHECKSIG,
            _OP_CHECKSIGVERIFY,
            _OP_CHECKMULTISIG,
            _OP_CHECKMULTISIGVERIFY,
        ):
            if self._tx is None:
                raise ScriptInvalidError(
                    "Signature-checking opcode requires transaction context"
                )
            ctx = (
                self._tx,
                self._input_index,
                self._input_value,
                self._script_code,
                self._sigversion,
            )
            if opcode_byte == _OP_CHECKSIG:
                op_checksig(self._stack, *ctx)
            elif opcode_byte == _OP_CHECKSIGVERIFY:
                op_checksigverify(self._stack, *ctx)
            elif opcode_byte == _OP_CHECKMULTISIG:
                op_checkmultisig(self._stack, *ctx)
            elif opcode_byte == _OP_CHECKMULTISIGVERIFY:
                op_checkmultisigverify(self._stack, *ctx)
            return

        # All remaining opcodes via dispatch table
        try:
            handler = get_handler(opcode_byte)
        except OpDisabledError:
            raise
        except KeyError:
            raise ScriptInvalidError(f"Unknown opcode 0x{opcode_byte:02x}")

        handler(self._stack)
