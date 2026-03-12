"""Script execution error hierarchy."""


class ScriptError(Exception):
    """Base class for all script execution errors."""


class ScriptInvalidError(ScriptError):
    """Script failed structural validation (not a runtime error)."""


class EvalFalseError(ScriptError):
    """Script evaluated to false (top of stack is zero or empty)."""


class OpDisabledError(ScriptError):
    """Encountered a disabled opcode."""


class StackUnderflowError(ScriptError):
    """Tried to pop from an empty stack."""


class PushSizeError(ScriptError):
    """Data push exceeds MAX_SCRIPT_ELEMENT_SIZE (520 bytes)."""


class OpCountError(ScriptError):
    """Exceeded MAX_OPS_PER_SCRIPT (201)."""


class StackSizeError(ScriptError):
    """Stack + altstack exceeds MAX_STACK_SIZE (1000)."""


class ScriptSizeError(ScriptError):
    """Script exceeds MAX_SCRIPT_SIZE (10000 bytes)."""


class VerifyFailedError(ScriptError):
    """OP_VERIFY or *VERIFY opcode found false on stack."""


class InvalidSignatureError(ScriptError):
    """Signature encoding or verification failed."""


class UnbalancedConditionalError(ScriptError):
    """IF/ELSE/ENDIF not properly nested."""
