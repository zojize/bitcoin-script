"""Tests for the ScriptEngine."""

from bitcoin_script.engine.engine import ScriptEngine


class TestScriptEngine:
    def test_empty_script_returns_false(self) -> None:
        """An empty script should evaluate to False (empty stack)."""
        ...

    def test_op_true_returns_true(self) -> None:
        """A script consisting of OP_TRUE should evaluate to True."""
        ...

    def test_op_return_fails(self) -> None:
        """OP_RETURN should cause immediate script failure."""
        ...

    def test_disabled_opcode_raises(self) -> None:
        """Encountering a disabled opcode should raise OpDisabledError."""
        ...

    def test_max_script_size_enforced(self) -> None:
        """Scripts exceeding 10,000 bytes should be rejected."""
        ...

    def test_max_ops_per_script_enforced(self) -> None:
        """More than 201 non-push operations should be rejected."""
        ...

    def test_max_stack_size_enforced(self) -> None:
        """Stack + altstack exceeding 1000 elements should be rejected."""
        ...

    def test_if_else_endif_true_branch(self) -> None:
        """OP_IF should execute the true branch when top is truthy."""
        ...

    def test_if_else_endif_false_branch(self) -> None:
        """OP_IF should skip to ELSE branch when top is falsy."""
        ...

    def test_nested_if(self) -> None:
        """Nested IF/ENDIF should work correctly."""
        ...

    def test_unbalanced_if_raises(self) -> None:
        """IF without matching ENDIF should raise UnbalancedConditionalError."""
        ...

    def test_verify_p2pkh_structure(self) -> None:
        """Verify method should run scriptSig then scriptPubKey."""
        ...

    def test_reset_clears_state(self) -> None:
        """Reset should clear the stack and all internal state."""
        ...
