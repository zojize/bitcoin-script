# opcodes

Complete Bitcoin Script opcode vocabulary. Pure data, no execution logic.

- `opcode.py` — `Opcode` IntEnum mapping all ~100 opcodes to their byte values (0x00–0xFF). Includes properties like `is_disabled` and `is_push_data` for introspection.
- `categories.py` — FrozenSets grouping opcodes by function: constants, stack manipulation, arithmetic, crypto, flow control, locktime, reserved/disabled, and NOPs.
