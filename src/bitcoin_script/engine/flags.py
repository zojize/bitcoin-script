"""Script verification flags mirroring Bitcoin Core's script/script_flags.h."""

from collections.abc import Iterable
from enum import IntFlag


class ScriptVerifyFlag(IntFlag):
    """Flags controlling script verification behavior."""

    NONE = 0
    P2SH = 1 << 0
    STRICTENC = 1 << 1
    DERSIG = 1 << 2
    LOW_S = 1 << 3
    NULLDUMMY = 1 << 4
    SIGPUSHONLY = 1 << 5
    MINIMALDATA = 1 << 6
    DISCOURAGE_UPGRADABLE_NOPS = 1 << 7
    CLEANSTACK = 1 << 8
    CHECKLOCKTIMEVERIFY = 1 << 9
    CHECKSEQUENCEVERIFY = 1 << 10
    WITNESS = 1 << 11
    DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM = 1 << 12
    MINIMALIF = 1 << 13
    NULLFAIL = 1 << 14
    WITNESS_PUBKEYTYPE = 1 << 15
    CONST_SCRIPTCODE = 1 << 16
    TAPROOT = 1 << 17

    @classmethod
    def from_names(cls, names: "Iterable[str]") -> "ScriptVerifyFlag":
        """Build a flag bitmask from a sequence of flag names.

        Names are case-insensitive and may be comma-separated within each
        list element (so both `["P2SH", "WITNESS"]` and `["p2sh,witness"]`
        work). Aliases: ``ALL`` expands to every flag; ``STANDARD`` is the
        Bitcoin Core mempool/relay default-active set.
        """
        result = cls.NONE
        for n in names:
            for token in n.split(","):
                token = token.strip().upper()
                if not token:
                    continue
                if token == "ALL":
                    for member in cls:
                        result |= member
                    continue
                if token == "STANDARD":
                    # Mirrors Bitcoin Core's STANDARD_SCRIPT_VERIFY_FLAGS as
                    # of v27.x. Useful default for relay-equivalent checks.
                    result |= (
                        cls.P2SH
                        | cls.STRICTENC
                        | cls.DERSIG
                        | cls.LOW_S
                        | cls.NULLDUMMY
                        | cls.SIGPUSHONLY
                        | cls.MINIMALDATA
                        | cls.DISCOURAGE_UPGRADABLE_NOPS
                        | cls.CLEANSTACK
                        | cls.CHECKLOCKTIMEVERIFY
                        | cls.CHECKSEQUENCEVERIFY
                        | cls.WITNESS
                        | cls.DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
                        | cls.MINIMALIF
                        | cls.NULLFAIL
                        | cls.WITNESS_PUBKEYTYPE
                        | cls.CONST_SCRIPTCODE
                        | cls.TAPROOT
                    )
                    continue
                # Allow leading "SCRIPT_VERIFY_" prefix (Bitcoin Core convention).
                if token.startswith("SCRIPT_VERIFY_"):
                    token = token[len("SCRIPT_VERIFY_") :]
                try:
                    result |= cls[token]
                except KeyError as exc:
                    valid = ", ".join(m.name for m in cls if m.name)
                    raise ValueError(
                        f"unknown flag {token!r}; expected one of "
                        f"{{ALL, STANDARD, {valid}}}"
                    ) from exc
        return result

    def names(self) -> list[str]:
        """Return the flag names that are active in this bitmask."""
        return [m.name for m in type(self) if m and m.name and m & self]
