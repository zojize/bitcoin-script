"""Script verification flags mirroring Bitcoin Core's script/script_flags.h."""

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
