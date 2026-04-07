"""Map block height/timestamp to active Bitcoin consensus verification flags.

Based on Bitcoin Core's GetBlockScriptFlags() in src/validation.cpp.
Covers all soft forks from genesis through SegWit activation (block 481,824).
"""

from __future__ import annotations

# Flag bitmask values (must match K semantics and conftest.py)
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
DISCOURAGE_UPGRADABLE_WITNESS = 1 << 12
MINIMALIF = 1 << 13
NULLFAIL = 1 << 14
WITNESS_PUBKEYTYPE = 1 << 15

# BIP 16 activates based on timestamp, not height
_BIP16_TIMESTAMP = 1333238400  # April 1, 2012

# BIP 66 (DERSIG) activation height on mainnet
_BIP66_HEIGHT = 363725

# BIP 65 (CLTV) activation height on mainnet
_BIP65_HEIGHT = 388381

# BIP 68/112/113 (CSV + relative locktime) activation height on mainnet
_BIP68_HEIGHT = 419328

# BIP 141/143/147 (SegWit) activation height on mainnet
_SEGWIT_HEIGHT = 481824


def flags_for_block(height: int, timestamp: int) -> int:
    """Return the bitmask of active SCRIPT_VERIFY_* flags at this block.

    Args:
        height: Block height.
        timestamp: Block header timestamp (nTime).

    Returns:
        Bitmask of active verification flags.
    """
    flags = 0

    # BIP 16: P2SH (timestamp-based activation)
    if timestamp >= _BIP16_TIMESTAMP:
        flags |= P2SH

    # BIP 66: strict DER signatures
    if height >= _BIP66_HEIGHT:
        flags |= DERSIG

    # BIP 65: OP_CHECKLOCKTIMEVERIFY
    if height >= _BIP65_HEIGHT:
        flags |= CHECKLOCKTIMEVERIFY

    # BIP 68/112/113: relative lock-time (CSV)
    if height >= _BIP68_HEIGHT:
        flags |= CHECKSEQUENCEVERIFY

    # BIP 141/143/147: Segregated Witness + associated rules
    if height >= _SEGWIT_HEIGHT:
        flags |= (
            WITNESS
            | NULLDUMMY
            | STRICTENC
            | LOW_S
            | NULLFAIL
            | SIGPUSHONLY
            | MINIMALDATA
            | CLEANSTACK
            | DISCOURAGE_UPGRADABLE_NOPS
            | MINIMALIF
            | WITNESS_PUBKEYTYPE
        )

    return flags
