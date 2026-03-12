"""Script type classification by template matching."""

from __future__ import annotations

from bitcoin_script.model.script import Script, ScriptType


def classify(script: Script) -> ScriptType:
    """Identify the standard script template type.

    Inspects the raw script bytes to match against known templates:
    P2PKH, P2SH, P2WPKH, P2WSH, P2PK, bare multisig, null data.
    Returns NONSTANDARD if no template matches.
    """
    ...


def is_p2pkh(script: Script) -> bool:
    """Check if script matches P2PKH template.

    Pattern: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    """
    ...


def is_p2sh(script: Script) -> bool:
    """Check if script matches P2SH template.

    Pattern: OP_HASH160 <20 bytes> OP_EQUAL
    """
    ...


def is_p2wpkh(script: Script) -> bool:
    """Check if script matches P2WPKH template.

    Pattern: OP_0 <20 bytes>
    """
    ...


def is_p2wsh(script: Script) -> bool:
    """Check if script matches P2WSH template.

    Pattern: OP_0 <32 bytes>
    """
    ...


def is_p2pk(script: Script) -> bool:
    """Check if script matches P2PK template.

    Pattern: <33 or 65 bytes pubkey> OP_CHECKSIG
    """
    ...


def is_multisig(script: Script) -> bool:
    """Check if script matches bare multisig template.

    Pattern: OP_m <pubkey1> ... <pubkeyn> OP_n OP_CHECKMULTISIG
    """
    ...


def is_null_data(script: Script) -> bool:
    """Check if script matches null data (OP_RETURN) template.

    Pattern: OP_RETURN <data>
    """
    ...
