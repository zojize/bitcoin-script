"""Unspent Transaction Output (UTXO) set tracking."""

from __future__ import annotations

from bitcoin_script.model.transaction import OutPoint, TxOut


class UTXOSet:
    """Track the set of unspent transaction outputs.

    During blockchain validation, this maintains the current UTXO set
    by adding new outputs and removing spent ones.
    """

    _utxos: dict[OutPoint, TxOut]

    def __init__(self) -> None:
        """Initialize an empty UTXO set."""
        ...

    def add(self, outpoint: OutPoint, txout: TxOut) -> None:
        """Add a new unspent output.

        Args:
            outpoint: The outpoint identifying this output.
            txout: The transaction output data.
        """
        ...

    def spend(self, outpoint: OutPoint) -> TxOut:
        """Mark an output as spent and return it.

        Args:
            outpoint: The outpoint to spend.

        Returns:
            The spent TxOut.

        Raises:
            KeyError: If the outpoint is not in the UTXO set.
        """
        ...

    def get(self, outpoint: OutPoint) -> TxOut | None:
        """Look up an unspent output.

        Args:
            outpoint: The outpoint to look up.

        Returns:
            The TxOut if found, None otherwise.
        """
        ...

    def contains(self, outpoint: OutPoint) -> bool:
        """Check if an outpoint exists in the UTXO set."""
        ...

    def size(self) -> int:
        """Return the number of unspent outputs."""
        ...
