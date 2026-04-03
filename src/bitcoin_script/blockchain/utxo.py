"""SQLite-backed Unspent Transaction Output (UTXO) set tracking."""

from __future__ import annotations

import sqlite3
from pathlib import Path


class UTXOSet:
    """Track the set of unspent transaction outputs using SQLite.

    During blockchain validation, this maintains the current UTXO set
    by adding new outputs and removing spent ones. Changes are batched
    within a SQLite transaction and committed per block.
    """

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self._conn = sqlite3.connect(str(db_path))
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS utxos (
                txid   BLOB NOT NULL,
                vout   INTEGER NOT NULL,
                script BLOB NOT NULL,
                amount INTEGER NOT NULL,
                PRIMARY KEY (txid, vout)
            )
        """)
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS meta (
                key   TEXT PRIMARY KEY,
                value INTEGER NOT NULL
            )
        """)
        self._conn.execute(
            "INSERT OR IGNORE INTO meta (key, value) VALUES ('height', -1)"
        )
        self._conn.commit()

    def __enter__(self) -> UTXOSet:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def add(
        self,
        txid: bytes,
        vout: int,
        script: bytes,
        amount: int,
        *,
        allow_overwrite: bool = False,
    ) -> None:
        """Add a new unspent output.

        By default raises sqlite3.IntegrityError on duplicate (txid, vout).
        Use allow_overwrite=True only for BIP-30 exception blocks (91842, 91880).
        """
        sql = (
            "INSERT OR REPLACE" if allow_overwrite else "INSERT"
        ) + " INTO utxos (txid, vout, script, amount) VALUES (?, ?, ?, ?)"
        self._conn.execute(sql, (txid, vout, script, amount))

    def spend(self, txid: bytes, vout: int) -> tuple[bytes, int]:
        """Remove an output and return (scriptPubKey, amount).

        Raises KeyError if the outpoint is not in the UTXO set.
        """
        cur = self._conn.execute(
            "SELECT script, amount FROM utxos WHERE txid = ? AND vout = ?",
            (txid, vout),
        )
        row = cur.fetchone()
        if row is None:
            raise KeyError(f"UTXO not found: {txid.hex()}:{vout}")
        self._conn.execute(
            "DELETE FROM utxos WHERE txid = ? AND vout = ?", (txid, vout)
        )
        return (row[0], row[1])

    def get(self, txid: bytes, vout: int) -> tuple[bytes, int] | None:
        """Look up an unspent output. Returns (scriptPubKey, amount) or None."""
        cur = self._conn.execute(
            "SELECT script, amount FROM utxos WHERE txid = ? AND vout = ?",
            (txid, vout),
        )
        row = cur.fetchone()
        return (row[0], row[1]) if row else None

    def commit(self) -> None:
        """Flush pending changes to disk."""
        self._conn.commit()

    def size(self) -> int:
        """Return the number of unspent outputs."""
        cur = self._conn.execute("SELECT COUNT(*) FROM utxos")
        return cur.fetchone()[0]

    @property
    def checkpoint_height(self) -> int:
        """Last committed block height (-1 if empty)."""
        cur = self._conn.execute("SELECT value FROM meta WHERE key = 'height'")
        return cur.fetchone()[0]

    @checkpoint_height.setter
    def checkpoint_height(self, height: int) -> None:
        self._conn.execute("UPDATE meta SET value = ? WHERE key = 'height'", (height,))

    def close(self) -> None:
        self._conn.close()
