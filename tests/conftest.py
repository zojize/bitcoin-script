"""Shared test fixtures for the bitcoin_script test suite."""

from __future__ import annotations

import pytest
from bitcoin.core import CMutableTxIn, CMutableTxOut, COutPoint, CTransaction
from bitcoin.core.script import CScript

from bitcoin_script.engine.stack import ScriptStack


@pytest.fixture
def empty_stack() -> ScriptStack:
    """A fresh empty script execution stack."""
    ...


@pytest.fixture
def genesis_coinbase_tx() -> CTransaction:
    """The genesis block (block 0) coinbase transaction."""
    ...


@pytest.fixture
def p2pkh_script_pubkey() -> CScript:
    """A sample P2PKH scriptPubKey.

    OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
    """
    ...


@pytest.fixture
def p2pkh_script_sig() -> CScript:
    """A sample P2PKH scriptSig matching p2pkh_script_pubkey.

    <signature> <pubkey>
    """
    ...


@pytest.fixture
def p2sh_script_pubkey() -> CScript:
    """A sample P2SH scriptPubKey.

    OP_HASH160 <20-byte-hash> OP_EQUAL
    """
    ...


@pytest.fixture
def p2wpkh_script_pubkey() -> CScript:
    """A sample P2WPKH scriptPubKey.

    OP_0 <20-byte-hash>
    """
    ...


@pytest.fixture
def sample_outpoint() -> COutPoint:
    """A sample outpoint referencing a previous transaction output."""
    ...


@pytest.fixture
def sample_txin(sample_outpoint: COutPoint) -> CMutableTxIn:
    """A sample transaction input."""
    ...


@pytest.fixture
def sample_txout() -> CMutableTxOut:
    """A sample transaction output."""
    ...
