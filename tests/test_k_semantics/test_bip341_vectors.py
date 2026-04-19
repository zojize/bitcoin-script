"""End-to-end validation of BIP-341 key-path sighash against the reference
wallet-test-vectors.json from bitcoin/bips.

Strategy: load the fully-signed transaction and prevouts from the reference
vector, then verify each taproot key-path input through K. Schnorr signature
verification only succeeds with the exact reference sighash, so passing
verification proves the K-side #bip341Sighash matches byte-for-byte.
"""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path

import pytest
from bitcoin.core import CTransaction

from bitcoin_script.script_utils import encode_witness_blob, is_witness_program

pytestmark = pytest.mark.k

_DATA_DIR = Path(__file__).parent / "data"
_BIP341_PATH = _DATA_DIR / "bip341-wallet-test-vectors.json"
_BIP341_URL = "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0341/wallet-test-vectors.json"


def _compact_size(n: int) -> bytes:
    if n <= 252:
        return n.to_bytes(1, "little")
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def _load_bip341() -> dict:
    _DATA_DIR.mkdir(exist_ok=True)
    if not _BIP341_PATH.exists():
        urllib.request.urlretrieve(_BIP341_URL, _BIP341_PATH)
    return json.loads(_BIP341_PATH.read_text())


def _serialize_prevouts(utxos: list[dict]) -> bytes:
    """Serialize BIP-341 ``utxosSpent`` into the <prevouts> blob format:
    concat of <8-byte LE amount><compactSize spk_len><scriptPubKey> per vin.
    """
    out = b""
    for u in utxos:
        amount = int(u["amountSats"])
        spk = bytes.fromhex(u["scriptPubKey"])
        out += amount.to_bytes(8, "little") + _compact_size(len(spk)) + spk
    return out


def _taproot_keypath_inputs(tx: CTransaction, utxos: list[dict]) -> list[int]:
    """Return indices of inputs that are taproot key-path (1-item witness,
    32-byte witness program, sig is 64 or 65 bytes)."""
    result: list[int] = []
    for i in range(len(tx.vin)):
        spk = bytes.fromhex(utxos[i]["scriptPubKey"])
        wp = is_witness_program(spk)
        if wp is None or wp[0] != 1 or len(wp[1]) != 32:
            continue
        if not tx.wit or i >= len(tx.wit.vtxinwit):
            continue
        stack = [bytes(w) for w in tx.wit.vtxinwit[i].scriptWitness.stack]
        if len(stack) != 1:
            continue  # script-path or annex present
        sig_len = len(stack[0])
        if sig_len not in (64, 65):
            continue
        result.append(i)
    return result


_TAPROOT_FLAGS = (
    0x01  # P2SH
    | 0x0800  # WITNESS
    | 0x20000  # TAPROOT
)


def _bip341_taproot_inputs():
    v = _load_bip341()
    ks = v["keyPathSpending"][0]
    tx_hex = ks["auxiliary"]["fullySignedTx"]
    utxos = ks["given"]["utxosSpent"]
    tx = CTransaction.deserialize(bytes.fromhex(tx_hex))
    tx_bytes = bytes.fromhex(tx_hex)
    prevouts = _serialize_prevouts(utxos)
    indices = _taproot_keypath_inputs(tx, utxos)
    return [(idx, tx_bytes, prevouts, tx, utxos) for idx in indices]


@pytest.mark.parametrize(
    "input_index,tx_bytes,prevouts,tx,utxos",
    _bip341_taproot_inputs(),
    ids=lambda p: f"input_{p}" if isinstance(p, int) else "",
)
def test_bip341_keypath_input(k, input_index, tx_bytes, prevouts, tx, utxos):
    """Each BIP-341 taproot key-path input should verify through the
    K-side #bip341Sighash path. Success here proves byte-exact sighash
    match against the reference wallet-test-vectors."""
    vin = tx.vin[input_index]
    script_pubkey = bytes.fromhex(utxos[input_index]["scriptPubKey"])
    amount = int(utxos[input_index]["amountSats"])
    script_sig = bytes(vin.scriptSig)

    witness_items = [bytes(w) for w in tx.wit.vtxinwit[input_index].scriptWitness.stack]
    witness_blob = encode_witness_blob(witness_items)

    result = k.verify_script(
        script_sig=script_sig,
        script_pubkey=script_pubkey,
        sighash=b"",  # no blob — force K-side path
        witness=witness_blob,
        flags=_TAPROOT_FLAGS,
        tx_version=tx.nVersion,
        n_locktime=tx.nLockTime,
        n_sequence=vin.nSequence,
        tx=tx_bytes,
        prevouts=prevouts,
        input_index=input_index,
        amount=amount,
    )

    assert k.success(result), f"BIP-341 input {input_index} failed: {k.error(result)}"
