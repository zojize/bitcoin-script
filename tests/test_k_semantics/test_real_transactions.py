"""Tests using real Bitcoin mainnet transactions parsed from local block files.

Block 170: First-ever P2PK spend (Satoshi -> Hal Finney, 2009-01-12)
  txid: 169e1e83e930853391bc6f35f605c6754cfead57cf8387639d3b4096c54f18f4

Block 50061: P2PKH spend
  txid: ea08bd98d96bfbc3631ee0ee7135ac58c546740910d70a983396c58b01280e92
"""

from __future__ import annotations

import pytest

from bitcoin_script.k_semantics import KBitcoinScript

pytestmark = pytest.mark.k


@pytest.fixture(scope="session")
def k() -> KBitcoinScript:
    return KBitcoinScript()


# ─── Block 170: first P2PK spend (Satoshi -> Hal Finney) ───────────────
# scriptPubKey: <pubkey> OP_CHECKSIG
# scriptSig:    <sig>
# Combined:     <sig> <pubkey> OP_CHECKSIG

BLOCK170_PUBKEY = (
    "04"
    "11db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5c"
    "b2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3"
)
# DER-encoded signature with SIGHASH_ALL hashtype (71 bytes)
BLOCK170_SIG_DER = (
    "304402204e45e16932b8af514961a1d3a1a25fdf3f4f7732e9d624c6c61548ab"
    "5fb8cd410220181522ec8eca07de4860a4acdd12909d831cc56cbbac46220822"
    "21a8768d1d0901"
)
BLOCK170_SIGHASH = (
    "7a05c6145f10101e9d6325494245adf1297d80f8f38d4d576d57cdba220bcb19"
)


# ─── Block 50061: P2PKH spend ──────────────────────────────────────────
# scriptPubKey: OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG
# scriptSig:    <sig> <pubkey>
# Combined:     <sig> <pubkey> OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG

BLOCK50061_PUBKEY = (
    "04"
    "9bcd62ff50d753df3cc7ba6d2c4b580e7661b6e2669c679579fa643789704f14"
    "198cfe6978360468bab337c75ffc248b9e644e5fdf35fbdbc2eddb3c6bb0002c"
)
# DER-encoded signature with SIGHASH_ALL hashtype (72 bytes)
BLOCK50061_SIG_DER = (
    "3045022100a8956f06d62562eca7cc7c14b8af92e7648bc62070254f82261cc7"
    "940c4cbca002202eb022ee0e69da3d21a9370c4f085a2ab514bdd0b777dbba46"
    "27c15fc9f183db01"
)
BLOCK50061_PUBKEY_HASH = "fdae813ab5f1180dbbbed8e1e2ab1b5b30c9c166"
BLOCK50061_SIGHASH = (
    "50d5ed5011b4a41877f3bd0678f747235425dd9dbd313a38d8fad6a35c937db6"
)


class TestP2PKBlock170:
    """Verify the first-ever Bitcoin P2PK spend (block 170, Satoshi -> Hal Finney)."""

    def test_checksig_passes(self, k: KBitcoinScript) -> None:
        # Stack order: sighash (bottom), sig, pubkey (top)
        # P2PK combined: <sighash> <sig> <pubkey> OP_CHECKSIG
        script = (
            f"OP_PUSHBYTES_32 {BLOCK170_SIGHASH} "
            f"OP_PUSHBYTES_71 {BLOCK170_SIG_DER} "
            f"OP_PUSHBYTES_65 {BLOCK170_PUBKEY} "
            f"OP_CHECKSIG"
        )
        result = k.run(k.pattern(script))
        assert not k.is_stuck(result)
        assert k.success(result)
        assert k.stack(result) == [b"\x01"]

    def test_wrong_sighash_fails(self, k: KBitcoinScript) -> None:
        wrong_hash = "ab" * 32  # 64 hex chars, wrong sighash
        script = (
            f"OP_PUSHBYTES_32 {wrong_hash} "
            f"OP_PUSHBYTES_71 {BLOCK170_SIG_DER} "
            f"OP_PUSHBYTES_65 {BLOCK170_PUBKEY} "
            f"OP_CHECKSIG"
        )
        result = k.run(k.pattern(script))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b""]


class TestP2PKHBlock50061:
    """Verify a real P2PKH spend from block 50061."""

    def test_full_p2pkh(self, k: KBitcoinScript) -> None:
        # Combined: <sighash> <sig> <pubkey> OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG
        script = (
            f"OP_PUSHBYTES_32 {BLOCK50061_SIGHASH} "
            f"OP_PUSHBYTES_72 {BLOCK50061_SIG_DER} "
            f"OP_PUSHBYTES_65 {BLOCK50061_PUBKEY} "
            f"OP_DUP "
            f"OP_HASH160 "
            f"OP_PUSHBYTES_20 {BLOCK50061_PUBKEY_HASH} "
            f"OP_EQUALVERIFY "
            f"OP_CHECKSIG"
        )
        result = k.run(k.pattern(script))
        assert not k.is_stuck(result)
        assert k.success(result)
        assert k.stack(result) == [b"\x01"]

    def test_wrong_pubkey_hash_stuck(self, k: KBitcoinScript) -> None:
        """EQUALVERIFY should get stuck when pubkey hash doesn't match."""
        wrong_hash = "dead" + "00" * 18  # 40 hex chars, but wrong hash
        script = (
            f"OP_PUSHBYTES_32 {BLOCK50061_SIGHASH} "
            f"OP_PUSHBYTES_72 {BLOCK50061_SIG_DER} "
            f"OP_PUSHBYTES_65 {BLOCK50061_PUBKEY} "
            f"OP_DUP "
            f"OP_HASH160 "
            f"OP_PUSHBYTES_20 {wrong_hash} "
            f"OP_EQUALVERIFY "
            f"OP_CHECKSIG"
        )
        result = k.run(k.pattern(script))
        assert k.is_stuck(result)

    def test_wrong_sighash_pushes_0(self, k: KBitcoinScript) -> None:
        """With correct pubkey hash but wrong sighash, CHECKSIG should push 0."""
        wrong_hash = "ff" * 32
        script = (
            f"OP_PUSHBYTES_32 {wrong_hash} "
            f"OP_PUSHBYTES_72 {BLOCK50061_SIG_DER} "
            f"OP_PUSHBYTES_65 {BLOCK50061_PUBKEY} "
            f"OP_DUP "
            f"OP_HASH160 "
            f"OP_PUSHBYTES_20 {BLOCK50061_PUBKEY_HASH} "
            f"OP_EQUALVERIFY "
            f"OP_CHECKSIG"
        )
        result = k.run(k.pattern(script))
        assert not k.is_stuck(result)
        assert k.stack(result) == [b""]
