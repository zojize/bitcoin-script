"""Tests using real Bitcoin mainnet transactions.

Block 170: First-ever P2PK spend (Satoshi -> Hal Finney, 2009-01-12)
  txid: 169e1e83e930853391bc6f35f605c6754cfead57cf8387639d3b4096c54f18f4

Block 50061: P2PKH spend
  txid: ea08bd98d96bfbc3631ee0ee7135ac58c546740910d70a983396c58b01280e92

Block 165084: First bare 1-of-2 multisig spend (2012-02-03)
  txid: 23b397edccd3740a74adb603c9756370fafcde9bcc4483eb271ecad09a94dd63
  spends output 0 of: 60a20bd93aa49ab4b28d514ec10b06e1829ce6818ec06cd3aabd013ebcdc4bb1

Block 462235: 2-of-3 bare multisig spend
  txid: 949591ad468cef5c41656c0a502d9500671ee421fadb590fbc6373000039b693
  spends output 0 of: 581d30e2a73a2db683ac2f15d53590bd0cd72de52555c2722d9d6a78e9fea510
"""

from __future__ import annotations

import pytest

from bitcoin_script.k_semantics import KBitcoinScript
from .script_helpers import script, push

pytestmark = pytest.mark.k


# ─── Block 170: first P2PK spend (Satoshi -> Hal Finney) ───────────────
# scriptPubKey: <pubkey> OP_CHECKSIG
# scriptSig:    <sig>

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
BLOCK170_SIGHASH = "7a05c6145f10101e9d6325494245adf1297d80f8f38d4d576d57cdba220bcb19"


# ─── Block 50061: P2PKH spend ──────────────────────────────────────────
# scriptPubKey: OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG
# scriptSig:    <sig> <pubkey>

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
BLOCK50061_SIGHASH = "50d5ed5011b4a41877f3bd0678f747235425dd9dbd313a38d8fad6a35c937db6"


# ─── Block 165084: first bare 1-of-2 multisig spend ──────────────────
# scriptPubKey: OP_1 <pk1> <pk2> OP_2 OP_CHECKMULTISIG
# scriptSig:    OP_0 <sig>

BLOCK165084_PUBKEY_1 = (
    "04"
    "cc71eb30d653c0c3163990c47b976f3fb3f37cccdcbedb169a1dfef58bbfbfaf"
    "f7d8a473e7e2e6d317b87bafe8bde97e3cf8f065dec022b51d11fcdd0d348ac4"
)
BLOCK165084_PUBKEY_2 = (
    "04"
    "61cbdcc5409fb4b4d42b51d33381354d80e550078cb532a34bfa2fcfdeb7d765"
    "19aecc62770f5b0e4ef8551946d8a540911abe3e7854a26f39f58b25c15342af"
)
# DER-encoded signature with SIGHASH_ALL (71 bytes)
BLOCK165084_SIG_DER = (
    "304402203f16c6f40162ab686621ef3000b04e75418a0c0cb2d8aebeac894ae3"
    "60ac1e780220ddc15ecdfc3507ac48e1681a33eb60996631bf6bf5bc0a0682c4"
    "db743ce7ca2b01"
)
BLOCK165084_SIGHASH = "259d83e4174d7a386542918b53294b6d0affd82b2939d37f5066d296f36914c2"


# ─── Block 462235: 2-of-3 bare multisig spend ────────────────────────
# scriptPubKey: OP_2 <pk1> <pk2> <pk3> OP_3 OP_CHECKMULTISIG
# scriptSig:    OP_0 <sig1> <sig2>

BLOCK462235_PUBKEY_1 = (
    "04"
    "d81fd577272bbe73308c93009eec5dc9fc319fc1ee2e7066e17220a5d47a1831"
    "4578be2faea34b9f1f8ca078f8621acd4bc22897b03daa422b9bf56646b342a2"
)
BLOCK462235_PUBKEY_2 = (
    "04"
    "ec3afff0b2b66e8152e9018fe3be3fc92b30bf886b3487a525997d00fd9da2d0"
    "12dce5d5275854adc3106572a5d1e12d4211b228429f5a7b2f7ba92eb0475bb1"
)
BLOCK462235_PUBKEY_3 = (
    "04"
    "b49b496684b02855bc32f5daefa2e2e406db4418f3b86bca5195600951c7d918"
    "cdbe5e6d3736ec2abf2dd7610995c3086976b2c0c7b4e459d10b34a316d5a5e7"
)
# DER-encoded signature 1 with SIGHASH_ALL (72 bytes)
BLOCK462235_SIG1_DER = (
    "3045022100af204ef91b8dba5884df50f87219ccef22014c21dd05aa44470d4e"
    "d800b7f6e40220428fe058684db1bb2bfb6061bff67048592c574effc217f0d1"
    "50daedcf36787601"
)
# DER-encoded signature 2 with SIGHASH_ALL (72 bytes)
BLOCK462235_SIG2_DER = (
    "3045022100e8547aa2c2a2761a5a28806d3ae0d1bbf0aeff782f9081dfea67b8"
    "6cacb321340220771a166929469c34959daf726a2ac0c253f9aff391e58a3c7c"
    "b46d8b7e0fdc4801"
)
BLOCK462235_SIGHASH = "68b105368501703f4d28fcaeb846a43f869741a38b5265308c5a8ec237845afb"


class TestP2PKBlock170:
    """Verify the first-ever Bitcoin P2PK spend (block 170, Satoshi -> Hal Finney)."""

    def test_checksig_passes(self, k: KBitcoinScript) -> None:
        # scriptSig: <sig>
        # scriptPubKey: <pubkey> OP_CHECKSIG
        result = k.verify_script(
            script_sig=script(push(BLOCK170_SIG_DER)),
            script_pubkey=script(push(BLOCK170_PUBKEY), "OP_CHECKSIG"),
            sighash=bytes.fromhex(BLOCK170_SIGHASH),
        )
        assert not k.is_stuck(result)
        assert k.success(result)
        assert k.stack(result) == [b"\x01"]

    def test_wrong_sighash_fails(self, k: KBitcoinScript) -> None:
        wrong_hash = "ab" * 32
        result = k.verify_script(
            script_sig=script(push(BLOCK170_SIG_DER)),
            script_pubkey=script(push(BLOCK170_PUBKEY), "OP_CHECKSIG"),
            sighash=bytes.fromhex(wrong_hash),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b""]


class TestP2PKHBlock50061:
    """Verify a real P2PKH spend from block 50061."""

    def test_full_p2pkh(self, k: KBitcoinScript) -> None:
        # scriptSig: <sig> <pubkey>
        # scriptPubKey: OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG
        result = k.verify_script(
            script_sig=script(push(BLOCK50061_SIG_DER), push(BLOCK50061_PUBKEY)),
            script_pubkey=script(
                "OP_DUP",
                "OP_HASH160",
                push(BLOCK50061_PUBKEY_HASH),
                "OP_EQUALVERIFY",
                "OP_CHECKSIG",
            ),
            sighash=bytes.fromhex(BLOCK50061_SIGHASH),
        )
        assert not k.is_stuck(result)
        assert k.success(result)
        assert k.stack(result) == [b"\x01"]

    def test_wrong_pubkey_hash_stuck(self, k: KBitcoinScript) -> None:
        """EQUALVERIFY should get stuck when pubkey hash doesn't match."""
        wrong_hash = "dead" + "00" * 18
        result = k.verify_script(
            script_sig=script(push(BLOCK50061_SIG_DER), push(BLOCK50061_PUBKEY)),
            script_pubkey=script(
                "OP_DUP",
                "OP_HASH160",
                push(wrong_hash),
                "OP_EQUALVERIFY",
                "OP_CHECKSIG",
            ),
            sighash=bytes.fromhex(BLOCK50061_SIGHASH),
        )
        assert k.is_stuck(result)

    def test_wrong_sighash_pushes_0(self, k: KBitcoinScript) -> None:
        """With correct pubkey hash but wrong sighash, CHECKSIG should push 0."""
        wrong_hash = "ff" * 32
        result = k.verify_script(
            script_sig=script(push(BLOCK50061_SIG_DER), push(BLOCK50061_PUBKEY)),
            script_pubkey=script(
                "OP_DUP",
                "OP_HASH160",
                push(BLOCK50061_PUBKEY_HASH),
                "OP_EQUALVERIFY",
                "OP_CHECKSIG",
            ),
            sighash=bytes.fromhex(wrong_hash),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b""]


class TestBareMultisig1of2Block165084:
    """Verify the first bare 1-of-2 multisig spend (block 165084, 2012-02-03)."""

    def test_checkmultisig_passes(self, k: KBitcoinScript) -> None:
        # scriptSig: OP_0 <sig>
        # scriptPubKey: OP_1 <pk1> <pk2> OP_2 OP_CHECKMULTISIG
        result = k.verify_script(
            script_sig=script("OP_0", push(BLOCK165084_SIG_DER)),
            script_pubkey=script(
                "OP_1",
                push(BLOCK165084_PUBKEY_1),
                push(BLOCK165084_PUBKEY_2),
                "OP_2",
                "OP_CHECKMULTISIG",
            ),
            sighash=bytes.fromhex(BLOCK165084_SIGHASH),
        )
        assert not k.is_stuck(result)
        assert k.success(result)
        assert k.stack(result) == [b"\x01"]

    def test_wrong_sighash_fails(self, k: KBitcoinScript) -> None:
        wrong_hash = "ab" * 32
        result = k.verify_script(
            script_sig=script("OP_0", push(BLOCK165084_SIG_DER)),
            script_pubkey=script(
                "OP_1",
                push(BLOCK165084_PUBKEY_1),
                push(BLOCK165084_PUBKEY_2),
                "OP_2",
                "OP_CHECKMULTISIG",
            ),
            sighash=bytes.fromhex(wrong_hash),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b""]


class TestBareMultisig2of3Block462235:
    """Verify a real 2-of-3 bare multisig spend (block 462235)."""

    def test_checkmultisig_passes(self, k: KBitcoinScript) -> None:
        # scriptSig: OP_0 <sig1> <sig2>
        # scriptPubKey: OP_2 <pk1> <pk2> <pk3> OP_3 OP_CHECKMULTISIG
        result = k.verify_script(
            script_sig=script(
                "OP_0",
                push(BLOCK462235_SIG1_DER),
                push(BLOCK462235_SIG2_DER),
            ),
            script_pubkey=script(
                "OP_2",
                push(BLOCK462235_PUBKEY_1),
                push(BLOCK462235_PUBKEY_2),
                push(BLOCK462235_PUBKEY_3),
                "OP_3",
                "OP_CHECKMULTISIG",
            ),
            sighash=bytes.fromhex(BLOCK462235_SIGHASH),
        )
        assert not k.is_stuck(result)
        assert k.success(result)
        assert k.stack(result) == [b"\x01"]

    def test_wrong_sighash_fails(self, k: KBitcoinScript) -> None:
        wrong_hash = "ab" * 32
        result = k.verify_script(
            script_sig=script(
                "OP_0",
                push(BLOCK462235_SIG1_DER),
                push(BLOCK462235_SIG2_DER),
            ),
            script_pubkey=script(
                "OP_2",
                push(BLOCK462235_PUBKEY_1),
                push(BLOCK462235_PUBKEY_2),
                push(BLOCK462235_PUBKEY_3),
                "OP_3",
                "OP_CHECKMULTISIG",
            ),
            sighash=bytes.fromhex(wrong_hash),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b""]

    def test_only_one_sig_fails(self, k: KBitcoinScript) -> None:
        """2-of-3 with only one valid signature should fail."""
        wrong_sig = BLOCK165084_SIG_DER
        result = k.verify_script(
            script_sig=script(
                "OP_0",
                push(BLOCK462235_SIG1_DER),
                push(wrong_sig),
            ),
            script_pubkey=script(
                "OP_2",
                push(BLOCK462235_PUBKEY_1),
                push(BLOCK462235_PUBKEY_2),
                push(BLOCK462235_PUBKEY_3),
                "OP_3",
                "OP_CHECKMULTISIG",
            ),
            sighash=bytes.fromhex(BLOCK462235_SIGHASH),
        )
        assert not k.is_stuck(result)
        assert k.stack(result) == [b""]
