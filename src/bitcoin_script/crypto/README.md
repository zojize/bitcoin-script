# crypto

Cryptographic primitives used by the script engine and transaction verification.

- `hashing.py` — Thin wrappers around `hashlib`: `sha256`, `hash256` (double SHA-256), `ripemd160`, `hash160` (RIPEMD160(SHA256)), and `sha1`.
- `secp256k1.py` — ECDSA and Schnorr signature verification on the secp256k1 curve, delegating to `python-bitcoinlib`. Accepts both compressed (33-byte) and uncompressed (65-byte) public keys.
- `signature.py` — DER encoding validation (BIP66), signature parsing into (r, s) integers, low-S enforcement (BIP62), and sighash type byte extraction.
