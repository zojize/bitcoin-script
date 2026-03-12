# model

Immutable data structures representing Bitcoin's on-chain objects. All classes are frozen dataclasses with `from_bytes`/`to_bytes` serialization. No execution logic.

- `transaction.py` — `Transaction`, `TxIn`, `TxOut`, `OutPoint`. Handles both legacy and segwit serialization formats. Computes `txid`, `wtxid`, weight, and vsize.
- `script.py` — `Script` (thin bytes wrapper with hex/ASM conversion), `ScriptIterator` (yields opcode/data pairs), and `ScriptType` enum (P2PKH, P2SH, P2WPKH, P2WSH, etc.).
- `block.py` — `BlockHeader` (80-byte header with hash, target, difficulty) and `Block` (header + transactions with Merkle root and PoW validation).
- `witness.py` — `WitnessProgram` for parsing SegWit witness version and program from scriptPubKey.
- `sighash.py` — `SigHashType` flags (ALL, NONE, SINGLE, ANYONECANPAY) and signature hash computation for both legacy and BIP143 segwit formats.
