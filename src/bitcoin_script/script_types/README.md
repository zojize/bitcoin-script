# script_types

Standard script template recognition and construction. Each module handles one Bitcoin address/script type.

- `classifier.py` — `classify(script) -> ScriptType` identifies scripts by matching against known byte patterns. Also exposes individual `is_p2pkh`, `is_p2sh`, `is_p2wpkh`, `is_p2wsh`, `is_multisig`, `is_null_data` predicates.
- `p2pkh.py` — Pay-to-Public-Key-Hash. Extract/create scriptPubKey (`OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG`) and scriptSig (`<sig> <pubkey>`).
- `p2sh.py` — Pay-to-Script-Hash. Extract/create scriptPubKey (`OP_HASH160 <hash> OP_EQUAL`) and deserialize the redeem script from scriptSig.
- `p2wpkh.py` — Pay-to-Witness-Public-Key-Hash (SegWit v0). Extract/create scriptPubKey (`OP_0 <20-byte-hash>`) and generate the BIP143 script code.
- `p2wsh.py` — Pay-to-Witness-Script-Hash (SegWit v0). Extract/create scriptPubKey (`OP_0 <32-byte-hash>`) and extract the witness script from the witness stack.
