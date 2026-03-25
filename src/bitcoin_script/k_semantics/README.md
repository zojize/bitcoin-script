# k_semantics

Formal K Framework semantics for Bitcoin Script, built on [pyk](https://github.com/runtimeverification/pyk) and the [blockchain-k-plugin](https://github.com/runtimeverification/blockchain-k-plugin) for crypto primitives.

## Architecture

- `semantics.py` — `KBitcoinScript` Python interface: parse ASM text, run via LLVM backend, extract stack/success results.
- `kdist/plugin.py` — kdist build plugin: compiles K source, builds `blockchain-k-plugin` crypto library, links everything together.
- `kdist/script-semantics/script.k` — K definition with CScriptNum bytes-only stack, covering:
  - **Push opcodes**: `OP_0`..`OP_16`, `OP_PUSH`, `OP_PUSHBYTES_{20,32,33,65,70,71,72,73}`
  - **Arithmetic**: `OP_ADD`
  - **Stack**: `OP_DUP`
  - **Crypto**: `OP_HASH160`, `OP_CHECKSIG`, `OP_CHECKMULTISIG`
  - **Verification**: `OP_EQUALVERIFY`
- `kdist/plugin/` — `blockchain-k-plugin` git submodule (KRYPTO module: SHA256, RIPEMD160, ECDSARecover, etc.)

## Building

```sh
uv run kdist build bitcoin-script-semantics.llvm
```

## Testing

```sh
uv run pytest tests/test_k_semantics/ -m k -v
```
