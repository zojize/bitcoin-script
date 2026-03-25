# k_semantics

Formal K Framework semantics for Bitcoin Script, built on [pyk](https://github.com/runtimeverification/pyk) and the [blockchain-k-plugin](https://github.com/runtimeverification/blockchain-k-plugin) for crypto primitives.

## Prerequisites

### K Framework

Install [kup](https://github.com/runtimeverification/kup) (the K package manager), then install K:

```sh
bash <(curl https://kframework.org/install)
kup install k
```

Verify the installation:

```sh
kompile --version
```

### Native dependencies

The blockchain-k-plugin compiles C/C++ crypto hooks that link against several system libraries.

**macOS (Homebrew):**

```sh
brew install cmake boost openssl libsecp256k1 gmp mpfr crypto++
```

**Ubuntu/Debian:**

```sh
sudo apt-get install -y \
  clang cmake pkg-config \
  libboost-test-dev libcrypto++-dev libsecp256k1-dev \
  libssl-dev libyaml-dev libgmp-dev libmpfr-dev \
  llvm-dev
```

### Git submodules

The blockchain-k-plugin is vendored as a git submodule. Make sure it's initialized:

```sh
git submodule update --init --recursive
```

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

This compiles the K definition with the LLVM backend. The build targets defined in `kdist/plugin.py` are:

| Target | Description |
|--------|-------------|
| `source` | Copies K source files |
| `plugin` | Builds the blockchain-k-plugin crypto library (`krypto.a`) |
| `llvm` | Kompiles via LLVM backend with crypto hooks |
| `llvm-lib` | Kompiles as a C library variant |

## Testing

```sh
uv run pytest -m k -v
```

All K semantics tests are marked with `@pytest.mark.k` and are excluded from the default test run.
