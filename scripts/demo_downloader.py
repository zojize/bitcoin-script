"""Demo script for BlockchainDownloader.

Usage (regtest — auto-starts a local node)::

    uv run python scripts/demo_downloader.py

Usage (mainnet — requires a running Bitcoin Core node)::

    BITCOIN_RPC_URL=http://user:pass@127.0.0.1:8332 uv run python scripts/demo_downloader.py
"""

from __future__ import annotations

import os
import resource
import shutil
import subprocess
import sys
import tempfile
import time

from bitcoin_script.blockchain.downloader import BlockchainDownloader


def start_regtest_node() -> tuple[subprocess.Popen[bytes], str, str]:
    """Start a temporary regtest node. Returns (process, datadir, rpc_url)."""
    conf = os.path.join(
        os.path.dirname(__file__), "..", "tests", "bitcoin-regtest.conf"
    )
    conf = os.path.abspath(conf)
    datadir = tempfile.mkdtemp(prefix="btc-regtest-")

    def _set_fd_limit() -> None:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft == resource.RLIM_INFINITY:
            resource.setrlimit(resource.RLIMIT_NOFILE, (4096, hard))

    proc = subprocess.Popen(
        ["bitcoind", "-regtest", f"-datadir={datadir}", f"-conf={conf}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        preexec_fn=_set_fd_limit,
    )

    cli = ["bitcoin-cli", "-regtest", "-rpcuser=test", "-rpcpassword=test"]
    for _ in range(30):
        try:
            subprocess.run([*cli, "getblockchaininfo"], capture_output=True, check=True)
            break
        except subprocess.CalledProcessError, FileNotFoundError:
            time.sleep(0.5)
    else:
        proc.terminate()
        shutil.rmtree(datadir, ignore_errors=True)
        print("ERROR: bitcoind did not become ready", file=sys.stderr)
        sys.exit(1)

    rpc_url = "http://test:test@127.0.0.1:18443"
    return proc, datadir, rpc_url


def stop_regtest_node(proc: subprocess.Popen[bytes], datadir: str) -> None:
    cli = ["bitcoin-cli", "-regtest", "-rpcuser=test", "-rpcpassword=test"]
    subprocess.run(cli + ["stop"], capture_output=True)
    proc.wait(timeout=10)
    shutil.rmtree(datadir, ignore_errors=True)


def main() -> None:
    url = os.environ.get("BITCOIN_RPC_URL")
    managed_node = False
    proc = None
    datadir = ""

    if url:
        print(f"Using external node: {url}")
    else:
        if not shutil.which("bitcoind"):
            print(
                "ERROR: bitcoind not on PATH. Install Bitcoin Core first.",
                file=sys.stderr,
            )
            sys.exit(1)
        print("Starting temporary regtest node...")
        proc, datadir, url = start_regtest_node()
        managed_node = True
        print("Regtest node ready.\n")

    try:
        dl = BlockchainDownloader.from_url(url)
        info = dl.get_blockchain_info()
        chain = info["chain"]
        print(f"Connected to {chain} chain (height: {info['blocks']})\n")

        if chain == "regtest":
            # Generate blocks so we have something to fetch
            try:
                dl._proxy.createwallet("demo")
            except Exception:
                try:
                    dl._proxy.loadwallet("demo")
                except Exception:
                    pass
            addr = dl._proxy.getnewaddress()
            dl._proxy.generatetoaddress(10, addr)
            print("Generated 10 regtest blocks.\n")

        # --- Genesis block ---
        genesis = dl.get_block(0, verbosity=1)
        print("=== Genesis Block ===")
        if isinstance(genesis, dict):
            print(f"  Hash:        {genesis['hash']}")
            print(f"  Merkle root: {genesis['merkleroot']}")
            print(f"  Txns:        {len(genesis['tx'])}")
            print(f"  Coinbase tx: {genesis['tx'][0]}")
        else:
            print(f"  Hex:         {genesis}")
        print()

        # --- Raw hex ---
        raw_hex = dl.get_block_raw(0)
        print(f"Raw genesis hex ({len(raw_hex)} chars): {raw_hex[:80]}...")
        print()

        # --- Block range ---
        blocks = dl.download_blocks(start_height=0, end_height=9)
        print("=== Blocks 0-9 ===")
        for b in blocks:
            print(f"  Block {b['height']:>3}: {b['hash']}")
        print()

        # --- Chain verification ---
        ok = dl.verify_chain(up_to_height=9)
        print(f"Chain verification (0-9): {'PASS' if ok else 'FAIL'}")

    finally:
        if managed_node and proc:
            print("\nStopping regtest node...")
            stop_regtest_node(proc, datadir)
            print("Done.")


if __name__ == "__main__":
    main()
