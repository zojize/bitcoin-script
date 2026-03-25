"""Demo: parse local Bitcoin Core block files and print block/transaction info."""

from pathlib import Path
from itertools import islice
from typing import cast

from bitcoin.core.script import CScriptOp
from bitcoin.core import CTransaction

from bitcoin_script.blockchain.parser import BlockFileParser

MAX_TRANSACTIONS = 200

data_dir = Path.home() / "Library/Application Support/Bitcoin"
parser = BlockFileParser(data_dir)

blocks = islice(parser.iter_blocks(start=170000), 5) 

tx_count = 0
for block in blocks:
    block_hash = block.GetHash()[::-1].hex()
    print(f"Block {block_hash}")
    print(f"  prev:  {block.hashPrevBlock[::-1].hex()}")
    print(f"  time:  {block.nTime}  nonce: {block.nNonce}")
    print(f"  txs:   {len(block.vtx)}")

    for tx in cast(list[CTransaction], block.vtx):
        txid = tx.GetHash()[::-1].hex()
        print(f"  tx {txid}")
        for i, inp in enumerate(tx.vin):
            print(f"    vin[{i}]  scriptSig:")
            for op in inp.scriptSig:
                if isinstance(op, bytes):
                    print(f"             PUSH {op.hex()}")
                else:
                    print(f"             {CScriptOp(op)}")
        for i, out in enumerate(tx.vout):
            print(f"    vout[{i}] {out.nValue / 1e8:.8f} BTC  scriptPubKey:")
            for op in out.scriptPubKey:
                if isinstance(op, bytes):
                    print(f"             PUSH {op.hex()}")
                else:
                    print(f"             {CScriptOp(op)}")

        tx_count += 1
        if tx_count >= MAX_TRANSACTIONS:
            break

    if tx_count >= MAX_TRANSACTIONS:
        break
