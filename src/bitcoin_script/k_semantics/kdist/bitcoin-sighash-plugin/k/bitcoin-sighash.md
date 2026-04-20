Bitcoin Sighash Streaming Plugin
================================

Bitcoin-specific bulk SHA-256 streaming hooks. Each hook parses a slice
of Bitcoin's wire-format transaction, walks vins / vouts / prevouts, and
feeds each per-record chunk to `SHA256_Update` in a tight C loop. The K
side exposes pure recursive equivalents so the Haskell prover can reason
about the sighash structure; the hooks are the fast path for LLVM-backend
execution.

State layout: each hook takes a `Bytes` midstate — the raw byte image of
an OpenSSL `SHA256_CTX`, identical to what `KRYPTO.sha256Init/Update/Final`
(in the sibling blockchain-k-plugin) produces. That makes the streams
interchangeable with a run of plain per-chunk `Sha256Update` calls, modulo
the per-record wire-format parsing these hooks do internally.

Equivalence lemmas (in lemmas.k) assert that each bulk hook produces the
same midstate as the corresponding pure K walker — this is the trust
boundary. See `#streamOutpointsPure`, `#streamSequencesPure`, etc.

```k
module BITCOIN-SIGHASH
  imports BYTES
  imports INT

  // Stream all 36-byte outpoints for N vins starting at byte offset O
  // within the wire-format tx.
  syntax Bytes ::= BitcoinOutpointsStream(Bytes, Bytes, Int, Int)
                   [function, total, hook(BITCOIN.outpointsStream)]

  // Stream all 4-byte LE sequences for N vins starting at O.
  syntax Bytes ::= BitcoinSequencesStream(Bytes, Bytes, Int, Int)
                   [function, total, hook(BITCOIN.sequencesStream)]

  // Stream all serialized vouts (amount || cs_len || spk) for N vouts
  // starting at O.
  syntax Bytes ::= BitcoinVoutsStream(Bytes, Bytes, Int, Int)
                   [function, total, hook(BITCOIN.voutsStream)]

  // Stream 8-byte LE amounts from a prevouts blob (vout-layout) for
  // N records starting at offset 0.
  syntax Bytes ::= BitcoinPrevoutAmountsStream(Bytes, Bytes, Int)
                   [function, total, hook(BITCOIN.prevoutAmountsStream)]

  // Stream each prevout's cs_len||spk (skipping the amount) for N
  // records starting at offset 0.
  syntax Bytes ::= BitcoinPrevoutScriptsStream(Bytes, Bytes, Int)
                   [function, total, hook(BITCOIN.prevoutScriptsStream)]

  // Stream the legacy modified-vins block: compactSize(n) prefix plus
  // N modified vins. Target vin (index = sig_idx) emits its outpoint,
  // the caller-supplied scriptCode (with its own cs length prefix), and
  // its original 4-byte sequence. Other vins emit outpoint, 0x00 empty
  // scriptSig, and either the original sequence (SIGHASH_ALL) or zeros
  // (SIGHASH_NONE / SIGHASH_SINGLE).
  syntax Bytes ::= BitcoinLegacyVinsBlockStream(Bytes, Bytes, Int, Int, Int, Bytes, Int)
                   [function, total, hook(BITCOIN.legacyVinsBlockStream)]

  // Stream the legacy modified-vouts block: compactSize(n) prefix plus
  // N modified vouts. For SIGHASH_SINGLE, vouts before sig_idx are
  // replaced with an 8-byte 0xff amount + empty scriptPubKey placeholder.
  // For SIGHASH_NONE the caller passes n=0. For SIGHASH_ALL the real
  // vouts pass through.
  syntax Bytes ::= BitcoinLegacyVoutsBlockStream(Bytes, Bytes, Int, Int, Int, Int)
                   [function, total, hook(BITCOIN.legacyVoutsBlockStream)]

endmodule
```
