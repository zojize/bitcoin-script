requires "script-num.k"

// Transaction wire-format primitives: fixed-width LE integer reads and
// Bitcoin's self-describing compactSize varint. These are the building
// blocks for the BIP-143 / BIP-341 / BIP-342 / legacy sighash rules.
//
// Kept in a dedicated module so both SCRIPT-CRYPTO (which consumes them
// for sighash assembly) and SCRIPT-SEMANTICS (which routes CHECKSIG rules)
// can import them without a circular dependency.
module SCRIPT-TX
  imports SCRIPT-NUM
  imports BYTES
  imports INT
  imports BOOL

  // =========================================================================
  // Fixed-width little-endian unsigned integer reads
  // =========================================================================

  // Read a 4-byte LE unsigned int at offset O.
  syntax Int ::= #readUInt32LE(Bytes, Int) [function]
  rule #readUInt32LE(B, O) => Bytes2Int(substrBytes(B, O, O +Int 4), LE, Unsigned)

  // Read an 8-byte LE unsigned int at offset O.
  syntax Int ::= #readUInt64LE(Bytes, Int) [function]
  rule #readUInt64LE(B, O) => Bytes2Int(substrBytes(B, O, O +Int 8), LE, Unsigned)

  // =========================================================================
  // compactSize (Bitcoin's variable-length integer)
  //
  //   first byte in [0x00, 0xfc]   -> value = first byte  (1 byte total)
  //   first byte == 0xfd           -> next 2 bytes LE      (3 bytes total)
  //   first byte == 0xfe           -> next 4 bytes LE      (5 bytes total)
  //   first byte == 0xff           -> next 8 bytes LE      (9 bytes total)
  //
  // We split the "value" and "length" concerns into two helpers so callers
  // can advance their offset cleanly without re-parsing the tag byte.
  // =========================================================================

  // Decode the compactSize at offset O; returns the unsigned int value.
  syntax Int ::= #readCompactSize(Bytes, Int) [function]
  rule #readCompactSize(B, O) => #byteAt(B, O)
    requires #byteAt(B, O) <Int 253
  rule #readCompactSize(B, O) =>
         Bytes2Int(substrBytes(B, O +Int 1, O +Int 3), LE, Unsigned)
    requires #byteAt(B, O) ==Int 253
  rule #readCompactSize(B, O) =>
         Bytes2Int(substrBytes(B, O +Int 1, O +Int 5), LE, Unsigned)
    requires #byteAt(B, O) ==Int 254
  rule #readCompactSize(B, O) =>
         Bytes2Int(substrBytes(B, O +Int 1, O +Int 9), LE, Unsigned)
    requires #byteAt(B, O) ==Int 255

  // Number of bytes the compactSize at offset O occupies (1, 3, 5, or 9).
  syntax Int ::= #compactSizeBytes(Bytes, Int) [function]
  rule #compactSizeBytes(B, O) => 1 requires #byteAt(B, O) <Int 253
  rule #compactSizeBytes(B, O) => 3 requires #byteAt(B, O) ==Int 253
  rule #compactSizeBytes(B, O) => 5 requires #byteAt(B, O) ==Int 254
  rule #compactSizeBytes(B, O) => 9 requires #byteAt(B, O) ==Int 255

  // =========================================================================
  // Top-level transaction field accessors
  // =========================================================================
  //
  // Transaction wire format:
  //
  //   nVersion        : 4 bytes LE
  //   [marker 0x00]   : only if segwit (followed by flag 0x01)
  //   [flag 0x01]     : only if segwit
  //   nVin            : compactSize
  //   vin[]           : <32 prev_hash> <4 LE prev_index>
  //                     <cs script_sig_len> <script_sig> <4 LE sequence>
  //   nVout           : compactSize
  //   vout[]          : <8 LE amount> <cs script_len> <script>
  //   [witness]       : per-vin stack (only if marker+flag present)
  //   nLockTime       : last 4 bytes LE

  // Version is always the first 4 bytes, regardless of segwit marker.
  syntax Int ::= #txVersion(Bytes) [function]
  rule #txVersion(TX) => #readUInt32LE(TX, 0)

  // nLockTime is always the last 4 bytes, regardless of segwit witness data.
  syntax Int ::= #txLocktime(Bytes) [function]
  rule #txLocktime(TX) => #readUInt32LE(TX, lengthBytes(TX) -Int 4)

  // True if the tx uses the BIP-141 segwit serialization (marker=0x00, flag=0x01
  // at bytes 4-5). A non-witness tx at the same offsets would have the vin count
  // (which is always >= 1 for a valid tx, so the 0x00 marker byte disambiguates).
  syntax Bool ::= #txHasWitness(Bytes) [function]
  rule #txHasWitness(TX) => #byteAt(TX, 4) ==Int 0 andBool #byteAt(TX, 5) ==Int 1
    requires lengthBytes(TX) >=Int 6
  rule #txHasWitness(TX) => false
    requires lengthBytes(TX) <Int 6

  // Offset of the nVin compactSize (skips the segwit marker+flag if present).
  syntax Int ::= #txVinOffset(Bytes) [function]
  rule #txVinOffset(TX) => 6 requires #txHasWitness(TX)
  rule #txVinOffset(TX) => 4 requires notBool #txHasWitness(TX)

  // Number of transaction inputs.
  syntax Int ::= #txVinCount(Bytes) [function]
  rule #txVinCount(TX) => #readCompactSize(TX, #txVinOffset(TX))

  // Offset of vin[0] (just past the vin-count compactSize).
  syntax Int ::= #txVin0Offset(Bytes) [function]
  rule #txVin0Offset(TX) =>
         #txVinOffset(TX) +Int #compactSizeBytes(TX, #txVinOffset(TX))

  // =========================================================================
  // Vin iteration: each vin occupies
  //   <32 prev_hash> <4 LE prev_index> <cs script_sig_len> <script_sig> <4 LE seq>
  //
  // vin[I]'s start offset is computed by iteratively skipping I prior vins.
  // We expose it as a fixpoint walker to keep the recursion visible to the
  // prover; per-vin accessors build on top.
  // =========================================================================

  // Byte length of one vin starting at offset O.
  syntax Int ::= #vinLen(Bytes, Int) [function]
  rule #vinLen(TX, O) =>
         36                                                    // outpoint
      +Int #compactSizeBytes(TX, O +Int 36)                    // scriptSig len prefix
      +Int #readCompactSize(TX, O +Int 36)                     // scriptSig bytes
      +Int 4                                                   // sequence

  // Offset after skipping N vins starting from offset O.
  syntax Int ::= #skipVins(Bytes, Int, Int) [function]
  rule #skipVins(_, O, 0) => O
  rule #skipVins(TX, O, N) => #skipVins(TX, O +Int #vinLen(TX, O), N -Int 1)
    requires N >Int 0

  // Start offset of vin[I].
  syntax Int ::= #txVinAt(Bytes, Int) [function]
  rule #txVinAt(TX, I) => #skipVins(TX, #txVin0Offset(TX), I)

  // 36-byte outpoint (32-byte txid || 4-byte LE vout) of vin[I].
  syntax Bytes ::= #txVinOutpoint(Bytes, Int) [function]
  rule #txVinOutpoint(TX, I) =>
         substrBytes(TX, #txVinAt(TX, I), #txVinAt(TX, I) +Int 36)

  // 4-byte LE sequence value of vin[I]. The sequence is the last 4 bytes
  // of the vin record, so offset = vin_start + vin_len - 4. Pass the
  // vin-start offset (not the vin index) as #vinLen's second arg.
  syntax Int ::= #txVinSequence(Bytes, Int) [function]
  rule #txVinSequence(TX, I) =>
         #readUInt32LE(TX,
           #txVinAt(TX, I) +Int #vinLen(TX, #txVinAt(TX, I)) -Int 4)

  // Offset of the nVout compactSize (right after the last vin).
  syntax Int ::= #txVoutOffset(Bytes) [function]
  rule #txVoutOffset(TX) => #skipVins(TX, #txVin0Offset(TX), #txVinCount(TX))

  // Number of outputs.
  syntax Int ::= #txVoutCount(Bytes) [function]
  rule #txVoutCount(TX) => #readCompactSize(TX, #txVoutOffset(TX))

  // Offset of vout[0] (just past the vout-count compactSize).
  syntax Int ::= #txVout0Offset(Bytes) [function]
  rule #txVout0Offset(TX) =>
         #txVoutOffset(TX) +Int #compactSizeBytes(TX, #txVoutOffset(TX))

  // =========================================================================
  // Vout iteration: each vout occupies
  //   <8 LE amount> <cs script_len> <script>
  // =========================================================================

  // Byte length of one vout starting at offset O.
  syntax Int ::= #voutLen(Bytes, Int) [function]
  rule #voutLen(TX, O) =>
         8                                                     // amount
      +Int #compactSizeBytes(TX, O +Int 8)                     // script len prefix
      +Int #readCompactSize(TX, O +Int 8)                      // script bytes

  // Offset after skipping N vouts starting from offset O.
  syntax Int ::= #skipVouts(Bytes, Int, Int) [function]
  rule #skipVouts(_, O, 0) => O
  rule #skipVouts(TX, O, N) => #skipVouts(TX, O +Int #voutLen(TX, O), N -Int 1)
    requires N >Int 0

  // Start offset of vout[I].
  syntax Int ::= #txVoutAt(Bytes, Int) [function]
  rule #txVoutAt(TX, I) => #skipVouts(TX, #txVout0Offset(TX), I)

  // 8-byte LE amount (in satoshis) of vout[I].
  syntax Int ::= #txVoutAmount(Bytes, Int) [function]
  rule #txVoutAmount(TX, I) => #readUInt64LE(TX, #txVoutAt(TX, I))

  // scriptPubKey bytes of vout[I]. Pass the resolved vout-start offset as
  // #voutLen's second arg (not the vout index).
  syntax Bytes ::= #txVoutScript(Bytes, Int) [function]
  rule #txVoutScript(TX, I) =>
         substrBytes(TX,
           #txVoutAt(TX, I) +Int 8 +Int #compactSizeBytes(TX, #txVoutAt(TX, I) +Int 8),
           #txVoutAt(TX, I) +Int #voutLen(TX, #txVoutAt(TX, I)))

  // Full serialized vout[I] (amount || script_len || script) — for hashOutputs.
  // #voutLen's second arg is a byte offset, so pass #txVoutAt(TX, I).
  syntax Bytes ::= #txVoutSerialized(Bytes, Int) [function]
  rule #txVoutSerialized(TX, I) =>
         substrBytes(TX,
           #txVoutAt(TX, I),
           #txVoutAt(TX, I) +Int #voutLen(TX, #txVoutAt(TX, I)))

  // =========================================================================
  // Prevouts iteration.
  //
  // The <prevouts> cell carries a concatenation of serialized prevout
  // records, one per vin, in vin order. Each record has the same layout as
  // a TxOut: <8-byte LE amount> <compactSize spk_len> <scriptPubKey>.
  //
  // This matches Bitcoin's normal vout serialization, so #voutLen /
  // #skipVouts work unchanged. The only difference is there's no enclosing
  // tx header — offset 0 is the first prevout.
  //
  // BIP-341 / BIP-342 sighash consume this blob to produce
  // sha_amounts / sha_scriptpubkeys (precomputed-per-tx) and the single
  // amount+scriptPubKey of vin[inputIdx] (for ANYONECANPAY).
  // =========================================================================

  // Byte offset of prevout[I] within the prevouts blob.
  syntax Int ::= #prevoutAt(Bytes, Int) [function]
  rule #prevoutAt(P, I) => #skipVouts(P, 0, I)

  // 8-byte LE amount of prevout[I].
  syntax Int ::= #prevoutAmount(Bytes, Int) [function]
  rule #prevoutAmount(P, I) => #readUInt64LE(P, #prevoutAt(P, I))

  // scriptPubKey bytes (no cs length prefix) of prevout[I].
  syntax Bytes ::= #prevoutScript(Bytes, Int) [function]
  rule #prevoutScript(P, I) =>
         substrBytes(P,
           #prevoutAt(P, I) +Int 8 +Int #compactSizeBytes(P, #prevoutAt(P, I) +Int 8),
           #prevoutAt(P, I) +Int #voutLen(P, #prevoutAt(P, I)))

  // scriptPubKey with its compactSize length prefix (serialized form), used
  // by BIP-341 sha_scriptpubkeys.
  syntax Bytes ::= #prevoutScriptSerialized(Bytes, Int) [function]
  rule #prevoutScriptSerialized(P, I) =>
         substrBytes(P,
           #prevoutAt(P, I) +Int 8,
           #prevoutAt(P, I) +Int #voutLen(P, #prevoutAt(P, I)))

endmodule
