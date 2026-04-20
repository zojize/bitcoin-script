// Bitcoin-specific bulk SHA-256 streaming hooks for sighash preimage
// assembly. Moves the per-vin / per-vout iteration inside the C hook so
// K doesn't pay its ~90 µs-per-rewrite-step overhead for each field.
//
// Each hook takes a SHA256_CTX-image midstate (same layout used by
// KRYPTO.sha256Init/Update/Final in the sibling blockchain-k-plugin),
// parses a slice of Bitcoin's wire-format tx, and calls SHA256_Update
// once per record. Returns the updated midstate.
//
// The K side exposes pure recursive walker equivalents that the Haskell
// prover can reason about inductively. A [simplification] lemma asserts
// each bulk hook and its pure walker produce the same midstate — that's
// the trust boundary.
//
// Wire-format reference (pre-segwit vin layout even in segwit txs —
// witness data is serialized separately and doesn't affect sighash):
//   vin    = 32 txid || 4 vout || cs(scriptsig_len) || scriptsig || 4 sequence
//   vout   = 8 amount || cs(spk_len) || spk
//   prevout (for BIP-341, a separate blob) = 8 amount || cs(spk_len) || spk

#include <openssl/sha.h>
#include <cstring>
#include <cstdint>
#include <cstddef>
#include <gmp.h>

// Minimal forward declarations of the K runtime ABI we consume.
// Pulling in runtime/header.h transitively requires fmt, immer, boost,
// and the full K AST — none of which this plugin needs. The block /
// string layout and the mask constants are part of the stable K LLVM
// backend ABI (include/kllvm/config/macros.h, include/kllvm/runtime/types.h).
extern "C" {
struct block_header {
  uint64_t hdr;
};
struct string {
  block_header h;
  char data[];
};

// From include/config/macros.h
static constexpr uint64_t BSP_LENGTH_MASK = 0xffffffffffULL;
static constexpr uint64_t BSP_NOT_YOUNG_OBJECT_BIT = 0x10000000000000ULL;
// Block size used by init_with_len's "not young" sizing heuristic. K's
// default is 264 (BLOCK_SIZE) on 64-bit; we only care that short strings
// don't get the bit set.
static constexpr uint64_t BSP_BLOCK_SIZE = 264;

void *kore_alloc_token(size_t size);

static inline uint64_t bsp_len(string const *s) {
  return s->h.hdr & BSP_LENGTH_MASK;
}

static inline void bsp_init_with_len(string *s, uint64_t l) {
  s->h.hdr = l
           | (l > BSP_BLOCK_SIZE - sizeof(char *) ? BSP_NOT_YOUNG_OBJECT_BIT : 0);
}

// Minimal local allocString/raw — we don't depend on plugin_util so the
// bitcoin-sighash-plugin can build standalone.
static string *bsp_alloc_string(size_t len) {
  auto *result = (string *)kore_alloc_token(len + sizeof(string));
  bsp_init_with_len(result, len);
  return result;
}

static string *bsp_raw(unsigned char const *digest, size_t len) {
  string *result = bsp_alloc_string(len);
  std::memcpy(result->data, digest, len);
  return result;
}

static string *bsp_empty() {
  return bsp_alloc_string(0);
}

// ---------------------------------------------------------------------------
// Wire-format helpers.
// ---------------------------------------------------------------------------

// Read compactSize at (*p); advance *p by the consumed bytes. Returns
// SIZE_MAX on truncation and leaves *p unchanged.
static size_t read_compact_size(unsigned char const **p, unsigned char const *end) {
  if (*p >= end) return SIZE_MAX;
  unsigned char marker = **p;
  (*p)++;
  if (marker < 0xfd) return marker;
  if (marker == 0xfd) {
    if (*p + 2 > end) return SIZE_MAX;
    size_t v = (*p)[0] | ((size_t)(*p)[1] << 8);
    *p += 2;
    return v;
  }
  if (marker == 0xfe) {
    if (*p + 4 > end) return SIZE_MAX;
    size_t v = (size_t)(*p)[0] | ((size_t)(*p)[1] << 8)
             | ((size_t)(*p)[2] << 16) | ((size_t)(*p)[3] << 24);
    *p += 4;
    return v;
  }
  if (*p + 8 > end) return SIZE_MAX;
  size_t v = 0;
  for (int i = 0; i < 8; i++) v |= ((size_t)(*p)[i]) << (8 * i);
  *p += 8;
  return v;
}

// Emit a compactSize prefix into the midstate via SHA256_Update.
static void update_compact_size(SHA256_CTX *ctx, size_t n) {
  unsigned char buf[9];
  size_t len;
  if (n <= 0xfc) {
    buf[0] = (unsigned char)n;
    len = 1;
  } else if (n <= 0xffff) {
    buf[0] = 0xfd;
    buf[1] = (unsigned char)(n & 0xff);
    buf[2] = (unsigned char)((n >> 8) & 0xff);
    len = 3;
  } else if (n <= 0xffffffffULL) {
    buf[0] = 0xfe;
    for (int i = 0; i < 4; i++) buf[1 + i] = (unsigned char)((n >> (8 * i)) & 0xff);
    len = 5;
  } else {
    buf[0] = 0xff;
    for (int i = 0; i < 8; i++) buf[1 + i] = (unsigned char)((n >> (8 * i)) & 0xff);
    len = 9;
  }
  SHA256_Update(ctx, buf, len);
}

// Load SHA256_CTX from a K state blob into local ctx. Returns 1 on success.
static int load_ctx(SHA256_CTX *ctx, string const *state) {
  if (bsp_len(state) != sizeof(SHA256_CTX)) return 0;
  std::memcpy(ctx, state->data, sizeof(SHA256_CTX));
  return 1;
}

static string *emit_ctx(SHA256_CTX const *ctx) {
  return bsp_raw((unsigned char const *)ctx, sizeof(SHA256_CTX));
}

// Byte length of one vin starting at p. Returns SIZE_MAX on truncation.
static size_t vin_len(unsigned char const *p, unsigned char const *end) {
  if (p + 36 > end) return SIZE_MAX;
  unsigned char const *q = p + 36;
  size_t sig_len = read_compact_size(&q, end);
  if (sig_len == SIZE_MAX) return SIZE_MAX;
  if (q + sig_len + 4 > end) return SIZE_MAX;
  return (size_t)(q - p) + sig_len + 4;
}

static size_t vout_len(unsigned char const *p, unsigned char const *end) {
  if (p + 8 > end) return SIZE_MAX;
  unsigned char const *q = p + 8;
  size_t spk_len = read_compact_size(&q, end);
  if (spk_len == SIZE_MAX) return SIZE_MAX;
  if (q + spk_len > end) return SIZE_MAX;
  return (size_t)(q - p) + spk_len;
}

static size_t mpz_to_size_t(mpz_ptr z) {
  if (mpz_sgn(z) < 0) return 0;
  return (size_t)mpz_get_ui(z);
}

// ---------------------------------------------------------------------------
// Hooks. Namespace "BITCOIN" for all bitcoin-sighash-plugin hooks.
// ---------------------------------------------------------------------------

// Stream all 36-byte outpoints from vins [O, O+N*vinLen). Used by both
// BIP-143 hashPrevouts and BIP-341 sha_prevouts.
string *hook_BITCOIN_outpointsStream(
    string *state, string *tx,
    mpz_ptr start_offset, mpz_ptr n_vins) {
  SHA256_CTX ctx;
  if (!load_ctx(&ctx, state)) return bsp_empty();
  size_t off = mpz_to_size_t(start_offset);
  size_t n = mpz_to_size_t(n_vins);
  unsigned char const *base = (unsigned char const *)tx->data;
  unsigned char const *end = base + bsp_len(tx);
  if (off > bsp_len(tx)) return emit_ctx(&ctx);
  unsigned char const *p = base + off;
  for (size_t i = 0; i < n; i++) {
    if (p + 36 > end) return emit_ctx(&ctx);
    SHA256_Update(&ctx, p, 36);
    size_t step = vin_len(p, end);
    if (step == SIZE_MAX) return emit_ctx(&ctx);
    p += step;
  }
  return emit_ctx(&ctx);
}

// Stream all 4-byte LE sequences from vins [O, O+N*vinLen).
string *hook_BITCOIN_sequencesStream(
    string *state, string *tx,
    mpz_ptr start_offset, mpz_ptr n_vins) {
  SHA256_CTX ctx;
  if (!load_ctx(&ctx, state)) return bsp_empty();
  size_t off = mpz_to_size_t(start_offset);
  size_t n = mpz_to_size_t(n_vins);
  unsigned char const *base = (unsigned char const *)tx->data;
  unsigned char const *end = base + bsp_len(tx);
  if (off > bsp_len(tx)) return emit_ctx(&ctx);
  unsigned char const *p = base + off;
  for (size_t i = 0; i < n; i++) {
    size_t step = vin_len(p, end);
    if (step == SIZE_MAX || p + step > end) return emit_ctx(&ctx);
    SHA256_Update(&ctx, p + step - 4, 4);
    p += step;
  }
  return emit_ctx(&ctx);
}

// Stream all serialized vouts (amount||cs_len||spk) from [O, O+N*voutLen).
string *hook_BITCOIN_voutsStream(
    string *state, string *tx,
    mpz_ptr start_offset, mpz_ptr n_vouts) {
  SHA256_CTX ctx;
  if (!load_ctx(&ctx, state)) return bsp_empty();
  size_t off = mpz_to_size_t(start_offset);
  size_t n = mpz_to_size_t(n_vouts);
  unsigned char const *base = (unsigned char const *)tx->data;
  unsigned char const *end = base + bsp_len(tx);
  if (off > bsp_len(tx)) return emit_ctx(&ctx);
  unsigned char const *p = base + off;
  for (size_t i = 0; i < n; i++) {
    size_t step = vout_len(p, end);
    if (step == SIZE_MAX || p + step > end) return emit_ctx(&ctx);
    SHA256_Update(&ctx, p, step);
    p += step;
  }
  return emit_ctx(&ctx);
}

// Stream 8-byte LE amounts from prevouts[0, n).
string *hook_BITCOIN_prevoutAmountsStream(
    string *state, string *prevouts, mpz_ptr n_arg) {
  SHA256_CTX ctx;
  if (!load_ctx(&ctx, state)) return bsp_empty();
  size_t n = mpz_to_size_t(n_arg);
  unsigned char const *base = (unsigned char const *)prevouts->data;
  unsigned char const *end = base + bsp_len(prevouts);
  unsigned char const *p = base;
  for (size_t i = 0; i < n; i++) {
    if (p + 8 > end) return emit_ctx(&ctx);
    SHA256_Update(&ctx, p, 8);
    size_t step = vout_len(p, end);
    if (step == SIZE_MAX || p + step > end) return emit_ctx(&ctx);
    p += step;
  }
  return emit_ctx(&ctx);
}

// Stream each prevout's scriptPubKey (cs_len || spk) from prevouts[0, n).
string *hook_BITCOIN_prevoutScriptsStream(
    string *state, string *prevouts, mpz_ptr n_arg) {
  SHA256_CTX ctx;
  if (!load_ctx(&ctx, state)) return bsp_empty();
  size_t n = mpz_to_size_t(n_arg);
  unsigned char const *base = (unsigned char const *)prevouts->data;
  unsigned char const *end = base + bsp_len(prevouts);
  unsigned char const *p = base;
  for (size_t i = 0; i < n; i++) {
    size_t step = vout_len(p, end);
    if (step == SIZE_MAX || p + step > end) return emit_ctx(&ctx);
    SHA256_Update(&ctx, p + 8, step - 8);
    p += step;
  }
  return emit_ctx(&ctx);
}

// Stream the full legacy vins block (count prefix + N modified vins).
string *hook_BITCOIN_legacyVinsBlockStream(
    string *state, string *tx,
    mpz_ptr start_offset, mpz_ptr n_vins_arg,
    mpz_ptr sig_idx_arg, string *script_code, mpz_ptr hashtype_arg) {
  SHA256_CTX ctx;
  if (!load_ctx(&ctx, state)) return bsp_empty();
  size_t off = mpz_to_size_t(start_offset);
  size_t n = mpz_to_size_t(n_vins_arg);
  size_t sig_idx = mpz_to_size_t(sig_idx_arg);
  int hashtype = (int)mpz_get_si(hashtype_arg);
  unsigned char const *base = (unsigned char const *)tx->data;
  unsigned char const *end = base + bsp_len(tx);
  if (off > bsp_len(tx)) return emit_ctx(&ctx);

  update_compact_size(&ctx, n);
  unsigned char const *p = base + off;
  int base_type = hashtype & 31;
  int other_seq_zero = (base_type == 2 /*NONE*/) || (base_type == 3 /*SINGLE*/);
  size_t sc_len = bsp_len(script_code);

  for (size_t i = 0; i < n; i++) {
    if (p + 36 > end) return emit_ctx(&ctx);
    size_t step = vin_len(p, end);
    if (step == SIZE_MAX || p + step > end) return emit_ctx(&ctx);
    SHA256_Update(&ctx, p, 36);
    if (i == sig_idx) {
      update_compact_size(&ctx, sc_len);
      SHA256_Update(&ctx, script_code->data, sc_len);
      SHA256_Update(&ctx, p + step - 4, 4);
    } else {
      unsigned char zero = 0;
      SHA256_Update(&ctx, &zero, 1);
      if (other_seq_zero) {
        unsigned char zeros[4] = {0, 0, 0, 0};
        SHA256_Update(&ctx, zeros, 4);
      } else {
        SHA256_Update(&ctx, p + step - 4, 4);
      }
    }
    p += step;
  }
  return emit_ctx(&ctx);
}

// Stream the full legacy vouts block (count prefix + N modified vouts).
string *hook_BITCOIN_legacyVoutsBlockStream(
    string *state, string *tx,
    mpz_ptr start_offset, mpz_ptr n_vouts_arg,
    mpz_ptr sig_idx_arg, mpz_ptr hashtype_arg) {
  SHA256_CTX ctx;
  if (!load_ctx(&ctx, state)) return bsp_empty();
  size_t off = mpz_to_size_t(start_offset);
  size_t n = mpz_to_size_t(n_vouts_arg);
  size_t sig_idx = mpz_to_size_t(sig_idx_arg);
  int hashtype = (int)mpz_get_si(hashtype_arg);
  unsigned char const *base = (unsigned char const *)tx->data;
  unsigned char const *end = base + bsp_len(tx);

  update_compact_size(&ctx, n);
  if (n == 0) return emit_ctx(&ctx);
  if (off > bsp_len(tx)) return emit_ctx(&ctx);

  int is_single = (hashtype & 31) == 3;
  unsigned char const *p = base + off;

  for (size_t j = 0; j < n; j++) {
    if (p >= end) return emit_ctx(&ctx);
    size_t step = vout_len(p, end);
    if (step == SIZE_MAX || p + step > end) return emit_ctx(&ctx);
    if (is_single && j < sig_idx) {
      static unsigned char const placeholder[9] = {
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00};
      SHA256_Update(&ctx, placeholder, sizeof(placeholder));
    } else {
      SHA256_Update(&ctx, p, step);
    }
    p += step;
  }
  return emit_ctx(&ctx);
}

}  // extern "C"
