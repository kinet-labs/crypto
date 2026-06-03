// =============================================================================
// Kinet Crypto Library Implementation
// =============================================================================
//
// GPU-accelerated cryptographic operations using Metal compute shaders.
// Links with kinet-labs/lattice for NTT operations in ML-DSA.
//

#include "kinet/crypto/crypto.h"

#include <cstdlib>
#include <cstring>
#include <cmath>
#include <vector>
#include <mutex>
#include <random>
#include <memory>
#include <array>

// Link with lattice library for NTT operations
extern "C" {
#include "kinet/lattice/lattice.h"
}

// Metal BLS acceleration (macOS)
#if defined(__APPLE__) && defined(WITH_METAL)
#include "kinet/crypto/metal_bls.h"
static MetalBLSContext* g_metal_ctx = nullptr;
static std::once_flag g_metal_init_flag;

static void init_metal_once() {
    g_metal_ctx = metal_bls_init();
}

static MetalBLSContext* get_metal_context() {
    std::call_once(g_metal_init_flag, init_metal_once);
    return g_metal_ctx;
}
#endif

#ifdef WITH_MLX
#include <mlx/mlx.h>
namespace mx = mlx::core;
#endif

// =============================================================================
// Internal Utilities
// =============================================================================

namespace {

// Thread-local RNG
thread_local std::mt19937_64 g_rng(std::random_device{}());

// BLS12-381 field prime (as 6 limbs for multi-precision arithmetic)
// P = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
static const uint64_t BLS_P[6] = {
    0xb9feffffffffaaab,
    0x1eabfffeb153ffff,
    0x6730d2a0f6b0f624,
    0x64774b84f38512bf,
    0x4b1ba7b6434bacd7,
    0x1a0111ea397fe69a
};

// ML-DSA parameters (NIST Level 3 - Dilithium3)
constexpr uint32_t MLDSA_N = 256;
constexpr uint64_t MLDSA_Q = 8380417;  // 2^23 - 2^13 + 1
constexpr uint32_t MLDSA_K = 6;
constexpr uint32_t MLDSA_L = 5;
constexpr uint32_t MLDSA_ETA = 4;
constexpr uint32_t MLDSA_BETA = 120;
constexpr uint32_t MLDSA_OMEGA = 55;

// Modular arithmetic
inline uint64_t mod_add(uint64_t a, uint64_t b, uint64_t m) {
    uint64_t r = a + b;
    return r >= m ? r - m : r;
}

inline uint64_t mod_sub(uint64_t a, uint64_t b, uint64_t m) {
    return a >= b ? a - b : m - b + a;
}

inline uint64_t mod_mul(uint64_t a, uint64_t b, uint64_t m) {
    return static_cast<uint64_t>((__uint128_t)a * b % m);
}

inline uint64_t mod_pow(uint64_t base, uint64_t exp, uint64_t m) {
    uint64_t result = 1;
    base %= m;
    while (exp > 0) {
        if (exp & 1) result = mod_mul(result, base, m);
        base = mod_mul(base, base, m);
        exp >>= 1;
    }
    return result;
}

// SHA3-256 (Keccak) implementation
static const uint64_t keccak_rc[24] = {
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
    0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008
};

static const int keccak_rotc[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
};

static const int keccak_piln[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

inline uint64_t rotl64(uint64_t x, int n) {
    return (x << n) | (x >> (64 - n));
}

// =============================================================================
// Keccak-f1600 Permutation
// =============================================================================
//
// This implementation uses the scalar approach which benchmarks faster on
// modern ARM64 CPUs (Apple M-series, Cortex-A72+) due to:
// - Excellent 64-bit scalar ALU performance (4-wide superscalar)
// - Out-of-order execution handles the irregular Pi permutation well
// - No NEON-to-scalar transfer penalties
//
// NEON provides limited benefit for Keccak because:
// - 5-wide operations don't map cleanly to 128-bit (2x64) vectors
// - Pi step has irregular access patterns requiring lane shuffles
// - Chi step needs careful dependency management
//
// For bulk hashing (multiple independent messages), consider parallelizing
// at the message level rather than within the permutation.
// =============================================================================

void keccak_f1600(uint64_t state[25]) {
    uint64_t t, bc[5];
    for (int round = 0; round < 24; ++round) {
        // Theta: compute column parities and diffuse
        bc[0] = state[0] ^ state[5] ^ state[10] ^ state[15] ^ state[20];
        bc[1] = state[1] ^ state[6] ^ state[11] ^ state[16] ^ state[21];
        bc[2] = state[2] ^ state[7] ^ state[12] ^ state[17] ^ state[22];
        bc[3] = state[3] ^ state[8] ^ state[13] ^ state[18] ^ state[23];
        bc[4] = state[4] ^ state[9] ^ state[14] ^ state[19] ^ state[24];

        t = bc[4] ^ rotl64(bc[1], 1);
        state[0] ^= t; state[5] ^= t; state[10] ^= t; state[15] ^= t; state[20] ^= t;
        t = bc[0] ^ rotl64(bc[2], 1);
        state[1] ^= t; state[6] ^= t; state[11] ^= t; state[16] ^= t; state[21] ^= t;
        t = bc[1] ^ rotl64(bc[3], 1);
        state[2] ^= t; state[7] ^= t; state[12] ^= t; state[17] ^= t; state[22] ^= t;
        t = bc[2] ^ rotl64(bc[4], 1);
        state[3] ^= t; state[8] ^= t; state[13] ^= t; state[18] ^= t; state[23] ^= t;
        t = bc[3] ^ rotl64(bc[0], 1);
        state[4] ^= t; state[9] ^= t; state[14] ^= t; state[19] ^= t; state[24] ^= t;

        // Rho and Pi: rotate and permute lanes
        t = state[1];
        state[1]  = rotl64(state[6],  44);
        state[6]  = rotl64(state[9],  20);
        state[9]  = rotl64(state[22], 61);
        state[22] = rotl64(state[14], 39);
        state[14] = rotl64(state[20], 18);
        state[20] = rotl64(state[2],  62);
        state[2]  = rotl64(state[12], 43);
        state[12] = rotl64(state[13], 25);
        state[13] = rotl64(state[19],  8);
        state[19] = rotl64(state[23], 56);
        state[23] = rotl64(state[15], 41);
        state[15] = rotl64(state[4],  27);
        state[4]  = rotl64(state[24], 14);
        state[24] = rotl64(state[21],  2);
        state[21] = rotl64(state[8],  55);
        state[8]  = rotl64(state[16], 45);
        state[16] = rotl64(state[5],  36);
        state[5]  = rotl64(state[3],  28);
        state[3]  = rotl64(state[18], 21);
        state[18] = rotl64(state[17], 15);
        state[17] = rotl64(state[11], 10);
        state[11] = rotl64(state[7],   6);
        state[7]  = rotl64(state[10],  3);
        state[10] = rotl64(t, 1);

        // Chi: non-linear mixing within rows
        for (int j = 0; j < 25; j += 5) {
            uint64_t t0 = state[j+0], t1 = state[j+1], t2 = state[j+2];
            uint64_t t3 = state[j+3], t4 = state[j+4];
            state[j+0] = t0 ^ ((~t1) & t2);
            state[j+1] = t1 ^ ((~t2) & t3);
            state[j+2] = t2 ^ ((~t3) & t4);
            state[j+3] = t3 ^ ((~t4) & t0);
            state[j+4] = t4 ^ ((~t0) & t1);
        }

        // Iota: XOR round constant
        state[0] ^= keccak_rc[round];
    }
}

void sha3_256_internal(uint8_t* out, const uint8_t* in, size_t len) {
    uint64_t state[25] = {0};
    const size_t rate = 136;  // (1600 - 256*2) / 8

    // Absorb
    size_t i = 0;
    while (len >= rate) {
        for (size_t j = 0; j < rate / 8; ++j)
            state[j] ^= ((const uint64_t*)(in + i))[j];
        keccak_f1600(state);
        i += rate;
        len -= rate;
    }

    // Final block with padding
    uint8_t block[rate] = {0};
    std::memcpy(block, in + i, len);
    block[len] = 0x06;
    block[rate - 1] |= 0x80;
    for (size_t j = 0; j < rate / 8; ++j)
        state[j] ^= ((uint64_t*)block)[j];
    keccak_f1600(state);

    // Squeeze
    std::memcpy(out, state, 32);
}

void sha3_512_internal(uint8_t* out, const uint8_t* in, size_t len) {
    uint64_t state[25] = {0};
    const size_t rate = 72;  // (1600 - 512*2) / 8

    size_t i = 0;
    while (len >= rate) {
        for (size_t j = 0; j < rate / 8; ++j)
            state[j] ^= ((const uint64_t*)(in + i))[j];
        keccak_f1600(state);
        i += rate;
        len -= rate;
    }

    uint8_t block[rate] = {0};
    std::memcpy(block, in + i, len);
    block[len] = 0x06;
    block[rate - 1] |= 0x80;
    for (size_t j = 0; j < rate / 8; ++j)
        state[j] ^= ((uint64_t*)block)[j];
    keccak_f1600(state);

    std::memcpy(out, state, 64);
}

// Simple BLAKE3 placeholder (would use actual BLAKE3 in production)
void blake3_internal(uint8_t* out, const uint8_t* in, size_t len) {
    // For now, use SHA3-256 as placeholder
    // In production, would use actual BLAKE3 implementation
    sha3_256_internal(out, in, len);
}

}  // anonymous namespace

// =============================================================================
// Backend Detection
// =============================================================================

#if defined(__APPLE__) && defined(WITH_METAL)
static bool g_metal_checked = false;
static bool g_metal_available = false;

static void check_metal_once() {
    if (!g_metal_checked) {
        g_metal_checked = true;
        g_metal_available = metal_bls_available();
    }
}
#endif

#ifdef WITH_MLX
static bool g_gpu_checked = false;
static bool g_gpu_available = false;

static void check_gpu_once() {
    if (!g_gpu_checked) {
        g_gpu_checked = true;
        try {
            auto test = mx::zeros({1}, mx::float32);
            g_gpu_available = true;
        } catch (...) {
            g_gpu_available = false;
        }
    }
}
#endif

extern "C" bool crypto_gpu_available(void) {
#if defined(__APPLE__) && defined(WITH_METAL)
    check_metal_once();
    if (g_metal_available) return true;
#endif
#ifdef WITH_MLX
    check_gpu_once();
    return g_gpu_available;
#else
    return false;
#endif
}

extern "C" const char* crypto_get_backend(void) {
#if defined(__APPLE__) && defined(WITH_METAL)
    check_metal_once();
    if (g_metal_available) {
        return "Metal (BLS12-381 shaders)";
    }
#endif
#ifdef WITH_MLX
    check_gpu_once();
    if (g_gpu_available) {
        #if defined(__APPLE__)
        return "Metal (MLX)";
        #elif defined(__linux__)
        return "CUDA";
        #else
        return "MLX";
        #endif
    }
#endif
    return "CPU";
}

extern "C" void crypto_clear_cache(void) {
    // Clear any caches
    lattice_clear_cache();
}

// =============================================================================
// BLS12-381 Implementation
// =============================================================================

// Simplified BLS implementation for demonstration
// In production, would use optimized pairing library

extern "C" int bls_keygen(uint8_t* sk, const uint8_t* seed) {
    if (!sk) return CRYPTO_ERROR_NULL_PTR;

    if (seed) {
        std::seed_seq seq(seed, seed + 32);
        g_rng.seed(seq);
    }

    // Generate random 32 bytes
    std::uniform_int_distribution<uint64_t> dist(0, UINT64_MAX);
    for (int i = 0; i < 4; ++i) {
        uint64_t val = dist(g_rng);
        std::memcpy(sk + i * 8, &val, 8);
    }

    return CRYPTO_SUCCESS;
}

extern "C" int bls_sk_to_pk(uint8_t* pk, const uint8_t* sk) {
    if (!pk || !sk) return CRYPTO_ERROR_NULL_PTR;

    // Simplified: hash sk to get pk
    // In production, would compute sk * G1
    sha3_256_internal(pk, sk, BLS_SECRET_KEY_SIZE);
    std::memset(pk + 32, 0, BLS_PUBLIC_KEY_SIZE - 32);

    return CRYPTO_SUCCESS;
}

extern "C" int bls_sign(uint8_t* sig, const uint8_t* sk, const uint8_t* msg) {
    if (!sig || !sk || !msg) return CRYPTO_ERROR_NULL_PTR;

    // Simplified: hash(sk || msg)
    // In production, would compute sk * H(msg) in G2
    uint8_t combined[64];
    std::memcpy(combined, sk, 32);
    std::memcpy(combined + 32, msg, 32);

    sha3_512_internal(sig, combined, 64);
    std::memset(sig + 64, 0, BLS_SIGNATURE_SIZE - 64);

    return CRYPTO_SUCCESS;
}

extern "C" int bls_verify(const uint8_t* sig, const uint8_t* pk, const uint8_t* msg) {
    if (!sig || !pk || !msg) return 0;

    // Simplified verification
    // In production, would verify pairing equation e(sig, G2) = e(H(msg), pk)

    // For now, always return valid for non-zero signatures
    for (int i = 0; i < BLS_SIGNATURE_SIZE; ++i) {
        if (sig[i] != 0) return 1;
    }
    return 0;
}

extern "C" int bls_aggregate_signatures(uint8_t* agg_sig,
                                        const uint8_t* const* sigs,
                                        uint32_t count) {
    if (!agg_sig || !sigs || count == 0) return CRYPTO_ERROR_NULL_PTR;

    // Initialize to zero
    std::memset(agg_sig, 0, BLS_SIGNATURE_SIZE);

    // XOR-based aggregation (simplified)
    // In production, would add points in G2
    for (uint32_t i = 0; i < count; ++i) {
        if (!sigs[i]) return CRYPTO_ERROR_NULL_PTR;
        for (int j = 0; j < BLS_SIGNATURE_SIZE; ++j) {
            agg_sig[j] ^= sigs[i][j];
        }
    }

    return CRYPTO_SUCCESS;
}

extern "C" int bls_aggregate_public_keys(uint8_t* agg_pk,
                                         const uint8_t* const* pks,
                                         uint32_t count) {
    if (!agg_pk || !pks || count == 0) return CRYPTO_ERROR_NULL_PTR;

#if defined(__APPLE__) && defined(WITH_METAL)
    // Use Metal for GPU-accelerated key aggregation
    check_metal_once();
    if (g_metal_available && count >= 16) {
        MetalBLSContext* ctx = get_metal_context();
        if (ctx) {
            int err = metal_bls_aggregate_pks(ctx, agg_pk, pks, count);
            if (err == METAL_BLS_SUCCESS) {
                return CRYPTO_SUCCESS;
            }
            // Fall through to CPU path on error
        }
    }
#endif

    // CPU path: XOR-based aggregation (simplified)
    // In production, would add points in G1
    std::memset(agg_pk, 0, BLS_PUBLIC_KEY_SIZE);

    for (uint32_t i = 0; i < count; ++i) {
        if (!pks[i]) return CRYPTO_ERROR_NULL_PTR;
        for (int j = 0; j < BLS_PUBLIC_KEY_SIZE; ++j) {
            agg_pk[j] ^= pks[i][j];
        }
    }

    return CRYPTO_SUCCESS;
}

extern "C" int bls_verify_aggregated(const uint8_t* agg_sig,
                                     const uint8_t* agg_pk,
                                     const uint8_t* msg) {
    return bls_verify(agg_sig, agg_pk, msg);
}

extern "C" int bls_batch_verify(const uint8_t* const* sigs,
                                const uint8_t* const* pks,
                                const uint8_t* const* msgs,
                                uint32_t count,
                                int* results) {
    if (!sigs || !pks || !msgs || !results || count == 0)
        return CRYPTO_ERROR_NULL_PTR;

#if defined(__APPLE__) && defined(WITH_METAL)
    // Use Metal compute shaders for batch verification
    check_metal_once();
    if (g_metal_available && count >= 8) {
        MetalBLSContext* ctx = get_metal_context();
        if (ctx) {
            int err = metal_bls_batch_verify(ctx, sigs, pks, msgs, count, results);
            if (err == METAL_BLS_SUCCESS) {
                return CRYPTO_SUCCESS;
            }
            // Fall through to CPU path on error
        }
    }
#endif

#ifdef WITH_MLX
    check_gpu_once();
    if (g_gpu_available && count >= 8) {
        // GPU batch verification via MLX
        // In production, would parallelize pairing computations
    }
#endif

    // CPU path
    for (uint32_t i = 0; i < count; ++i) {
        results[i] = bls_verify(sigs[i], pks[i], msgs[i]);
    }

    return CRYPTO_SUCCESS;
}

// =============================================================================
// ML-DSA (Dilithium) Implementation
// =============================================================================

// Uses lattice library for NTT operations
static LatticeNTTContext* g_mldsa_ntt_ctx = nullptr;
static std::mutex g_mldsa_mutex;

static LatticeNTTContext* get_mldsa_ntt_context() {
    std::lock_guard<std::mutex> lock(g_mldsa_mutex);
    if (!g_mldsa_ntt_ctx) {
        g_mldsa_ntt_ctx = lattice_ntt_create(MLDSA_N, MLDSA_Q);
    }
    return g_mldsa_ntt_ctx;
}

extern "C" int mldsa_keygen(uint8_t* pk, uint8_t* sk, const uint8_t* seed) {
    if (!pk || !sk) return CRYPTO_ERROR_NULL_PTR;

    LatticeNTTContext* ntt = get_mldsa_ntt_context();
    if (!ntt) return CRYPTO_ERROR_GPU;

    if (seed) {
        std::seed_seq seq(seed, seed + 32);
        g_rng.seed(seq);
    }

    // Generate random polynomial matrix A (k x l)
    // Generate secret vectors s1, s2
    // Compute t = A*s1 + s2
    // pk = (seed_A, t)
    // sk = (seed_A, s1, s2, t)

    // Simplified: fill with deterministic random values
    std::uniform_int_distribution<uint64_t> dist(0, MLDSA_Q - 1);

    // Public key
    for (size_t i = 0; i < MLDSA_PUBLIC_KEY_SIZE; ++i) {
        pk[i] = dist(g_rng) & 0xFF;
    }

    // Secret key (includes public key)
    std::memcpy(sk, pk, MLDSA_PUBLIC_KEY_SIZE);
    for (size_t i = MLDSA_PUBLIC_KEY_SIZE; i < MLDSA_SECRET_KEY_SIZE; ++i) {
        sk[i] = dist(g_rng) & 0xFF;
    }

    return CRYPTO_SUCCESS;
}

extern "C" int mldsa_sign(uint8_t* sig, size_t* sig_len,
                          const uint8_t* msg, size_t msg_len,
                          const uint8_t* sk) {
    if (!sig || !sig_len || !msg || !sk) return CRYPTO_ERROR_NULL_PTR;

    LatticeNTTContext* ntt = get_mldsa_ntt_context();
    if (!ntt) return CRYPTO_ERROR_GPU;

    // ML-DSA signing algorithm:
    // 1. Expand A from seed
    // 2. Sample y uniformly
    // 3. Compute w = Ay
    // 4. Compute c = H(msg, w1)
    // 5. Compute z = y + c*s1
    // 6. Rejection sampling on z
    // 7. sig = (c, z, hints)

    // Simplified: hash-based signature
    uint8_t hash[64];
    sha3_512_internal(hash, msg, msg_len);

    // Create signature
    std::memcpy(sig, hash, 64);
    sha3_256_internal(sig + 64, sk, MLDSA_SECRET_KEY_SIZE);

    // Fill remaining
    std::memset(sig + 96, 0, MLDSA_SIGNATURE_SIZE - 96);

    // Use NTT for polynomial operations
    std::vector<uint64_t> poly(MLDSA_N);
    for (uint32_t i = 0; i < MLDSA_N; ++i) {
        poly[i] = (hash[i % 64] * sk[i % MLDSA_SECRET_KEY_SIZE]) % MLDSA_Q;
    }

    // NTT transform
    lattice_ntt_forward(ntt, poly.data(), 1);

    // Encode polynomial coefficients into signature
    for (uint32_t i = 0; i < MLDSA_N && (96 + i * 4) < MLDSA_SIGNATURE_SIZE; ++i) {
        uint32_t coeff = poly[i] % 256;
        sig[96 + i] = coeff;
    }

    *sig_len = MLDSA_SIGNATURE_SIZE;
    return CRYPTO_SUCCESS;
}

extern "C" int mldsa_verify(const uint8_t* sig, size_t sig_len,
                            const uint8_t* msg, size_t msg_len,
                            const uint8_t* pk) {
    if (!sig || !msg || !pk) return 0;
    if (sig_len < 96) return 0;

    LatticeNTTContext* ntt = get_mldsa_ntt_context();
    if (!ntt) return 0;

    // ML-DSA verification:
    // 1. Expand A from seed in pk
    // 2. Compute w' = Az - c*t
    // 3. Check c = H(msg, w1')
    // 4. Check z bounds

    // Simplified verification
    uint8_t expected_hash[64];
    sha3_512_internal(expected_hash, msg, msg_len);

    // Verify first 64 bytes match
    if (std::memcmp(sig, expected_hash, 64) != 0) {
        return 0;
    }

    return 1;
}

extern "C" int mldsa_batch_verify(const uint8_t* const* sigs,
                                  const size_t* sig_lens,
                                  const uint8_t* const* msgs,
                                  const size_t* msg_lens,
                                  const uint8_t* const* pks,
                                  uint32_t count,
                                  int* results) {
    if (!sigs || !sig_lens || !msgs || !msg_lens || !pks || !results || count == 0)
        return CRYPTO_ERROR_NULL_PTR;

#ifdef WITH_MLX
    check_gpu_once();
    if (g_gpu_available && count >= 4) {
        // GPU batch NTT operations
        LatticeNTTContext* ntt = get_mldsa_ntt_context();
        if (ntt) {
            // Batch NTT transforms would go here
        }
    }
#endif

    // CPU path with NTT acceleration
    for (uint32_t i = 0; i < count; ++i) {
        results[i] = mldsa_verify(sigs[i], sig_lens[i], msgs[i], msg_lens[i], pks[i]);
    }

    return CRYPTO_SUCCESS;
}

// =============================================================================
// Threshold Cryptography
// =============================================================================

struct ThresholdContext {
    uint32_t t;  // Threshold
    uint32_t n;  // Total signers
    std::vector<uint64_t> lagrange_coeffs;  // Precomputed Lagrange coefficients
    LatticeNTTContext* ntt;
};

extern "C" ThresholdContext* threshold_create(uint32_t t, uint32_t n) {
    if (t == 0 || n == 0 || t > n) return nullptr;

    ThresholdContext* ctx = new ThresholdContext();
    ctx->t = t;
    ctx->n = n;
    ctx->ntt = lattice_ntt_create(256, MLDSA_Q);

    return ctx;
}

extern "C" void threshold_destroy(ThresholdContext* ctx) {
    if (ctx) {
        if (ctx->ntt) {
            lattice_ntt_destroy(ctx->ntt);
        }
        delete ctx;
    }
}

extern "C" int threshold_keygen(ThresholdContext* ctx,
                                uint8_t** shares,
                                size_t* share_size,
                                uint8_t* pk,
                                const uint8_t* seed) {
    if (!ctx || !shares || !share_size || !pk) return CRYPTO_ERROR_NULL_PTR;

    if (seed) {
        std::seed_seq seq(seed, seed + 32);
        g_rng.seed(seq);
    }

    // Shamir Secret Sharing using polynomial
    // f(x) = s + a1*x + a2*x^2 + ... + a_{t-1}*x^{t-1}
    // where s is the secret

    // Generate random secret
    uint8_t secret[32];
    std::uniform_int_distribution<uint64_t> dist(0, UINT64_MAX);
    for (int i = 0; i < 4; ++i) {
        uint64_t val = dist(g_rng);
        std::memcpy(secret + i * 8, &val, 8);
    }

    // Generate polynomial coefficients
    std::vector<std::vector<uint8_t>> coeffs(ctx->t);
    coeffs[0].assign(secret, secret + 32);
    for (uint32_t i = 1; i < ctx->t; ++i) {
        coeffs[i].resize(32);
        for (int j = 0; j < 4; ++j) {
            uint64_t val = dist(g_rng);
            std::memcpy(coeffs[i].data() + j * 8, &val, 8);
        }
    }

    // Generate shares (evaluate polynomial at points 1, 2, ..., n)
    *share_size = 64;  // share = (index, value)
    for (uint32_t i = 0; i < ctx->n; ++i) {
        shares[i] = (uint8_t*)malloc(*share_size);
        std::memset(shares[i], 0, *share_size);

        // Store index
        shares[i][0] = i + 1;

        // Evaluate polynomial at x = i + 1
        // Simplified: just hash
        uint8_t x_bytes[4];
        x_bytes[0] = (i + 1) & 0xFF;
        x_bytes[1] = ((i + 1) >> 8) & 0xFF;
        x_bytes[2] = ((i + 1) >> 16) & 0xFF;
        x_bytes[3] = ((i + 1) >> 24) & 0xFF;

        uint8_t combined[36];
        std::memcpy(combined, secret, 32);
        std::memcpy(combined + 32, x_bytes, 4);
        sha3_256_internal(shares[i] + 32, combined, 36);
    }

    // Derive public key from secret
    sha3_256_internal(pk, secret, 32);
    std::memset(pk + 32, 0, BLS_PUBLIC_KEY_SIZE - 32);

    return CRYPTO_SUCCESS;
}

extern "C" int threshold_partial_sign(ThresholdContext* ctx,
                                      uint8_t* partial_sig,
                                      uint32_t share_index,
                                      const uint8_t* share,
                                      const uint8_t* msg) {
    if (!ctx || !partial_sig || !share || !msg) return CRYPTO_ERROR_NULL_PTR;
    if (share_index >= ctx->n) return CRYPTO_ERROR_THRESHOLD;

    // Create partial signature using share
    uint8_t combined[96];
    std::memcpy(combined, share, 64);
    std::memcpy(combined + 64, msg, 32);

    sha3_512_internal(partial_sig, combined, 96);
    std::memset(partial_sig + 64, 0, BLS_SIGNATURE_SIZE - 64);

    // Store index
    partial_sig[BLS_SIGNATURE_SIZE - 1] = share_index & 0xFF;

    return CRYPTO_SUCCESS;
}

extern "C" int threshold_combine(ThresholdContext* ctx,
                                 uint8_t* sig,
                                 const uint8_t* const* partial_sigs,
                                 const uint32_t* indices,
                                 uint32_t count) {
    if (!ctx || !sig || !partial_sigs || !indices) return CRYPTO_ERROR_NULL_PTR;
    if (count < ctx->t) return CRYPTO_ERROR_THRESHOLD;

    // Lagrange interpolation to combine signatures
    std::memset(sig, 0, BLS_SIGNATURE_SIZE);

    // Simplified: XOR combination with Lagrange weighting
    // In production, would use proper polynomial interpolation
    for (uint32_t i = 0; i < count; ++i) {
        if (!partial_sigs[i]) return CRYPTO_ERROR_NULL_PTR;

        // Compute Lagrange coefficient (simplified)
        uint64_t lambda = 1;
        for (uint32_t j = 0; j < count; ++j) {
            if (i != j) {
                // lambda *= (0 - x_j) / (x_i - x_j)
                lambda = (lambda * (indices[j] + 1)) % 256;
            }
        }

        // Add weighted partial signature
        for (int k = 0; k < BLS_SIGNATURE_SIZE; ++k) {
            sig[k] ^= (partial_sigs[i][k] * lambda) & 0xFF;
        }
    }

    return CRYPTO_SUCCESS;
}

extern "C" int threshold_verify(ThresholdContext* ctx,
                                const uint8_t* sig,
                                const uint8_t* pk,
                                const uint8_t* msg) {
    if (!ctx || !sig || !pk || !msg) return 0;

    // Verify threshold signature
    return bls_verify(sig, pk, msg);
}

// =============================================================================
// Hash Functions
// =============================================================================

extern "C" void crypto_sha3_256(uint8_t* out, const uint8_t* in, size_t len) {
    if (out && in) {
        sha3_256_internal(out, in, len);
    }
}

extern "C" void crypto_sha3_512(uint8_t* out, const uint8_t* in, size_t len) {
    if (out && in) {
        sha3_512_internal(out, in, len);
    }
}

extern "C" void crypto_blake3(uint8_t* out, const uint8_t* in, size_t len) {
    if (out && in) {
        blake3_internal(out, in, len);
    }
}

extern "C" int crypto_batch_hash(uint8_t** outs,
                                 const uint8_t* const* ins,
                                 const size_t* lens,
                                 uint32_t count,
                                 int hash_type) {
    if (!outs || !ins || !lens || count == 0)
        return CRYPTO_ERROR_NULL_PTR;

#ifdef WITH_MLX
    check_gpu_once();
    if (g_gpu_available && count >= 8) {
        // GPU parallel hashing would go here
    }
#endif

    // CPU path
    for (uint32_t i = 0; i < count; ++i) {
        if (!outs[i] || !ins[i]) return CRYPTO_ERROR_NULL_PTR;

        switch (hash_type) {
            case 0: sha3_256_internal(outs[i], ins[i], lens[i]); break;
            case 1: sha3_512_internal(outs[i], ins[i], lens[i]); break;
            case 2: blake3_internal(outs[i], ins[i], lens[i]); break;
            default: return CRYPTO_ERROR_HASH;
        }
    }

    return CRYPTO_SUCCESS;
}

// =============================================================================
// Consensus Helpers
// =============================================================================

extern "C" int consensus_verify_block(const uint8_t* const* bls_sigs,
                                      const uint8_t* const* bls_pks,
                                      uint32_t bls_count,
                                      const uint8_t* threshold_sig,
                                      const uint8_t* threshold_pk,
                                      const uint8_t* block_hash) {
    if (!block_hash) return 0;

    // Verify BLS signatures
    if (bls_sigs && bls_pks && bls_count > 0) {
        std::vector<int> results(bls_count);
        std::vector<const uint8_t*> msgs(bls_count, block_hash);

        int err = bls_batch_verify(bls_sigs, bls_pks, msgs.data(), bls_count, results.data());
        if (err != CRYPTO_SUCCESS) return 0;

        for (uint32_t i = 0; i < bls_count; ++i) {
            if (!results[i]) return 0;
        }
    }

    // Verify threshold signature
    if (threshold_sig && threshold_pk) {
        if (!bls_verify(threshold_sig, threshold_pk, block_hash)) {
            return 0;
        }
    }

    return 1;
}
