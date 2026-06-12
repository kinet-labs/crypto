// =============================================================================
// kinet-labs/crypto - top-level dispatcher
// =============================================================================
// Implements the GPU control plane and version reporting from crypto.h.
// Per-algorithm symbols (keccak256, sha256, ...) are exported by their
// respective <alg>/c-abi/c_<alg>.cpp files.
//
// Brand stays in include path (<kinet/crypto/...>); symbols are brand-neutral.
// =============================================================================

#include "crypto.h"

#include <atomic>

namespace {
constexpr int  kDefaultBackend = CRYPTO_BACKEND_CPU;
std::atomic<int> g_backend{kDefaultBackend};
}  // namespace

extern "C" int crypto_gpu_available(int backend) {
    switch (backend) {
        case CRYPTO_BACKEND_CPU:
            return 1;
#if defined(CRYPTO_HAS_CUDA)
        case CRYPTO_BACKEND_CUDA: return 1;
#endif
#if defined(CRYPTO_HAS_METAL)
        case CRYPTO_BACKEND_METAL: return 1;
#endif
#if defined(CRYPTO_HAS_WGSL)
        case CRYPTO_BACKEND_WGSL: return 1;
#endif
        default: return 0;
    }
}

extern "C" int crypto_gpu_set_default(int backend) {
    if (!crypto_gpu_available(backend)) return CRYPTO_ERR_BACKEND;
    g_backend.store(backend, std::memory_order_relaxed);
    return CRYPTO_OK;
}

extern "C" int crypto_gpu_get_default(void) {
    return g_backend.load(std::memory_order_relaxed);
}

extern "C" const char* crypto_version(void) {
    return "1.0.0";
}

// =============================================================================
// crypto_status — bitmask of wired algorithms
// =============================================================================
// Built from the actual wire state of every c-abi shim. Updated when a
// previously NOTIMPL algorithm is wired. Stable across the v1.x C-ABI.
//
// "Wired" = at least one operation in the algorithm can return a value
// other than CRYPTO_ERR_NOTIMPL after argument validation.
// =============================================================================

extern "C" uint64_t crypto_status(void) {
    return CRYPTO_ALG_SHA256
         | CRYPTO_ALG_KECCAK256
         | CRYPTO_ALG_BLAKE2B
         | CRYPTO_ALG_BLAKE3
         | CRYPTO_ALG_RIPEMD160
         | CRYPTO_ALG_AEAD_CHACHA
         | CRYPTO_ALG_AEAD_AES_GCM
         | CRYPTO_ALG_SECP256K1     /* recover wired; sign/verify NOTIMPL */
         | CRYPTO_ALG_SECP256R1     /* verify wired (RIP-7212 / EIP-7951) */
         | CRYPTO_ALG_ED25519
         | CRYPTO_ALG_SR25519        /* Schnorrkel sign/verify wired via kinet-labs/sr25519-crust */
         | CRYPTO_ALG_BN254
         | CRYPTO_ALG_BLS12_381     /* bls12_381_* canonical surface */
         | CRYPTO_ALG_KZG
         | CRYPTO_ALG_MLDSA
         | CRYPTO_ALG_MLKEM
         | CRYPTO_ALG_SLHDSA
         | CRYPTO_ALG_IPA           /* create_proof / check_proof wired */
         | CRYPTO_ALG_LAMPORT
         | CRYPTO_ALG_PEDERSEN      /* vector commit form wired */
         | CRYPTO_ALG_POSEIDON_BN254
         | CRYPTO_ALG_POSEIDON_GLDLKS
         | CRYPTO_ALG_MODEXP
         | CRYPTO_ALG_EVM256
         | CRYPTO_ALG_NTT
         | CRYPTO_ALG_POLY_MUL
         | CRYPTO_ALG_BANDERWAGON
         | CRYPTO_ALG_ATTESTATION
         | CRYPTO_ALG_RINGTAIL      /* Ring-LWE threshold sig (CPU body wired) */
         | CRYPTO_ALG_CGGMP21       /* setup + partial_sign wired (aggregate+verify host-side) */
         ;
}

extern "C" int crypto_alg_status(uint64_t alg_flag) {
    return (crypto_status() & alg_flag) ? 1 : 0;
}
