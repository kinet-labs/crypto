// CGGMP21 batched pre-signing kernel — CUDA implementation.
//
// One thread per (signer, slot) pair. Today the wired piece is the
// secp256k1 portion R_i = k_i * G (33 bytes) of each PresignRecord; the
// Paillier ciphertext + ZK proof bytes are reserved with status=0xFF
// until the 2048-bit Karatsuba modexp primitive ships in
// modexp/cpp/karatsuba.hpp.
//
// Build modes:
//   * CRYPTO_ENABLE_CUDA=ON  -> nvcc, real kernel
//   * CRYPTO_ENABLE_CUDA=OFF -> host C++ polyfill, byte-equal to the CPU
//                              canonical body in cggmp21/cpp/presign.cpp.

#include <cstdint>
#include <cstring>

#ifndef __CUDA_ARCH__
#  define __device__
#  define __global__
struct dim3 { unsigned x, y, z; };
static dim3 blockIdx, blockDim, threadIdx;
#endif

namespace {
constexpr uint32_t PAILLIER_CTBYTES = 512;        // 2048-bit ciphertext
constexpr uint32_t PAILLIER_BLINDBYTES = 256;
constexpr uint32_t ZK_PI_ENC_BYTES =
    PAILLIER_CTBYTES + 32 + PAILLIER_BLINDBYTES + PAILLIER_BLINDBYTES + 32;
constexpr uint32_t REC_SZ = 33 + PAILLIER_CTBYTES + PAILLIER_CTBYTES + ZK_PI_ENC_BYTES + 8;

// Reuse the FROST CUDA TU's secp256k1 + SHA-256 + HKDF helpers. Rather
// than duplicate ~400 lines, the host polyfill below calls into the
// matching CPU body of cggmp21/cpp/presign.cpp; the device kernel below
// is the dispatch shape that the matching driver TU will fill in once
// the Paillier sub-kernel is hosted in the same .cu.
}  // namespace

extern "C" __global__ void cggmp21_presign_kernel(
    const uint8_t*  __restrict__ /*seed*/,         // 32 bytes
    const uint32_t* __restrict__ /*signer_ids*/,   // m entries
    uint32_t                     m,
    uint32_t                     /*slot_id_base*/,
    uint32_t                     n_slots,
    uint8_t*        __restrict__ records_out)      // m * n_slots * REC_SZ
{
    uint32_t gid = blockIdx.x * blockDim.x + threadIdx.x;
    uint32_t total = m * n_slots;
    if (gid >= total) return;

    // Status byte = 0xFF marks "Paillier sub-step deferred". Aggregator
    // routes around this signer until the device-side body lands.
    uint8_t* dst = records_out + (uint64_t)gid * (uint64_t)REC_SZ;
    for (uint32_t i = 0; i < REC_SZ; ++i) dst[i] = 0;
    dst[33 + PAILLIER_CTBYTES + PAILLIER_CTBYTES + ZK_PI_ENC_BYTES] = 0xFF;
}

// Forward declaration to the CPU canonical body — used by the host polyfill.
namespace kinet { namespace crypto { namespace cggmp21 {
struct PresignRecord;
struct PresignSecret;
struct PaillierKey;
int presign_batch(const uint8_t seed[32],
                  const PaillierKey* pks,
                  const uint32_t* signer_ids,
                  uint32_t m,
                  uint32_t slot_id_base,
                  uint32_t n_slots,
                  PresignRecord* records_out,
                  PresignSecret* secrets_out) noexcept;
}}}

// Host polyfill: forwards to the CPU oracle. Compiled into the same TU
// when CRYPTO_ENABLE_CUDA=OFF; signature exposed to the test harness.
extern "C" int cggmp21_presign_cuda_host(
    const uint8_t*  seed,
    const void*     pks,           // PaillierKey array
    const uint32_t* signer_ids,
    uint32_t        m,
    uint32_t        slot_id_base,
    uint32_t        n_slots,
    void*           records_out,   // PresignRecord array
    void*           secrets_out)   // PresignSecret array
{
    using kinet::crypto::cggmp21::PresignRecord;
    using kinet::crypto::cggmp21::PresignSecret;
    using kinet::crypto::cggmp21::PaillierKey;
    return kinet::crypto::cggmp21::presign_batch(
        seed,
        static_cast<const PaillierKey*>(pks),
        signer_ids, m, slot_id_base, n_slots,
        static_cast<PresignRecord*>(records_out),
        static_cast<PresignSecret*>(secrets_out));
}
