// CGGMP21 pre-sign determinism + correctness test.
//
// Status (2026-04-28):
//   * The secp256k1 portion (R_i = k_i * G) is wired and tested byte-equal
//     between the CPU canonical body and the CUDA host polyfill.
//   * The Paillier ciphertext + ZK proof are reserved with status=0xFF until
//     the 2048-bit Karatsuba modexp primitive ships; the test asserts the
//     reserved bytes are zero and status == 0xFF, freezing the wire layout.

#include "../cpp/presign.hpp"
#include "../../secp256k1/cpp/curve.hpp"
#include "../../secp256k1/cpp/field.hpp"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>

extern "C" int cggmp21_presign_cuda_host(
    const uint8_t* seed,
    const void* pks,
    const uint32_t* signer_ids,
    uint32_t m,
    uint32_t slot_id_base,
    uint32_t n_slots,
    void* records_out,
    void* secrets_out);

namespace {

using namespace kinet::crypto::cggmp21;
using kinet::crypto::secp256k1::U256;

struct XorShift {
    uint64_t s;
    uint64_t next() { s ^= s>>12; s ^= s<<25; s ^= s>>27; return s * 0x2545F4914F6CDD1DULL; }
    void fill(uint8_t* p, std::size_t n) { for (std::size_t i = 0; i < n; ++i) p[i] = (uint8_t)next(); }
};

bool R_eq_kG(const uint8_t k_be[32], const uint8_t R[33]) {
    using namespace kinet::crypto::secp256k1;
    U256 k = U256::from_be32(k_be);
    AffinePoint G;
    G.x = to_mont_p(GX); G.y = to_mont_p(GY); G.infinity = false;
    JacobianPoint P = jac_mul(k, G);
    AffinePoint A = jacobian_to_affine(P);
    if (A.infinity) return false;
    U256 x_p = from_mont_p(A.x);
    U256 y_p = from_mont_p(A.y);
    uint8_t want[33];
    want[0] = (y_p.limbs[0] & 1) ? 0x03 : 0x02;
    x_p.to_be32(want + 1);
    return std::memcmp(want, R, 33) == 0;
}

void test_secp256k1_portion() {
    uint8_t seed[32];
    XorShift rng{0xCDCDCDCDCDCDCDCDULL};
    rng.fill(seed, 32);

    PaillierKey pk{};  // Reserved for the Paillier sub-step.
    for (int trial = 0; trial < 16; ++trial) {
        uint32_t sid = (uint32_t)((rng.next() % 1000) + 1);
        uint32_t slot = (uint32_t)(rng.next() % 1000);
        PresignRecord rec{};
        PresignSecret sec{};
        int rc = presign_one(seed, pk, sid, slot, rec, sec);
        if (rc != 0) { std::fprintf(stderr, "presign_one rc=%d\n", rc); std::abort(); }
        if (!R_eq_kG(sec.k, rec.R)) {
            std::fprintf(stderr, "trial %d: R != k*G\n", trial); std::abort();
        }
        // gamma_i must be in (0, n) too (sanity).
        bool gamma_nonzero = false;
        for (int i = 0; i < 32; ++i) if (sec.gamma[i]) { gamma_nonzero = true; break; }
        if (!gamma_nonzero) { std::fprintf(stderr, "gamma == 0\n"); std::abort(); }
        // Paillier portion must be zero (reserved) and status must be 0xFF.
        if (rec.status != 0xFF) {
            std::fprintf(stderr, "trial %d: status=%u (want 0xFF)\n", trial, rec.status);
            std::abort();
        }
        for (auto b : rec.K)     if (b != 0) { std::fprintf(stderr, "K leak\n"); std::abort(); }
        for (auto b : rec.G_cmt) if (b != 0) { std::fprintf(stderr, "G_cmt leak\n"); std::abort(); }
        for (auto b : rec.pi_enc) if (b != 0) { std::fprintf(stderr, "pi_enc leak\n"); std::abort(); }
    }
    std::puts("secp256k1 portion (R = k*G): pass");
    std::puts("reserved bytes (Paillier + ZK proof): zero, status=0xFF — pass");
}

void test_batch_eq_single() {
    uint8_t seed[32];
    XorShift rng{0x9999999999999999ULL};
    rng.fill(seed, 32);
    constexpr uint32_t M = 10;
    constexpr uint32_t N = 64;
    std::vector<uint32_t> sids(M);
    for (uint32_t i = 0; i < M; ++i) sids[i] = i + 1;
    std::vector<PaillierKey> pks(M);
    std::vector<PresignRecord> recs(M * N);
    std::vector<PresignSecret> secs(M * N);
    if (presign_batch(seed, pks.data(), sids.data(), M, /*slot_base=*/200, N,
                      recs.data(), secs.data()) != 0) std::abort();
    for (uint32_t i = 0; i < M; ++i) {
        for (uint32_t s = 0; s < N; ++s) {
            PresignRecord r1{}; PresignSecret s1{};
            presign_one(seed, pks[i], sids[i], 200 + s, r1, s1);
            std::size_t k = (std::size_t)i * N + s;
            if (std::memcmp(r1.R, recs[k].R, 33) != 0) {
                std::fprintf(stderr, "batch != single at (%u,%u)\n", i, s);
                std::abort();
            }
            if (std::memcmp(s1.k,     secs[k].k,     32) != 0 ||
                std::memcmp(s1.gamma, secs[k].gamma, 32) != 0) {
                std::fprintf(stderr, "batch nonces != single at (%u,%u)\n", i, s);
                std::abort();
            }
        }
    }
    std::printf("batch == single: pass (M=%u, N=%u)\n", M, N);
}

void test_cuda_polyfill_byte_equal() {
    uint8_t seed[32]; XorShift rng{0xBEEFBEEFBEEFBEEFULL}; rng.fill(seed, 32);
    constexpr uint32_t M = 10;
    constexpr uint32_t N = 64;
    std::vector<uint32_t> sids(M);
    for (uint32_t i = 0; i < M; ++i) sids[i] = i + 1;
    std::vector<PaillierKey> pks(M);
    std::vector<PresignRecord> cpu_r(M * N), gpu_r(M * N);
    std::vector<PresignSecret> cpu_s(M * N), gpu_s(M * N);
    presign_batch(seed, pks.data(), sids.data(), M, 0, N, cpu_r.data(), cpu_s.data());
    cggmp21_presign_cuda_host(seed, pks.data(), sids.data(), M, 0, N,
                              gpu_r.data(), gpu_s.data());
    for (std::size_t k = 0; k < cpu_r.size(); ++k) {
        if (std::memcmp(&cpu_r[k], &gpu_r[k], sizeof(PresignRecord)) != 0) {
            std::fprintf(stderr, "CPU vs CUDA polyfill record mismatch at slot %zu\n", k);
            std::abort();
        }
    }
    std::printf("CUDA host polyfill == CPU: pass (%u records)\n", M * N);
}

void test_n100_random() {
    XorShift rng{0xDEAFDEAFDEAFDEAFULL};
    int total = 0;
    for (int trial = 0; trial < 100; ++trial) {
        uint8_t seed[32]; rng.fill(seed, 32);
        uint32_t M = 1u + (uint32_t)(rng.next() % 8u);
        uint32_t N = 1u + (uint32_t)(rng.next() % 16u);
        std::vector<uint32_t> sids(M);
        for (uint32_t i = 0; i < M; ++i) sids[i] = (uint32_t)(rng.next() & 0xFFFF) + 1;
        std::vector<PaillierKey> pks(M);
        std::vector<PresignRecord> cpu_r(M * N), gpu_r(M * N);
        std::vector<PresignSecret> cpu_s(M * N), gpu_s(M * N);
        uint32_t sb = (uint32_t)(rng.next() & 0xFFFF);
        presign_batch(seed, pks.data(), sids.data(), M, sb, N, cpu_r.data(), cpu_s.data());
        cggmp21_presign_cuda_host(seed, pks.data(), sids.data(), M, sb, N,
                                  gpu_r.data(), gpu_s.data());
        for (uint32_t k = 0; k < M * N; ++k) {
            if (std::memcmp(&cpu_r[k], &gpu_r[k], sizeof(PresignRecord)) != 0) {
                std::fprintf(stderr, "trial %d slot %u\n", trial, k); std::abort();
            }
        }
        total += M * N;
    }
    std::printf("N=100 random batches: pass (%d records)\n", total);
}

}  // namespace

int main() {
    test_secp256k1_portion();
    test_batch_eq_single();
    test_cuda_polyfill_byte_equal();
    test_n100_random();
    std::puts("cggmp21_presign_test: ALL PASS");
    return 0;
}
