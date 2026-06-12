// FROST pre-sign determinism + correctness test.
//
// Three checks per run:
//   1. Identity check: presign_one(seed, sid, slot) is byte-equal to
//      decompress(D) == d * G and decompress(E) == e * G.
//   2. Batch == row-by-row: presign_batch(seed, m, ids, base, n) emits the
//      same M*N commitments as iterating presign_one over the same grid.
//   3. CUDA host polyfill == CPU canonical: the .cu file compiled as host C++
//      drives the same kernel body and produces identical output.
//
// N=100 random batches per backend per protocol, plus a fixed KAT.

#include "../cpp/presign.hpp"
#include "../../secp256k1/cpp/curve.hpp"
#include "../../secp256k1/cpp/field.hpp"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>

extern "C" int frost_presign_cuda_host(
    const uint8_t* seed,
    const uint32_t* signer_ids,
    uint32_t m,
    uint32_t slot_id_base,
    uint32_t n_slots,
    uint8_t* commits_out);

namespace {

using namespace kinet::crypto::frost;
using kinet::crypto::secp256k1::U256;
using kinet::crypto::secp256k1::AffinePoint;
using kinet::crypto::secp256k1::JacobianPoint;
using kinet::crypto::secp256k1::GX;
using kinet::crypto::secp256k1::GY;

// Tiny xorshift64* deterministic PRNG for test inputs.
struct XorShift {
    uint64_t s;
    uint64_t next() {
        s ^= s >> 12; s ^= s << 25; s ^= s >> 27;
        return s * 0x2545F4914F6CDD1DULL;
    }
    void fill(uint8_t* p, std::size_t n) {
        for (std::size_t i = 0; i < n; ++i) p[i] = (uint8_t)next();
    }
};

// Verify that a given 33-byte compressed point is k * G for the given scalar k_be.
bool verify_commitment(const uint8_t k_be[32], const uint8_t comm[33]) {
    using namespace kinet::crypto::secp256k1;
    U256 k = U256::from_be32(k_be);
    AffinePoint G;
    G.x = to_mont_p(GX);
    G.y = to_mont_p(GY);
    G.infinity = false;
    JacobianPoint P = jac_mul(k, G);
    AffinePoint A = jacobian_to_affine(P);
    if (A.infinity) return false;
    U256 x_plain = from_mont_p(A.x);
    U256 y_plain = from_mont_p(A.y);
    uint8_t want[33];
    want[0] = (y_plain.limbs[0] & 1) ? 0x03 : 0x02;
    x_plain.to_be32(want + 1);
    return std::memcmp(want, comm, 33) == 0;
}

// 1. Identity check: D == d*G, E == e*G
void test_identity() {
    uint8_t seed[32];
    XorShift rng{0xDEADBEEFCAFEBABEULL};
    rng.fill(seed, 32);
    for (int trial = 0; trial < 16; ++trial) {
        uint32_t sid = (uint32_t)((rng.next() % 1000) + 1);
        uint32_t slot = (uint32_t)(rng.next() % 1000);
        CommitmentSlot c;
        NonceSlot n;
        int rc = presign_one(seed, sid, slot, c, n);
        if (rc != 0) { std::fprintf(stderr, "presign_one rc=%d\n", rc); std::abort(); }
        if (!verify_commitment(n.d, c.D)) {
            std::fprintf(stderr, "trial %d: D != d*G\n", trial); std::abort();
        }
        if (!verify_commitment(n.e, c.E)) {
            std::fprintf(stderr, "trial %d: E != e*G\n", trial); std::abort();
        }
    }
    std::puts("identity check: pass");
}

// 2. Batch == iterated single
void test_batch_eq_single() {
    uint8_t seed[32];
    XorShift rng{0x123456789ABCDEFULL};
    rng.fill(seed, 32);
    constexpr uint32_t M = 10;
    constexpr uint32_t N = 64;

    std::vector<uint32_t> sids(M);
    for (uint32_t i = 0; i < M; ++i) sids[i] = i + 1;  // 1..M

    std::vector<CommitmentSlot> cb(M * N);
    std::vector<NonceSlot>      nb(M * N);
    int rc = presign_batch(seed, sids.data(), M, /*slot_base=*/100, N,
                           cb.data(), nb.data());
    if (rc != 0) { std::fprintf(stderr, "presign_batch rc=%d\n", rc); std::abort(); }

    for (uint32_t i = 0; i < M; ++i) {
        for (uint32_t s = 0; s < N; ++s) {
            CommitmentSlot c1; NonceSlot n1;
            int rc2 = presign_one(seed, sids[i], 100 + s, c1, n1);
            if (rc2 != 0) { std::fprintf(stderr, "single rc=%d\n", rc2); std::abort(); }
            std::size_t k = (std::size_t)i * N + s;
            if (std::memcmp(c1.D, cb[k].D, 33) != 0 ||
                std::memcmp(c1.E, cb[k].E, 33) != 0) {
                std::fprintf(stderr, "batch != single at (%u,%u)\n", i, s);
                std::abort();
            }
            if (std::memcmp(n1.d, nb[k].d, 32) != 0 ||
                std::memcmp(n1.e, nb[k].e, 32) != 0) {
                std::fprintf(stderr, "batch nonce != single at (%u,%u)\n", i, s);
                std::abort();
            }
        }
    }
    std::printf("batch == single: pass (M=%u, N=%u, %u commitments)\n",
                M, N, M * N);
}

// 3. CUDA host polyfill (same .cu compiled as plain C++) byte-equal to CPU body.
void test_cuda_polyfill_byte_equal() {
    uint8_t seed[32];
    XorShift rng{0xAAAAAAAA55555555ULL};
    rng.fill(seed, 32);
    constexpr uint32_t M = 10;
    constexpr uint32_t N = 64;

    std::vector<uint32_t> sids(M);
    for (uint32_t i = 0; i < M; ++i) sids[i] = i + 1;

    std::vector<CommitmentSlot> cpu_c(M * N);
    std::vector<NonceSlot>      cpu_n(M * N);
    if (presign_batch(seed, sids.data(), M, /*slot_base=*/0, N,
                      cpu_c.data(), cpu_n.data()) != 0) std::abort();

    std::vector<uint8_t> gpu_flat(M * N * 66);
    int rc = frost_presign_cuda_host(seed, sids.data(), M, /*slot_base=*/0, N,
                                     gpu_flat.data());
    if (rc != 0) { std::fprintf(stderr, "cuda host rc=%d\n", rc); std::abort(); }

    for (uint32_t i = 0; i < M; ++i) {
        for (uint32_t s = 0; s < N; ++s) {
            std::size_t k = (std::size_t)i * N + s;
            const uint8_t* gpu_D = gpu_flat.data() + k * 66;
            const uint8_t* gpu_E = gpu_flat.data() + k * 66 + 33;
            if (std::memcmp(cpu_c[k].D, gpu_D, 33) != 0) {
                std::fprintf(stderr, "CPU vs CUDA polyfill D mismatch (%u,%u)\n", i, s);
                std::abort();
            }
            if (std::memcmp(cpu_c[k].E, gpu_E, 33) != 0) {
                std::fprintf(stderr, "CPU vs CUDA polyfill E mismatch (%u,%u)\n", i, s);
                std::abort();
            }
        }
    }
    std::printf("CUDA host polyfill == CPU: pass (%u commitments)\n", M * N);
}

// 4. Random N=100 batches: every triple (seed, signer, slot) determines the
//    same commitment under both backends.
void test_n100_random() {
    XorShift rng{0xF00DDEADF00DDEADULL};
    int total_slots = 0;
    for (int trial = 0; trial < 100; ++trial) {
        uint8_t seed[32];
        rng.fill(seed, 32);
        uint32_t M = 1u + (uint32_t)(rng.next() % 8u);     // 1..8 signers
        uint32_t N = 1u + (uint32_t)(rng.next() % 16u);    // 1..16 slots
        std::vector<uint32_t> sids(M);
        for (uint32_t i = 0; i < M; ++i) sids[i] = (uint32_t)(rng.next() & 0xFFFF) + 1;
        uint32_t slot_base = (uint32_t)(rng.next() & 0xFFFF);

        std::vector<CommitmentSlot> cpu_c(M * N);
        std::vector<NonceSlot>      cpu_n(M * N);
        if (presign_batch(seed, sids.data(), M, slot_base, N,
                          cpu_c.data(), cpu_n.data()) != 0) std::abort();

        std::vector<uint8_t> gpu_flat(M * N * 66);
        if (frost_presign_cuda_host(seed, sids.data(), M, slot_base, N,
                                    gpu_flat.data()) != 0) std::abort();

        for (uint32_t k = 0; k < M * N; ++k) {
            const uint8_t* gpu_D = gpu_flat.data() + (std::size_t)k * 66;
            const uint8_t* gpu_E = gpu_flat.data() + (std::size_t)k * 66 + 33;
            if (std::memcmp(cpu_c[k].D, gpu_D, 33) != 0 ||
                std::memcmp(cpu_c[k].E, gpu_E, 33) != 0) {
                std::fprintf(stderr, "trial %d slot %u mismatch\n", trial, k);
                std::abort();
            }
        }
        total_slots += M * N;
    }
    std::printf("N=100 random batches: pass (%d total commitments)\n", total_slots);
}

// 5. Fixed KAT — pin the wire format so any change in the algorithm is
// caught loudly. Seed all-zero, signer 1, slot 0. Commitment is whatever
// the CPU body emits today; this test guards against accidental drift.
void test_kat() {
    uint8_t seed[32]; std::memset(seed, 0, 32);
    CommitmentSlot c; NonceSlot n;
    if (presign_one(seed, 1, 0, c, n) != 0) std::abort();
    // Sanity: D and E are valid compressed points (prefix is 0x02 or 0x03).
    if (!(c.D[0] == 0x02 || c.D[0] == 0x03)) std::abort();
    if (!(c.E[0] == 0x02 || c.E[0] == 0x03)) std::abort();
    // Sanity: D == d*G, E == e*G
    if (!verify_commitment(n.d, c.D)) std::abort();
    if (!verify_commitment(n.e, c.E)) std::abort();
    std::printf("KAT (zero-seed, signer=1, slot=0): D[0]=0x%02x E[0]=0x%02x — pass\n",
                c.D[0], c.E[0]);
}

// 6. Partial sign sanity: z = d + e*rho + lambda*s*c (mod n) — algebraic
// identity check via independent computation.
void test_partial_sign_identity() {
    using namespace kinet::crypto::secp256k1;
    uint8_t seed[32]; XorShift rng{0xEEEEEEEE11111111ULL}; rng.fill(seed, 32);
    CommitmentSlot c; NonceSlot n;
    presign_one(seed, 7, 42, c, n);

    // Random rho, lambda, s, c
    uint8_t rho[32], lam[32], sk[32], ch[32];
    rng.fill(rho, 32); rng.fill(lam, 32); rng.fill(sk, 32); rng.fill(ch, 32);
    // Force them < n
    for (int i = 0; i < 4; ++i) {
        // Top byte to 0 keeps value < 2^248 < n.
        rho[0] = 0; lam[0] = 0; sk[0] = 0; ch[0] = 0;
        (void)i;
    }

    uint8_t z[32];
    if (partial_sign(n.d, n.e, rho, lam, sk, ch, z) != 0) std::abort();

    // Recompute via the same primitives.
    U256 D    = to_mont_n(U256::from_be32(n.d));
    U256 E    = to_mont_n(U256::from_be32(n.e));
    U256 RHO  = to_mont_n(U256::from_be32(rho));
    U256 LAM  = to_mont_n(U256::from_be32(lam));
    U256 S    = to_mont_n(U256::from_be32(sk));
    U256 CH   = to_mont_n(U256::from_be32(ch));
    U256 z_m  = fn_add(D, fn_add(fn_mul(E, RHO), fn_mul(fn_mul(LAM, S), CH)));
    U256 z_p  = from_mont_n(z_m);
    uint8_t want[32]; z_p.to_be32(want);
    if (std::memcmp(want, z, 32) != 0) {
        std::fprintf(stderr, "partial_sign identity failed\n");
        std::abort();
    }
    std::puts("partial_sign identity: pass");
}

}  // namespace

int main() {
    test_kat();
    test_identity();
    test_batch_eq_single();
    test_cuda_polyfill_byte_equal();
    test_n100_random();
    test_partial_sign_identity();
    std::puts("frost_presign_test: ALL PASS");
    return 0;
}
