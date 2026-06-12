// Byte-equality test for the combined-pair Miller-loop C-ABI entry.
//
// For k in {1, 4, 16, 64, 256}, build random (P_i, Q_i) inputs, then
// compare:
//
//   bls12_381_combined_miller(g1s, g2s, k, out)
//
// against the canonical CPU reference (per-pair blst_miller_loop +
// canonical pairwise Fp12 tree reduction).  The C-ABI entry routes
// through the Metal driver on Apple builds; if Metal is unavailable
// the entry falls back to the CPU path automatically.
//
// All assertions are byte-equality (memcmp == 0).  No GoogleTest.

#include <blst.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <vector>

extern "C" int bls12_381_combined_miller(const uint8_t* g1s,
                                          const uint8_t* g2s,
                                          std::size_t    k,
                                          uint8_t        fp12_out[576]);

namespace {

constexpr std::size_t kP1Aff   = 96;
constexpr std::size_t kP2Aff   = 192;
constexpr std::size_t kFp12B   = 576;

const std::uint64_t kBLS_R_LE[6] = {
    0x760900000002FFFDULL, 0xEBF4000BC40C0002ULL, 0x5F48985753C758BAULL,
    0x77CE585370525745ULL, 0x5C071A97A256EC6DULL, 0x15F65EC3FA80E493ULL
};

void make_fp12_one(blst_fp12& f)
{
    std::memset(&f, 0, sizeof(f));
    std::memcpy(&f, kBLS_R_LE, sizeof(kBLS_R_LE));
}

// Canonical pairwise tree reduction — same shape as tree_reduce_fp12 in
// cpp/bls_pairing.cpp and the Metal/CUDA/WGSL kernels.
void tree_reduce(std::vector<blst_fp12>& v)
{
    while (v.size() > 1) {
        std::vector<blst_fp12> next;
        next.reserve((v.size() + 1) / 2);
        for (std::size_t i = 0; i + 1 < v.size(); i += 2) {
            blst_fp12 r;
            blst_fp12_mul(&r, &v[i], &v[i + 1]);
            next.push_back(r);
        }
        if (v.size() & 1u) next.push_back(v.back());
        v = std::move(next);
    }
}

void cpu_reference(const std::uint8_t* g1s,
                   const std::uint8_t* g2s,
                   std::size_t         k,
                   std::uint8_t        out[576])
{
    std::vector<blst_fp12> ml;
    ml.reserve(k);
    for (std::size_t i = 0; i < k; ++i) {
        blst_p1_affine P;
        blst_p2_affine Q;
        std::memcpy(&P, g1s + i * kP1Aff, sizeof(P));
        std::memcpy(&Q, g2s + i * kP2Aff, sizeof(Q));
        blst_fp12 t;
        blst_miller_loop(&t, &Q, &P);
        ml.push_back(t);
    }
    tree_reduce(ml);
    std::memcpy(out, &ml[0], sizeof(blst_fp12));
}

struct RNG {
    std::mt19937_64 r;
    RNG(std::uint64_t seed) : r(seed) {}
    void fill_sk(std::uint8_t sk[32]) {
        for (int i = 0; i < 32; ++i) sk[i] = static_cast<std::uint8_t>(r() & 0xFF);
        sk[31] &= 0x3F;
        sk[0]  |= 0x01;
    }
};

void make_corpus(std::size_t k,
                 std::vector<std::uint8_t>& g1s,
                 std::vector<std::uint8_t>& g2s,
                 std::uint64_t seed)
{
    g1s.assign(k * kP1Aff, 0);
    g2s.assign(k * kP2Aff, 0);
    RNG rng(seed);
    for (std::size_t i = 0; i < k; ++i) {
        std::uint8_t sk1[32], sk2[32];
        rng.fill_sk(sk1);
        rng.fill_sk(sk2);
        blst_p1 P_jac;
        blst_p1_mult(&P_jac, blst_p1_generator(), sk1, 256);
        blst_p1_affine P_aff;
        blst_p1_to_affine(&P_aff, &P_jac);
        std::memcpy(g1s.data() + i * kP1Aff, &P_aff, sizeof(P_aff));

        blst_p2 Q_jac;
        blst_p2_mult(&Q_jac, blst_p2_generator(), sk2, 256);
        blst_p2_affine Q_aff;
        blst_p2_to_affine(&Q_aff, &Q_jac);
        std::memcpy(g2s.data() + i * kP2Aff, &Q_aff, sizeof(Q_aff));
    }
}

void hexdump(const char* label, const std::uint8_t* p, std::size_t n)
{
    std::printf("  %s: ", label);
    for (std::size_t i = 0; i < n; ++i) {
        std::printf("%02x", p[i]);
        if ((i + 1) % 32 == 0 && i + 1 < n) std::printf("\n            ");
        else if (i + 1 < n) std::printf(" ");
    }
    std::printf("\n");
}

int run_k(std::size_t k, std::uint64_t seed)
{
    std::vector<std::uint8_t> g1s, g2s;
    make_corpus(k, g1s, g2s, seed);

    std::uint8_t expected[kFp12B];
    cpu_reference(g1s.data(), g2s.data(), k, expected);

    std::uint8_t actual[kFp12B];
    int rc = bls12_381_combined_miller(g1s.data(), g2s.data(), k, actual);
    if (rc != 0) {
        std::fprintf(stderr, "FAIL: combined_miller(k=%zu) rc=%d\n", k, rc);
        return 1;
    }
    if (std::memcmp(expected, actual, kFp12B) != 0) {
        std::fprintf(stderr, "FAIL: byte mismatch at k=%zu\n", k);
        hexdump("expect", expected, kFp12B);
        hexdump("actual", actual,   kFp12B);
        return 1;
    }
    std::printf("  k=%-4zu  PASS  (%zu bytes)\n", k, kFp12B);
    return 0;
}

}  // namespace

int main(int argc, char** argv)
{
    (void)argc; (void)argv;
    std::printf("=== combined Miller-loop byte-equality vs CPU multi_pair ===\n");

    int failures = 0;
    for (std::size_t k : { (std::size_t)1, (std::size_t)4, (std::size_t)16,
                           (std::size_t)64, (std::size_t)256 }) {
        // One deterministic seeded corpus per k.  Same seed -> same input
        // bytes -> same Fp12 product.
        if (run_k(k, 0xC0FFEEULL ^ k) != 0) ++failures;
    }

    // Random N=8 stress sweep, fresh seeds — proves the kernel survives
    // novel inputs not in the canonical k set.
    constexpr int kRandomTrials = 8;
    for (int t = 0; t < kRandomTrials; ++t) {
        std::uint64_t seed = 0xDEAD'BEEFULL + static_cast<std::uint64_t>(t) * 1009ULL;
        if (run_k(8, seed) != 0) ++failures;
    }

    if (failures == 0) {
        std::printf("---------------------------------------------------\n");
        std::printf("  ALL PASS  (5 fixed sizes + %d random)\n", kRandomTrials);
        return 0;
    }
    std::fprintf(stderr, "  %d failure(s)\n", failures);
    return 1;
}
