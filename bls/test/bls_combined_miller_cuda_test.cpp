// Byte-equality test for the combined-pair Miller-loop CUDA driver.
//
// On Apple (no CUDA toolkit), the driver runs in stub mode and
// bls_combined_miller_cuda returns -2.  This test prints a SKIP line
// and exits 0 — same convention as bls_driver_cuda.cpp's stub mode.
//
// On CUDA-enabled CI runners (BLS_HAVE_CUDA defined and a real GPU),
// the driver dispatches the same kernel sequence the Metal driver does
// and the test asserts byte-equality against the CPU reference for
// k in {1, 4, 16, 64, 256}.

#include <blst.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <random>
#include <vector>

#include "../gpu/cuda/bls_combined_miller_driver.h"

namespace {

constexpr std::size_t kP1Aff = 96;
constexpr std::size_t kP2Aff = 192;
constexpr std::size_t kFp12B = 576;

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

void cpu_reference(const std::uint8_t* g1s, const std::uint8_t* g2s,
                   std::size_t k, std::uint8_t out[576])
{
    std::vector<blst_fp12> ml; ml.reserve(k);
    for (std::size_t i = 0; i < k; ++i) {
        blst_p1_affine P; blst_p2_affine Q;
        std::memcpy(&P, g1s + i * kP1Aff, sizeof(P));
        std::memcpy(&Q, g2s + i * kP2Aff, sizeof(Q));
        blst_fp12 t; blst_miller_loop(&t, &Q, &P);
        ml.push_back(t);
    }
    tree_reduce(ml);
    std::memcpy(out, &ml[0], sizeof(blst_fp12));
}

void make_corpus(std::size_t k,
                 std::vector<std::uint8_t>& g1s,
                 std::vector<std::uint8_t>& g2s,
                 std::uint64_t seed)
{
    g1s.assign(k * kP1Aff, 0);
    g2s.assign(k * kP2Aff, 0);
    std::mt19937_64 r(seed);
    for (std::size_t i = 0; i < k; ++i) {
        std::uint8_t sk1[32], sk2[32];
        for (int j = 0; j < 32; ++j) sk1[j] = static_cast<std::uint8_t>(r() & 0xFF);
        for (int j = 0; j < 32; ++j) sk2[j] = static_cast<std::uint8_t>(r() & 0xFF);
        sk1[31] &= 0x3F; sk1[0] |= 0x01;
        sk2[31] &= 0x3F; sk2[0] |= 0x01;
        blst_p1 P_jac; blst_p1_mult(&P_jac, blst_p1_generator(), sk1, 256);
        blst_p1_affine P_aff; blst_p1_to_affine(&P_aff, &P_jac);
        std::memcpy(g1s.data() + i * kP1Aff, &P_aff, sizeof(P_aff));
        blst_p2 Q_jac; blst_p2_mult(&Q_jac, blst_p2_generator(), sk2, 256);
        blst_p2_affine Q_aff; blst_p2_to_affine(&Q_aff, &Q_jac);
        std::memcpy(g2s.data() + i * kP2Aff, &Q_aff, sizeof(Q_aff));
    }
}

}  // namespace

int main(int, char**)
{
    if (!bls_combined_miller_cuda_available()) {
        std::printf("=== combined Miller-loop CUDA test ===\n");
        std::printf("  SKIP: CUDA unavailable on this host (stub mode)\n");
        return 0;
    }

    std::printf("=== combined Miller-loop CUDA byte-equality vs CPU ===\n");
    int failures = 0;
    for (std::size_t k : { (std::size_t)1, (std::size_t)4, (std::size_t)16,
                           (std::size_t)64, (std::size_t)256 }) {
        std::vector<std::uint8_t> g1s, g2s;
        make_corpus(k, g1s, g2s, 0xC0FFEEULL ^ k);
        std::uint8_t expected[kFp12B], actual[kFp12B];
        cpu_reference(g1s.data(), g2s.data(), k, expected);
        int rc = bls_combined_miller_cuda(g1s.data(), g2s.data(), k, actual);
        if (rc != 0) {
            std::fprintf(stderr, "FAIL: cuda(k=%zu) rc=%d\n", k, rc);
            ++failures;
            continue;
        }
        if (std::memcmp(expected, actual, kFp12B) != 0) {
            std::fprintf(stderr, "FAIL: cuda byte mismatch at k=%zu\n", k);
            ++failures;
            continue;
        }
        std::printf("  k=%-4zu  PASS\n", k);
    }
    return failures == 0 ? 0 : 1;
}
