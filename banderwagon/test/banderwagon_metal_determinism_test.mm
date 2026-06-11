// CPU vs Metal byte-equality test for Banderwagon group ops.
//
// Three batteries:
//   1. 100 random Element pairs   : assert CPU::add(P, Q) == Metal_add(P, Q)
//      byte-equal (compare X || Y || Z limbs verbatim).
//   2. 100 random (Element, Fr) pairs : assert CPU::scalar_mul(P, s) ==
//      Metal_smul(P, s) byte-equal.
//   3. 5 batch MSMs (sizes 64, 256, 1024, varying batch widths) :
//      assert CPU MSM == Metal MSM byte-equal.
//
// Skipped silently when KINET_CRYPTO_BANDERWAGON_METALLIB is unset (test still
// registers on non-Apple hosts).

#include "../cpp/element.hpp"
#include "../cpp/fp.hpp"
#include "../cpp/fr.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#if __APPLE__
#include "../gpu/metal/banderwagon_driver.h"
#endif

using kinet::banderwagon::Element;
using kinet::banderwagon::Fp;
using kinet::banderwagon::Fr;

namespace {

// Deterministic LCG (so this test is byte-stable across hosts).
uint64_t lcg_state = 0xBADCAFEC0FFEE001ULL;
uint8_t lcg_byte() {
    lcg_state = lcg_state * 6364136223846793005ULL + 1442695040888963407ULL;
    return uint8_t(lcg_state >> 33);
}

// Random Fr scalar via from_bytes_le accept-reject (32 attempts max).
Fr random_fr() {
    for (int tries = 0; tries < 32; ++tries) {
        std::uint8_t b[32];
        for (int i = 0; i < 32; ++i) b[i] = lcg_byte();
        // Clear top 4 bits to ensure the value is comfortably below the
        // 252-bit Fr modulus (probability of acceptance ~ 1).
        b[31] &= 0x0f;
        Fr s;
        if (Fr::from_bytes_le(b, s)) return s;
    }
    return Fr::zero();
}

// Random non-identity Banderwagon element: take generator * random Fr.
Element random_element() {
    Fr s = random_fr();
    if (s.is_zero()) {
        std::uint8_t one_le[32] = {1, 0};
        Fr::from_bytes_le(one_le, s);
    }
    return Element::scalar_mul(Element::generator(), s);
}

// Pack Pt -> 96 bytes (Mont limbs LE per Fp coordinate).
void pack_pt(const Element& p, std::uint8_t out[96]) {
    auto put_fp = [&](const Fp& v, std::uint8_t* dst) {
        for (int i = 0; i < 4; ++i) {
            std::uint64_t l = v.limbs[i];
            for (int j = 0; j < 8; ++j) {
                dst[i * 8 + j] = std::uint8_t(l & 0xffULL);
                l >>= 8;
            }
        }
    };
    put_fp(p.X, out);
    put_fp(p.Y, out + 32);
    put_fp(p.Z, out + 64);
}

// Compare CPU Element to packed 96 bytes (Mont limbs LE).
bool eq_pt(const Element& cpu, const std::uint8_t gpu_bytes[96]) {
    std::uint8_t cpu_bytes[96];
    pack_pt(cpu, cpu_bytes);
    return std::memcmp(cpu_bytes, gpu_bytes, 96) == 0;
}

}  // namespace

int main() {
    std::fprintf(stdout, "=== banderwagon CPU vs Metal byte-equality ===\n");

    int failures = 0;

#if __APPLE__
    const char* metallib = std::getenv("KINET_CRYPTO_BANDERWAGON_METALLIB");
    if (!metallib) {
        std::fprintf(stdout, "(skip GPU equality: KINET_CRYPTO_BANDERWAGON_METALLIB unset)\n");
        std::fprintf(stdout, "=== ALL TESTS PASSED (GPU skipped) ===\n");
        return 0;
    }

    // -----------------------------------------------------------------
    // 1. Add: 100 random pairs.
    // -----------------------------------------------------------------
    {
        constexpr int N = 100;
        std::vector<std::uint8_t> pairs(N * 192);
        std::vector<Element>      cpu_pts_p(N);
        std::vector<Element>      cpu_pts_q(N);
        for (int i = 0; i < N; ++i) {
            cpu_pts_p[i] = random_element();
            cpu_pts_q[i] = random_element();
            pack_pt(cpu_pts_p[i], pairs.data() + i * 192);
            pack_pt(cpu_pts_q[i], pairs.data() + i * 192 + 96);
        }
        std::vector<std::uint8_t> outs(N * 96, 0);
        int rc = banderwagon_metal_add_batch(pairs.data(), outs.data(), N, metallib);
        if (rc != 0) {
            std::fprintf(stderr, "FAIL Metal add dispatch rc=%d\n", rc);
            return 1;
        }
        int eq = 0;
        for (int i = 0; i < N; ++i) {
            Element cpu = Element::add(cpu_pts_p[i], cpu_pts_q[i]);
            if (eq_pt(cpu, outs.data() + i * 96)) ++eq;
            else ++failures;
        }
        std::fprintf(stdout, "%s add  byte-equal %d/%d pairs\n",
            eq == N ? "PASS" : "FAIL", eq, N);
    }

    // -----------------------------------------------------------------
    // 2. scalar_mul: 100 random (Element, Fr).
    // -----------------------------------------------------------------
    {
        constexpr int N = 100;
        std::vector<std::uint8_t> pts(N * 96);
        std::vector<std::uint8_t> scalars(N * 32);
        std::vector<Element>      cpu_pts(N);
        std::vector<Fr>           cpu_scl(N);
        for (int i = 0; i < N; ++i) {
            cpu_pts[i] = random_element();
            cpu_scl[i] = random_fr();
            pack_pt(cpu_pts[i], pts.data() + i * 96);
            cpu_scl[i].to_bytes_le(scalars.data() + i * 32);
        }
        std::vector<std::uint8_t> outs(N * 96, 0);
        int rc = banderwagon_metal_smul_batch(pts.data(), scalars.data(),
                                              outs.data(), N, metallib);
        if (rc != 0) {
            std::fprintf(stderr, "FAIL Metal smul dispatch rc=%d\n", rc);
            return 1;
        }
        int eq = 0;
        for (int i = 0; i < N; ++i) {
            Element cpu = Element::scalar_mul(cpu_pts[i], cpu_scl[i]);
            if (eq_pt(cpu, outs.data() + i * 96)) ++eq;
            else ++failures;
        }
        std::fprintf(stdout, "%s smul byte-equal %d/%d pairs\n",
            eq == N ? "PASS" : "FAIL", eq, N);
    }

    // -----------------------------------------------------------------
    // 3. MSM: 5 sizes, varying M batch widths.
    // -----------------------------------------------------------------
    {
        struct Spec { int n; int M; };
        const Spec specs[5] = {
            { 64,   1 },
            { 64,   4 },
            { 256,  2 },
            { 1024, 1 },
            { 1024, 3 },
        };
        for (int s = 0; s < 5; ++s) {
            int n = specs[s].n;
            int M = specs[s].M;

            // Shared point set.
            std::vector<std::uint8_t> pts_buf(n * 96);
            std::vector<Element>      cpu_pts(n);
            for (int i = 0; i < n; ++i) {
                cpu_pts[i] = random_element();
                pack_pt(cpu_pts[i], pts_buf.data() + i * 96);
            }

            // Per-batch scalars.
            std::vector<std::uint8_t> scalars(M * n * 32);
            std::vector<std::vector<Fr>> cpu_scalars(M, std::vector<Fr>(n));
            for (int b = 0; b < M; ++b) {
                for (int i = 0; i < n; ++i) {
                    cpu_scalars[b][i] = random_fr();
                    cpu_scalars[b][i].to_bytes_le(
                        scalars.data() + (b * n + i) * 32);
                }
            }

            // GPU MSMs.
            std::vector<std::uint8_t> outs(M * 96, 0);
            int rc = banderwagon_metal_msm_batch(pts_buf.data(),
                                                 scalars.data(),
                                                 outs.data(),
                                                 (size_t)n, (size_t)M,
                                                 metallib);
            if (rc != 0) {
                std::fprintf(stderr, "FAIL Metal msm dispatch rc=%d\n", rc);
                return 1;
            }

            // CPU oracle MSMs (naive).
            int eq = 0;
            for (int b = 0; b < M; ++b) {
                Element acc = Element::identity();
                for (int i = 0; i < n; ++i) {
                    Element term = Element::scalar_mul(cpu_pts[i],
                                                       cpu_scalars[b][i]);
                    acc = Element::add(acc, term);
                }
                if (eq_pt(acc, outs.data() + b * 96)) ++eq;
                else ++failures;
            }
            std::fprintf(stdout, "%s msm  n=%4d M=%d byte-equal %d/%d\n",
                eq == M ? "PASS" : "FAIL", n, M, eq, M);
        }
    }
#else
    std::fprintf(stdout, "(non-Apple host: GPU equality skipped)\n");
#endif

    std::fprintf(stdout, "=== %s (%d failure%s) ===\n",
        failures == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED",
        failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
