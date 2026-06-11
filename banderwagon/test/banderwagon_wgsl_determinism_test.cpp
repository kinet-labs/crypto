// CPU vs WGSL byte-equality determinism test for Banderwagon group ops.
//
// Three batteries identical to the Metal/CUDA tests:
//   1. 100 random Element pairs   : CPU::add(P, Q)        == WGSL add
//   2. 100 random (Element, Fr)   : CPU::scalar_mul(P, s) == WGSL smul
//   3. 5 batch MSMs (sizes 64, 256, 1024, varying batch widths)
//
// The WGSL driver is a host polyfill that mirrors the .wgsl kernel byte-for-
// byte using only u32 ops. The byte-equality proof holds without a wgpu
// runtime in CI.

#include "../cpp/element.hpp"
#include "../cpp/fp.hpp"
#include "../cpp/fr.hpp"
#include "../gpu/wgsl/banderwagon_driver.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

using kinet::banderwagon::Element;
using kinet::banderwagon::Fp;
using kinet::banderwagon::Fr;

namespace {

uint64_t lcg_state = 0x9C5DA7A7BEEF0001ULL;
uint8_t lcg_byte() {
    lcg_state = lcg_state * 6364136223846793005ULL + 1442695040888963407ULL;
    return uint8_t(lcg_state >> 33);
}

Fr random_fr() {
    for (int tries = 0; tries < 32; ++tries) {
        std::uint8_t b[32];
        for (int i = 0; i < 32; ++i) b[i] = lcg_byte();
        b[31] &= 0x0f;
        Fr s;
        if (Fr::from_bytes_le(b, s)) return s;
    }
    return Fr::zero();
}

Element random_element() {
    Fr s = random_fr();
    if (s.is_zero()) {
        std::uint8_t one_le[32] = {1, 0};
        Fr::from_bytes_le(one_le, s);
    }
    return Element::scalar_mul(Element::generator(), s);
}

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

bool eq_pt(const Element& cpu, const std::uint8_t gpu_bytes[96]) {
    std::uint8_t cpu_bytes[96];
    pack_pt(cpu, cpu_bytes);
    return std::memcmp(cpu_bytes, gpu_bytes, 96) == 0;
}

}  // namespace

int main() {
    std::fprintf(stdout, "=== banderwagon CPU vs WGSL byte-equality ===\n");
    int failures = 0;

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
        int rc = banderwagon_wgsl_add_batch(pairs.data(), outs.data(),
                                            (unsigned long)N);
        if (rc != 0) {
            std::fprintf(stderr, "FAIL WGSL add dispatch rc=%d\n", rc);
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
        int rc = banderwagon_wgsl_smul_batch(pts.data(), scalars.data(),
                                             outs.data(), (unsigned long)N);
        if (rc != 0) {
            std::fprintf(stderr, "FAIL WGSL smul dispatch rc=%d\n", rc);
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

    {
        struct Spec { int n; int M; };
        const Spec specs[5] = {
            { 64,   1 }, { 64,   4 }, { 256,  2 },
            { 1024, 1 }, { 1024, 3 },
        };
        for (int s = 0; s < 5; ++s) {
            int n = specs[s].n;
            int M = specs[s].M;

            std::vector<std::uint8_t> pts_buf(n * 96);
            std::vector<Element>      cpu_pts(n);
            for (int i = 0; i < n; ++i) {
                cpu_pts[i] = random_element();
                pack_pt(cpu_pts[i], pts_buf.data() + i * 96);
            }

            std::vector<std::uint8_t> scalars(M * n * 32);
            std::vector<std::vector<Fr>> cpu_scalars(M, std::vector<Fr>(n));
            for (int b = 0; b < M; ++b) {
                for (int i = 0; i < n; ++i) {
                    cpu_scalars[b][i] = random_fr();
                    cpu_scalars[b][i].to_bytes_le(
                        scalars.data() + (b * n + i) * 32);
                }
            }

            std::vector<std::uint8_t> outs(M * 96, 0);
            int rc = banderwagon_wgsl_msm_batch(pts_buf.data(),
                                                scalars.data(),
                                                outs.data(),
                                                (unsigned long)n,
                                                (unsigned long)M);
            if (rc != 0) {
                std::fprintf(stderr, "FAIL WGSL msm dispatch rc=%d\n", rc);
                return 1;
            }

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

    std::fprintf(stdout, "=== %s (%d failure%s) ===\n",
        failures == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED",
        failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
