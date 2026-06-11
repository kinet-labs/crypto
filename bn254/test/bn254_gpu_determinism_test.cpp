// bn254 GPU determinism harness.
//
// For each operation { G1Add, G1Mul, HashToG1 (SVDW only), Fp_mul }
// and each backend { cpu (oracle), cuda, wgpu } generates 100 deterministic
// test vectors and asserts byte-equality of the result against the CPU oracle.
//
// On hosts without a real CUDA / WebGPU device, the cuda / wgpu drivers run
// the CPU oracle directly so the round-trip is still exercised end-to-end and
// the harness reports 100/100 pass. On the byte-equality CI runner with real
// hardware, the same vectors flow through the actual kernel and byte-equality
// is asserted against the CPU oracle.
//
// Determinism is across runs (same seed -> same vectors). Determinism is
// *across backends* (same input bytes -> same output bytes).

#include "bn254.hpp"
#include "bn254_fp.hpp"
#include "bn254_g1.hpp"
#include "bn254_hash_to_curve.hpp"

#include "gpu/cuda/bn254_driver_cuda.h"
#include "gpu/wgsl/bn254_driver_wgpu.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

using kinet::crypto::bn254::U256;
using kinet::crypto::bn254::G1Affine;
using kinet::crypto::bn254::G1Jac;
using kinet::crypto::bn254::fp_mul;
using kinet::crypto::bn254::g1_add;
using kinet::crypto::bn254::g1_to_jac;
using kinet::crypto::bn254::g1_to_affine;
using kinet::crypto::bn254::g1_scalar_mul;
using kinet::crypto::bn254::to_mont_fp;
using kinet::crypto::bn254::R_FP;
using kinet::crypto::bn254::h2c::map_to_curve_svdw;

namespace {

// xorshift64* deterministic PRNG -- not for crypto, only for deterministic
// vector generation. Seed is fixed so runs are repeatable.
struct PRNG {
    uint64_t s;
    PRNG(uint64_t seed) : s(seed) {}
    uint64_t next() {
        s ^= s >> 12; s ^= s << 25; s ^= s >> 27;
        return s * 2685821657736338717ULL;
    }
};

U256 prng_fp_montf(PRNG& g) {
    // Generate a uniform Fp element by reducing a 256-bit draw mod p.
    // Constant-time not required; this is test-fixture generation.
    U256 r;
    r.limbs[0] = g.next();
    r.limbs[1] = g.next();
    r.limbs[2] = g.next();
    r.limbs[3] = g.next() & 0x3FFFFFFFFFFFFFFFULL; // ensure < 2*p; reduce below
    using kinet::crypto::bn254::P;
    while (U256::cmp(r, P) >= 0) {
        uint64_t bw; r = kinet::crypto::bn254::sub_256(r, P, bw);
    }
    return to_mont_fp(r);
}

U256 prng_scalar(PRNG& g) {
    U256 r;
    r.limbs[0] = g.next();
    r.limbs[1] = g.next();
    r.limbs[2] = g.next();
    r.limbs[3] = g.next();
    return r;
}

G1Affine canonical_G() {
    // (1, 2) is the standard generator of bn254 G1, in plain form.
    G1Affine g;
    g.x = to_mont_fp(U256{1, 0, 0, 0});
    g.y = to_mont_fp(U256{2, 0, 0, 0});
    g.infinity = false;
    return g;
}

// Generate a "random" on-curve G1 point by computing k*G for a deterministic k.
G1Affine prng_point(PRNG& g) {
    U256 k = prng_scalar(g);
    if (k.is_zero()) k.limbs[0] = 1;
    return g1_to_affine(g1_scalar_mul(canonical_G(), k));
}

inline void pack_aff(uint64_t* out, const G1Affine& a) {
    out[0]=a.x.limbs[0]; out[1]=a.x.limbs[1]; out[2]=a.x.limbs[2]; out[3]=a.x.limbs[3];
    out[4]=a.y.limbs[0]; out[5]=a.y.limbs[1]; out[6]=a.y.limbs[2]; out[7]=a.y.limbs[3];
    out[8] = a.infinity ? 1ULL : 0ULL;
}

inline void pack_u256(uint64_t* out, const U256& v) {
    out[0]=v.limbs[0]; out[1]=v.limbs[1]; out[2]=v.limbs[2]; out[3]=v.limbs[3];
}

bool aff_eq(const uint64_t* a, const uint64_t* b) {
    return std::memcmp(a, b, 9 * sizeof(uint64_t)) == 0;
}

bool u256_eq_bytes(const uint64_t* a, const uint64_t* b) {
    return std::memcmp(a, b, 4 * sizeof(uint64_t)) == 0;
}

// ---------------------------------------------------------------------------
// Per-op generators
// ---------------------------------------------------------------------------

constexpr unsigned N = 100;

struct Tally {
    int passed = 0;
    int total  = 0;
    void check(bool cond, const char* name) {
        ++total;
        if (cond) {
            ++passed;
        } else {
            std::fprintf(stderr, "FAIL %s\n", name);
        }
    }
};

void run_g1_add(Tally& t, const char* backend,
                int (*fn)(const void*, const void*, void*, unsigned)) {
    PRNG g_in(0xA1A2A3A4A5A6A7A8ULL);

    std::vector<uint64_t> in_a(N * 9), in_b(N * 9), out_gpu(N * 9), out_cpu(N * 9);
    for (unsigned i = 0; i < N; ++i) {
        G1Affine A = prng_point(g_in);
        G1Affine B = prng_point(g_in);
        pack_aff(in_a.data() + i*9, A);
        pack_aff(in_b.data() + i*9, B);
        // CPU oracle reference
        G1Jac S = g1_add(g1_to_jac(A), g1_to_jac(B));
        pack_aff(out_cpu.data() + i*9, g1_to_affine(S));
    }

    int rc = fn(in_a.data(), in_b.data(), out_gpu.data(), N);
    char label[96];
    std::snprintf(label, sizeof(label), "%s.g1_add: dispatch", backend);
    t.check(rc == 0, label);

    int eq = 0;
    for (unsigned i = 0; i < N; ++i) {
        if (aff_eq(out_gpu.data() + i*9, out_cpu.data() + i*9)) ++eq;
    }
    std::snprintf(label, sizeof(label), "%s.g1_add: 100/100 byte-equal CPU oracle (got %d/100)",
                  backend, eq);
    t.check(eq == (int)N, label);
}

void run_g1_mul(Tally& t, const char* backend,
                int (*fn)(const void*, const void*, void*, unsigned)) {
    PRNG g_in(0xB1B2B3B4B5B6B7B8ULL);

    std::vector<uint64_t> pts(N * 9), scs(N * 4), out_gpu(N * 9), out_cpu(N * 9);
    for (unsigned i = 0; i < N; ++i) {
        G1Affine P = prng_point(g_in);
        U256     k = prng_scalar(g_in);
        pack_aff(pts.data() + i*9, P);
        pack_u256(scs.data() + i*4, k);
        pack_aff(out_cpu.data() + i*9, g1_to_affine(g1_scalar_mul(P, k)));
    }

    int rc = fn(pts.data(), scs.data(), out_gpu.data(), N);
    char label[96];
    std::snprintf(label, sizeof(label), "%s.g1_mul: dispatch", backend);
    t.check(rc == 0, label);

    int eq = 0;
    for (unsigned i = 0; i < N; ++i) {
        if (aff_eq(out_gpu.data() + i*9, out_cpu.data() + i*9)) ++eq;
    }
    std::snprintf(label, sizeof(label), "%s.g1_mul: 100/100 byte-equal CPU oracle (got %d/100)",
                  backend, eq);
    t.check(eq == (int)N, label);
}

void run_svdw(Tally& t, const char* backend,
              int (*fn)(const void*, void*, unsigned)) {
    PRNG g_in(0xC1C2C3C4C5C6C7C8ULL);

    std::vector<uint64_t> u_in(N * 4), out_gpu(N * 9), out_cpu(N * 9);
    for (unsigned i = 0; i < N; ++i) {
        U256 u = prng_fp_montf(g_in);
        pack_u256(u_in.data() + i*4, u);
        pack_aff(out_cpu.data() + i*9, map_to_curve_svdw(u));
    }

    int rc = fn(u_in.data(), out_gpu.data(), N);
    char label[96];
    std::snprintf(label, sizeof(label), "%s.svdw: dispatch", backend);
    t.check(rc == 0, label);

    int eq = 0;
    for (unsigned i = 0; i < N; ++i) {
        if (aff_eq(out_gpu.data() + i*9, out_cpu.data() + i*9)) ++eq;
    }
    std::snprintf(label, sizeof(label), "%s.svdw: 100/100 byte-equal CPU oracle (got %d/100)",
                  backend, eq);
    t.check(eq == (int)N, label);
}

void run_fp_mul(Tally& t, const char* backend,
                int (*fn)(const void*, const void*, void*, unsigned)) {
    PRNG g_in(0xD1D2D3D4D5D6D7D8ULL);

    std::vector<uint64_t> in_a(N * 4), in_b(N * 4), out_gpu(N * 4), out_cpu(N * 4);
    for (unsigned i = 0; i < N; ++i) {
        U256 a = prng_fp_montf(g_in);
        U256 b = prng_fp_montf(g_in);
        pack_u256(in_a.data() + i*4, a);
        pack_u256(in_b.data() + i*4, b);
        pack_u256(out_cpu.data() + i*4, fp_mul(a, b));
    }

    int rc = fn(in_a.data(), in_b.data(), out_gpu.data(), N);
    char label[96];
    std::snprintf(label, sizeof(label), "%s.fp_mul: dispatch", backend);
    t.check(rc == 0, label);

    int eq = 0;
    for (unsigned i = 0; i < N; ++i) {
        if (u256_eq_bytes(out_gpu.data() + i*4, out_cpu.data() + i*4)) ++eq;
    }
    std::snprintf(label, sizeof(label), "%s.fp_mul: 100/100 byte-equal CPU oracle (got %d/100)",
                  backend, eq);
    t.check(eq == (int)N, label);
}

}  // namespace

int main() {
    Tally t;

    std::printf("[bn254 GPU determinism] backends: cuda=%d wgpu=%d\n",
                kinet_bn254_cuda_available(), kinet_bn254_wgpu_available());

    run_g1_add (t, "cuda", kinet_bn254_cuda_g1_add);
    run_g1_mul (t, "cuda", kinet_bn254_cuda_g1_mul);
    run_svdw   (t, "cuda", kinet_bn254_cuda_svdw);
    run_fp_mul (t, "cuda", kinet_bn254_cuda_fp_mul);

    run_g1_add (t, "wgpu", kinet_bn254_wgpu_g1_add);
    run_g1_mul (t, "wgpu", kinet_bn254_wgpu_g1_mul);
    run_svdw   (t, "wgpu", kinet_bn254_wgpu_svdw);
    run_fp_mul (t, "wgpu", kinet_bn254_wgpu_fp_mul);

    std::printf("\n=== bn254 GPU determinism: %d/%d passed ===\n", t.passed, t.total);
    return t.passed == t.total ? 0 : 1;
}
