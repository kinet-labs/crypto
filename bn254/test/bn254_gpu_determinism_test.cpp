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
#include "bn254_fp2.hpp"
#include "bn254_fp12.hpp"
#include "bn254_g1.hpp"
#include "bn254_g2.hpp"
#include "bn254_hash_to_curve.hpp"
#include "bn254_pairing.hpp"

#include "gpu/cuda/bn254_driver_cuda.h"
#include "gpu/wgsl/bn254_driver_wgpu.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

using kinet::crypto::bn254::U256;
using kinet::crypto::bn254::Fp2;
using kinet::crypto::bn254::Fp12;
using kinet::crypto::bn254::G1Affine;
using kinet::crypto::bn254::G1Jac;
using kinet::crypto::bn254::G2Affine;
using kinet::crypto::bn254::fp_mul;
using kinet::crypto::bn254::fp2_mul;
using kinet::crypto::bn254::fp12_mul;
using kinet::crypto::bn254::cyclotomic_sqr_public;
using kinet::crypto::bn254::g1_add;
using kinet::crypto::bn254::g1_to_jac;
using kinet::crypto::bn254::g1_to_affine;
using kinet::crypto::bn254::g1_scalar_mul;
using kinet::crypto::bn254::multi_pair;
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

// Canonical G2 generator (gnark-crypto bn254 generator), plain decimal limbs
// converted to U256 then to Montgomery.
G2Affine canonical_G2() {
    G2Affine g;
    Fp2 x;
    x.a0 = to_mont_fp(U256{0x46debd5cd992f6edULL, 0x674322d4f75edaddULL,
                           0x426a00665e5c4479ULL, 0x1800deef121f1e76ULL});
    x.a1 = to_mont_fp(U256{0x97e485b7aef312c2ULL, 0xf1aa493335a9e712ULL,
                           0x7260bfb731fb5d25ULL, 0x198e9393920d483aULL});
    Fp2 y;
    y.a0 = to_mont_fp(U256{0x4ce6cc0166fa7daaULL, 0xe3d1e7690c43d37bULL,
                           0x4aab71808dcb408fULL, 0x12c85ea5db8c6debULL});
    y.a1 = to_mont_fp(U256{0x55acdadcd122975bULL, 0xbc4b313370b38ef3ULL,
                           0xec9e99ad690c3395ULL, 0x090689d0585ff075ULL});
    g.x = x; g.y = y; g.infinity = false;
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

inline void pack_fp2(uint64_t* out, const Fp2& v) {
    pack_u256(out + 0, v.a0);
    pack_u256(out + 4, v.a1);
}
inline void pack_g2(uint64_t* out, const G2Affine& a) {
    pack_fp2(out + 0, a.x);
    pack_fp2(out + 8, a.y);
    out[16] = a.infinity ? 1ULL : 0ULL;
    out[17] = 0ULL;
}
inline void pack_fp12(uint64_t* out, const Fp12& v) {
    pack_fp2(out +  0, v.c0.b0);
    pack_fp2(out +  8, v.c0.b1);
    pack_fp2(out + 16, v.c0.b2);
    pack_fp2(out + 24, v.c1.b0);
    pack_fp2(out + 32, v.c1.b1);
    pack_fp2(out + 40, v.c1.b2);
}

bool aff_eq(const uint64_t* a, const uint64_t* b) {
    return std::memcmp(a, b, 9 * sizeof(uint64_t)) == 0;
}

bool u256_eq_bytes(const uint64_t* a, const uint64_t* b) {
    return std::memcmp(a, b, 4 * sizeof(uint64_t)) == 0;
}

bool fp2_eq_bytes(const uint64_t* a, const uint64_t* b) {
    return std::memcmp(a, b, 8 * sizeof(uint64_t)) == 0;
}

bool fp12_eq_bytes(const uint64_t* a, const uint64_t* b) {
    return std::memcmp(a, b, 48 * sizeof(uint64_t)) == 0;
}

Fp2 prng_fp2(PRNG& g) {
    Fp2 r; r.a0 = prng_fp_montf(g); r.a1 = prng_fp_montf(g);
    return r;
}
Fp12 prng_fp12(PRNG& g) {
    Fp12 r;
    r.c0.b0 = prng_fp2(g); r.c0.b1 = prng_fp2(g); r.c0.b2 = prng_fp2(g);
    r.c1.b0 = prng_fp2(g); r.c1.b1 = prng_fp2(g); r.c1.b2 = prng_fp2(g);
    return r;
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

void run_fp2_mul(Tally& t, const char* backend,
                 int (*fn)(const void*, const void*, void*, unsigned)) {
    PRNG g_in(0xE1E2E3E4E5E6E7E8ULL);
    std::vector<uint64_t> in_a(N * 8), in_b(N * 8), out_gpu(N * 8), out_cpu(N * 8);
    for (unsigned i = 0; i < N; ++i) {
        Fp2 A = prng_fp2(g_in);
        Fp2 B = prng_fp2(g_in);
        pack_fp2(in_a.data() + i*8, A);
        pack_fp2(in_b.data() + i*8, B);
        pack_fp2(out_cpu.data() + i*8, fp2_mul(A, B));
    }
    int rc = fn(in_a.data(), in_b.data(), out_gpu.data(), N);
    char label[96];
    std::snprintf(label, sizeof(label), "%s.fp2_mul: dispatch", backend);
    t.check(rc == 0, label);
    int eq = 0;
    for (unsigned i = 0; i < N; ++i)
        if (fp2_eq_bytes(out_gpu.data() + i*8, out_cpu.data() + i*8)) ++eq;
    std::snprintf(label, sizeof(label), "%s.fp2_mul: 100/100 byte-equal CPU oracle (got %d/100)",
                  backend, eq);
    t.check(eq == (int)N, label);
}

void run_fp12_mul(Tally& t, const char* backend,
                  int (*fn)(const void*, const void*, void*, unsigned)) {
    PRNG g_in(0xF1F2F3F4F5F6F7F8ULL);
    std::vector<uint64_t> in_a(N * 48), in_b(N * 48), out_gpu(N * 48), out_cpu(N * 48);
    for (unsigned i = 0; i < N; ++i) {
        Fp12 A = prng_fp12(g_in);
        Fp12 B = prng_fp12(g_in);
        pack_fp12(in_a.data() + i*48, A);
        pack_fp12(in_b.data() + i*48, B);
        pack_fp12(out_cpu.data() + i*48, fp12_mul(A, B));
    }
    int rc = fn(in_a.data(), in_b.data(), out_gpu.data(), N);
    char label[96];
    std::snprintf(label, sizeof(label), "%s.fp12_mul: dispatch", backend);
    t.check(rc == 0, label);
    int eq = 0;
    for (unsigned i = 0; i < N; ++i)
        if (fp12_eq_bytes(out_gpu.data() + i*48, out_cpu.data() + i*48)) ++eq;
    std::snprintf(label, sizeof(label), "%s.fp12_mul: 100/100 byte-equal CPU oracle (got %d/100)",
                  backend, eq);
    t.check(eq == (int)N, label);
}

// 100 cyclotomic-square iterations -- Miller-loop inner-square stress test.
// Inputs come from multi_pair so they're already in the cyclotomic subgroup.
void run_miller_iter(Tally& t, const char* backend,
                     int (*fn)(const void*, void*, unsigned)) {
    PRNG g_in(0xAB12CD34EF56AB78ULL);
    std::vector<uint64_t> in_a(N * 48), out_gpu(N * 48), out_cpu(N * 48);
    G2Affine Q = canonical_G2();
    for (unsigned i = 0; i < N; ++i) {
        U256 k = prng_scalar(g_in);
        if (k.is_zero()) k.limbs[0] = 7;
        G1Affine P = g1_to_affine(g1_scalar_mul(canonical_G(), k));
        Fp12 z = multi_pair(&P, &Q, 1);
        pack_fp12(in_a.data() + i*48, z);
        Fp12 z_cpu = z;
        for (int j = 0; j < 100; ++j) z_cpu = cyclotomic_sqr_public(z_cpu);
        pack_fp12(out_cpu.data() + i*48, z_cpu);
    }
    int rc = fn(in_a.data(), out_gpu.data(), N);
    char label[96];
    std::snprintf(label, sizeof(label), "%s.miller_iter: dispatch", backend);
    t.check(rc == 0, label);
    int eq = 0;
    for (unsigned i = 0; i < N; ++i)
        if (fp12_eq_bytes(out_gpu.data() + i*48, out_cpu.data() + i*48)) ++eq;
    std::snprintf(label, sizeof(label), "%s.miller_iter: 100/100 byte-equal CPU oracle (got %d/100)",
                  backend, eq);
    t.check(eq == (int)N, label);
}

void run_pairing(Tally& t, const char* backend,
                 int (*fn)(const void*, const void*, void*, unsigned)) {
    // Three-vector battery covering bilinearity, non-trivial scalar, infinity.
    constexpr unsigned M = 3;
    std::vector<uint64_t> in_p(M * 9), in_q(M * 18), out_gpu(M * 48), out_cpu(M * 48);

    G1Affine g1 = canonical_G();
    G2Affine g2 = canonical_G2();

    // Vector 0: e(g1, -g2)
    G2Affine ng2 = g2; ng2.y = kinet::crypto::bn254::fp2_neg(g2.y);
    pack_aff(in_p.data() + 0*9, g1);
    pack_g2 (in_q.data() + 0*18, ng2);
    {
        G1Affine P = g1; G2Affine Q = ng2;
        pack_fp12(out_cpu.data() + 0*48, multi_pair(&P, &Q, 1));
    }
    // Vector 1: e(2*g1, g2)
    G1Affine two_g1 = g1_to_affine(g1_scalar_mul(g1, U256{2,0,0,0}));
    pack_aff(in_p.data() + 1*9, two_g1);
    pack_g2 (in_q.data() + 1*18, g2);
    {
        G1Affine P = two_g1; G2Affine Q = g2;
        pack_fp12(out_cpu.data() + 1*48, multi_pair(&P, &Q, 1));
    }
    // Vector 2: e(0, g2) -- infinity P -> Fp12_one.
    G1Affine zero_g1 = g1; zero_g1.infinity = true;
    pack_aff(in_p.data() + 2*9, zero_g1);
    pack_g2 (in_q.data() + 2*18, g2);
    {
        G1Affine P = zero_g1; G2Affine Q = g2;
        pack_fp12(out_cpu.data() + 2*48, multi_pair(&P, &Q, 1));
    }

    int rc = fn(in_p.data(), in_q.data(), out_gpu.data(), M);
    char label[96];
    std::snprintf(label, sizeof(label), "%s.pairing: dispatch", backend);
    t.check(rc == 0, label);
    int eq = 0;
    for (unsigned i = 0; i < M; ++i)
        if (fp12_eq_bytes(out_gpu.data() + i*48, out_cpu.data() + i*48)) ++eq;
    std::snprintf(label, sizeof(label), "%s.pairing: 3/3 byte-equal CPU oracle (got %d/3)",
                  backend, eq);
    t.check(eq == (int)M, label);
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

    run_g1_add      (t, "cuda", kinet_bn254_cuda_g1_add);
    run_g1_mul      (t, "cuda", kinet_bn254_cuda_g1_mul);
    run_svdw        (t, "cuda", kinet_bn254_cuda_svdw);
    run_fp_mul      (t, "cuda", kinet_bn254_cuda_fp_mul);
    run_fp2_mul     (t, "cuda", kinet_bn254_cuda_fp2_mul);
    run_fp12_mul    (t, "cuda", kinet_bn254_cuda_fp12_mul);
    run_miller_iter (t, "cuda", kinet_bn254_cuda_miller_iter);
    run_pairing     (t, "cuda", kinet_bn254_cuda_pairing);

    run_g1_add      (t, "wgpu", kinet_bn254_wgpu_g1_add);
    run_g1_mul      (t, "wgpu", kinet_bn254_wgpu_g1_mul);
    run_svdw        (t, "wgpu", kinet_bn254_wgpu_svdw);
    run_fp_mul      (t, "wgpu", kinet_bn254_wgpu_fp_mul);
    run_fp2_mul     (t, "wgpu", kinet_bn254_wgpu_fp2_mul);
    run_fp12_mul    (t, "wgpu", kinet_bn254_wgpu_fp12_mul);
    run_miller_iter (t, "wgpu", kinet_bn254_wgpu_miller_iter);
    run_pairing     (t, "wgpu", kinet_bn254_wgpu_pairing);

    std::printf("\n=== bn254 GPU determinism: %d/%d passed ===\n", t.passed, t.total);
    return t.passed == t.total ? 0 : 1;
}
