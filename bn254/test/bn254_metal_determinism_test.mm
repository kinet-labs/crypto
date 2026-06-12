// CPU vs Metal byte-equality test for bn254 G1 ops + Pedersen commitments.
//
// Four batteries:
//   1. 100 random (scalar, point) pairs        : CPU vs Metal byte-equal
//      for g1_scalar_mul (constant-time ladder).
//   2. 100 random Pedersen (v, r) commits      : CPU vs Metal byte-equal,
//      with G,H derived via bn254_hash_to_g1(seed, "KINET_PEDERSEN_*").
//   3. 5 G1 add edge cases (P+P, P+(-P), P+0)  : assert algebraic identities.
//   4. 5 Pedersen hiding-distinguishability    : commit(v1,r1) != commit(v2,r2)
//      whenever (v1,r1) != (v2,r2).
//
// On non-Apple hosts the GPU batteries are skipped; CPU-only checks (#3, #4)
// still run.  On Apple hosts without CRYPTO_BN254_METALLIB set, the file
// still links and registers as a passing test that records the GPU was skipped.

#include "../cpp/bn254_fp.hpp"
#include "../cpp/bn254_g1.hpp"
#include "../cpp/bn254_hash_to_curve.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#if __APPLE__
#include "zk_metal.h"
extern "C" {
int metal_is_available(void);
int metal_pedersen_commit(const uint64_t* value, const uint64_t* blinding,
                          uint64_t* commitmentX, uint64_t* commitmentY);
int metal_bn254_scalar_mul(const uint64_t* px, const uint64_t* py,
                           const uint64_t* scalar,
                           uint64_t* rx, uint64_t* ry);
int metal_bn254_add(const uint64_t* ax, const uint64_t* ay,
                    const uint64_t* bx, const uint64_t* by,
                    uint64_t* rx, uint64_t* ry);
}
#endif

using kinet::crypto::bn254::U256;
using kinet::crypto::bn254::G1Affine;
using kinet::crypto::bn254::G1Jac;
using kinet::crypto::bn254::g1_to_jac;
using kinet::crypto::bn254::g1_to_affine;
using kinet::crypto::bn254::g1_add;
using kinet::crypto::bn254::g1_scalar_mul;
using kinet::crypto::bn254::to_mont_fp;
using kinet::crypto::bn254::from_mont_fp;
using kinet::crypto::bn254::fp_neg;
using kinet::crypto::bn254::P;
using kinet::crypto::bn254::FR_ORDER;
using kinet::crypto::bn254::h2c::hash_to_curve_g1;

namespace {

// Deterministic xorshift PRNG -- byte-stable across hosts.
struct PRNG {
    uint64_t s;
    explicit PRNG(uint64_t seed) : s(seed ? seed : 0xDEADBEEFCAFEBABEULL) {}
    uint64_t next() {
        s ^= s >> 12; s ^= s << 25; s ^= s >> 27;
        return s * 2685821657736338717ULL;
    }
};

// Random scalar (canonical Fr, 32 bytes LE).  Top bits cleared to keep
// value comfortably below FR_ORDER without rejection sampling.
void prng_scalar32(PRNG& g, uint8_t out[32]) {
    for (int i = 0; i < 32; i += 8) {
        uint64_t v = g.next();
        for (int j = 0; j < 8; j++) out[i + j] = uint8_t((v >> (j * 8)) & 0xFF);
    }
    out[31] &= 0x0F;
}

void scalar32_to_limbs(const uint8_t in[32], uint64_t out[4]) {
    for (int i = 0; i < 4; i++) {
        uint64_t v = 0;
        for (int j = 0; j < 8; j++) v |= uint64_t(in[i * 8 + j]) << (j * 8);
        out[i] = v;
    }
}

// Random valid G1 point on the curve via H2C of fresh entropy.
G1Affine random_g1(PRNG& g) {
    uint8_t msg[32];
    for (int i = 0; i < 32; i++) msg[i] = uint8_t(g.next() & 0xFF);
    const uint8_t dst[] = {'L','U','X','_','B','N','2','5','4','_','T','E','S','T'};
    return hash_to_curve_g1({msg, sizeof(msg)}, {dst, sizeof(dst)});
}

// Derive G,H exactly the same way the host driver does in initBN254Pipelines().
void derive_pedersen_GH(G1Affine& G, G1Affine& H) {
    const uint8_t seed_g[] = {'s','e','e','d','_','g'};
    const uint8_t seed_h[] = {'s','e','e','d','_','h'};
    const uint8_t dst_g[]  = {'L','U','X','_','P','E','D','E','R','S','E','N','_','G'};
    const uint8_t dst_h[]  = {'L','U','X','_','P','E','D','E','R','S','E','N','_','H'};
    G = hash_to_curve_g1({seed_g, sizeof(seed_g)}, {dst_g, sizeof(dst_g)});
    H = hash_to_curve_g1({seed_h, sizeof(seed_h)}, {dst_h, sizeof(dst_h)});
}

bool eq_affine(const G1Affine& a, const G1Affine& b) {
    if (a.infinity != b.infinity) return false;
    if (a.infinity) return true;
    return std::memcmp(a.x.limbs, b.x.limbs, 32) == 0
        && std::memcmp(a.y.limbs, b.y.limbs, 32) == 0;
}

// CPU oracle: Pedersen v*G + r*H using the canonical (G,H).
G1Affine pedersen_cpu(const G1Affine& G, const G1Affine& H,
                     const uint64_t v[4], const uint64_t r[4]) {
    U256 vs; std::memcpy(vs.limbs, v, 32);
    U256 rs; std::memcpy(rs.limbs, r, 32);
    G1Jac vG = g1_scalar_mul(G, vs);
    G1Jac rH = g1_scalar_mul(H, rs);
    G1Jac sum = g1_add(vG, rH);
    return g1_to_affine(sum);
}

}  // namespace

int main() {
    std::fprintf(stdout, "=== bn254 CPU vs Metal byte-equality ===\n");
    int failures = 0;

    G1Affine G, H;
    derive_pedersen_GH(G, H);

#if __APPLE__
    bool gpu_available = (metal_is_available() == 1);
    const char* metallib = std::getenv("CRYPTO_BN254_METALLIB");
    if (!gpu_available || !metallib) {
        std::fprintf(stdout,
            "(skip GPU equality: metal_is_available=%d metallib=%s)\n",
            (int)gpu_available, metallib ? metallib : "<unset>");
        gpu_available = false;
    }

    // Battery 1: scalar mul -- 100 random (s, P).
    if (gpu_available) {
        constexpr int N = 100;
        PRNG g(0x515CA1A4D050B17EULL);
        int eq = 0;
        for (int i = 0; i < N; i++) {
            G1Affine P = random_g1(g);
            uint8_t s_bytes[32]; prng_scalar32(g, s_bytes);
            uint64_t s_limbs[4];  scalar32_to_limbs(s_bytes, s_limbs);

            G1Jac jac = g1_scalar_mul(P,
                U256{s_limbs[0], s_limbs[1], s_limbs[2], s_limbs[3]});
            G1Affine cpu = g1_to_affine(jac);

            uint64_t gpu_x[4], gpu_y[4];
            int rc = metal_bn254_scalar_mul(P.x.limbs, P.y.limbs, s_limbs,
                                            gpu_x, gpu_y);
            if (rc != 0) { failures++; continue; }
            if (std::memcmp(cpu.x.limbs, gpu_x, 32) == 0 &&
                std::memcmp(cpu.y.limbs, gpu_y, 32) == 0) eq++;
            else failures++;
        }
        std::fprintf(stdout, "%s scalar_mul byte-equal %d/%d\n",
            eq == N ? "PASS" : "FAIL", eq, N);
    }

    // Battery 2: Pedersen commit -- 100 random (v, r).
    if (gpu_available) {
        constexpr int N = 100;
        PRNG g(0xC0DECABC0DECABULL);
        int eq = 0;
        for (int i = 0; i < N; i++) {
            uint8_t v_bytes[32], r_bytes[32];
            prng_scalar32(g, v_bytes);
            prng_scalar32(g, r_bytes);
            uint64_t v[4], r[4];
            scalar32_to_limbs(v_bytes, v);
            scalar32_to_limbs(r_bytes, r);

            G1Affine cpu = pedersen_cpu(G, H, v, r);

            uint64_t gpu_x[4], gpu_y[4];
            int rc = metal_pedersen_commit(v, r, gpu_x, gpu_y);
            if (rc != 0) { failures++; continue; }

            if (std::memcmp(cpu.x.limbs, gpu_x, 32) == 0 &&
                std::memcmp(cpu.y.limbs, gpu_y, 32) == 0) eq++;
            else failures++;
        }
        std::fprintf(stdout, "%s pedersen_commit byte-equal %d/%d\n",
            eq == N ? "PASS" : "FAIL", eq, N);
    }
#else
    std::fprintf(stdout, "(non-Apple host: GPU batteries skipped)\n");
#endif

    // Battery 3: G1 add edge cases (CPU-only sanity, runs everywhere).
    {
        PRNG g(0xADDEDFACE00FFEE5ULL);
        int passed = 0;
        const int CASES = 5;
        for (int i = 0; i < CASES; i++) {
            G1Affine P = random_g1(g);
            G1Jac    Pj = g1_to_jac(P);

            G1Jac dbl = g1_add(Pj, Pj);
            G1Affine dbl_a = g1_to_affine(dbl);

            G1Affine negP = P;
            negP.y = fp_neg(P.y);
            G1Jac infj = g1_add(Pj, g1_to_jac(negP));
            G1Affine infa = g1_to_affine(infj);

            G1Jac zero;
            zero.X = U256{}; zero.Y = U256{}; zero.Z = U256{};
            zero.infinity = true;
            G1Jac p_plus_zero = g1_add(Pj, zero);
            G1Affine p_plus_zero_a = g1_to_affine(p_plus_zero);

            bool ok = !dbl_a.infinity
                   && infa.infinity
                   && eq_affine(p_plus_zero_a, P);
            if (ok) passed++;
            else failures++;
        }
        std::fprintf(stdout, "%s g1_add edge-cases %d/%d\n",
            passed == CASES ? "PASS" : "FAIL", passed, CASES);
    }

    // Battery 4: Pedersen hiding distinguishability -- distinct (v,r)
    // yield distinct commitments under canonical (G, H).
    {
        PRNG g(0xB1ADE5C0FFEEFACEULL);
        int passed = 0;
        const int CASES = 5;
        for (int i = 0; i < CASES; i++) {
            uint8_t b1[32], b2[32], b3[32], b4[32];
            prng_scalar32(g, b1); prng_scalar32(g, b2);
            prng_scalar32(g, b3); prng_scalar32(g, b4);
            // Force inequality if accidentally equal.
            if (std::memcmp(b1, b3, 32) == 0 && std::memcmp(b2, b4, 32) == 0) {
                b3[0] ^= 0x01;
            }
            uint64_t v1[4], r1[4], v2[4], r2[4];
            scalar32_to_limbs(b1, v1); scalar32_to_limbs(b2, r1);
            scalar32_to_limbs(b3, v2); scalar32_to_limbs(b4, r2);

            G1Affine c1 = pedersen_cpu(G, H, v1, r1);
            G1Affine c2 = pedersen_cpu(G, H, v2, r2);
            if (!eq_affine(c1, c2)) passed++;
            else failures++;
        }
        std::fprintf(stdout, "%s pedersen distinguishability %d/%d\n",
            passed == CASES ? "PASS" : "FAIL", passed, CASES);
    }

    std::fprintf(stdout, "=== %s (%d failure%s) ===\n",
        failures == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED",
        failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
