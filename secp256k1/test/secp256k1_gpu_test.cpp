// Copyright (c) 2024-2026 Kinet Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// CPU vs GPU byte-equality test for secp256k1.
//
// The Metal kernel currently emits a 20-byte Ethereum address per signature
// (last 20 bytes of keccak256(pubkey)). We compute the same value on CPU and
// assert byte-equal.
//
// Build only when WITH_METAL is on (Apple host). Skipped otherwise.

#include "kinet/crypto/secp256k1.h"
#include "kinet/crypto/keccak.h"
#include "../cpp/field.hpp"
#include "../cpp/curve.hpp"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>

namespace lc = kinet::crypto::secp256k1;

#if __APPLE__
extern "C" kinet_secp256k1_status kinet_secp256k1_ecrecover_address_batch_metal(
    const uint8_t* inputs, size_t n, uint8_t* out_addr, uint8_t* out_st,
    const char* metallib_path);
#endif

static lc::U256 lcg_next(uint64_t& state) {
    lc::U256 r;
    for (int i = 0; i < 4; ++i) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        r.limbs[i] = state;
    }
    return r;
}

static lc::U256 reduce_mod_n(lc::U256 x) {
    while (lc::U256::cmp(x, lc::N) >= 0) {
        uint64_t bw;
        x = lc::sub_256(x, lc::N, bw);
    }
    return x;
}

struct SigRSV { lc::U256 r; lc::U256 s; uint8_t v; };

static SigRSV sign_with_k(const lc::U256& d, const lc::U256& k, const lc::U256& e_in) {
    SigRSV out{};
    lc::AffinePoint G;
    G.x = lc::to_mont_p(lc::GX);
    G.y = lc::to_mont_p(lc::GY);
    G.infinity = false;
    lc::JacobianPoint Rj = lc::jac_mul(k, G);
    lc::AffinePoint Ra = lc::jacobian_to_affine(Rj);
    lc::U256 rx = lc::from_mont_p(Ra.x);
    lc::U256 r = rx;
    if (lc::U256::cmp(r, lc::N) >= 0) { uint64_t bw; r = lc::sub_256(r, lc::N, bw); }
    out.r = r;

    lc::U256 e = e_in;
    if (lc::U256::cmp(e, lc::N) >= 0) { uint64_t bw; e = lc::sub_256(e, lc::N, bw); }

    lc::U256 r_nm = lc::to_mont_n(r);
    lc::U256 d_nm = lc::to_mont_n(d);
    lc::U256 e_nm = lc::to_mont_n(e);
    lc::U256 k_nm = lc::to_mont_n(k);
    lc::U256 rd = lc::fn_mul(r_nm, d_nm);
    lc::U256 sum = lc::fn_add(e_nm, rd);
    lc::U256 k_inv = lc::fn_inv(k_nm);
    lc::U256 s_nm = lc::fn_mul(k_inv, sum);
    out.s = lc::from_mont_n(s_nm);

    lc::U256 ry = lc::from_mont_p(Ra.y);
    out.v = (ry.limbs[0] & 1ULL) ? 1 : 0;
    return out;
}

static int g_failures = 0;

int main(int argc, char** argv) {
    std::fprintf(stdout, "=== kinet_crypto secp256k1 CPU vs GPU equality ===\n");

    // Generate N test inputs deterministically.
    const int N = 32;
    uint64_t state = 0x12345678ABCDEF01ULL;
    std::vector<uint8_t> inputs(N * 97);
    std::vector<uint8_t> cpu_addr(N * 20);

    int prepared = 0;
    while (prepared < N) {
        lc::U256 d = reduce_mod_n(lcg_next(state));
        if (d.is_zero()) continue;
        lc::U256 e = lcg_next(state);
        lc::U256 k = reduce_mod_n(lcg_next(state));
        if (k.is_zero()) continue;
        SigRSV sig = sign_with_k(d, k, e);
        if (sig.r.is_zero() || sig.s.is_zero()) continue;

        uint8_t* base = &inputs[prepared * 97];
        e.to_be32(base);
        sig.r.to_be32(base + 32);
        sig.s.to_be32(base + 64);
        base[96] = sig.v;

        // CPU compute: ecrecover -> pubkey -> keccak256 -> last 20 bytes.
        uint8_t pubkey[64];
        auto st = kinet_secp256k1_ecrecover(base, base + 32, base + 64, sig.v, pubkey);
        if (st != KINET_SECP256K1_OK) {
            std::fprintf(stderr, "CPU ecrecover failed at i=%d\n", prepared);
            return 2;
        }
        uint8_t hash[32];
        kinet_keccak256(pubkey, 64, hash);
        std::memcpy(&cpu_addr[prepared * 20], hash + 12, 20);

        ++prepared;
    }

    // Run GPU path.
#if __APPLE__
    const char* metallib = std::getenv("KINET_CRYPTO_SECP256K1_METALLIB");
    if (!metallib) {
        std::fprintf(stdout, "(skip GPU equality: KINET_CRYPTO_SECP256K1_METALLIB not set)\n");
        std::fprintf(stdout, "=== ALL TESTS PASSED (GPU skipped) ===\n");
        return 0;
    }
    std::vector<uint8_t> gpu_addr(N * 20, 0xFF);
    std::vector<uint8_t> gpu_st(N, 0xFF);
    auto st = kinet_secp256k1_ecrecover_address_batch_metal(
        inputs.data(), N, gpu_addr.data(), gpu_st.data(), metallib);
    if (st != KINET_SECP256K1_OK) {
        std::fprintf(stderr, "GPU dispatch returned %d\n", (int)st);
        return 3;
    }

    int eq = 0;
    for (int i = 0; i < N; ++i) {
        if (gpu_st[i] != 0) {
            std::fprintf(stderr, "i=%d gpu_st=%u\n", i, gpu_st[i]);
            ++g_failures;
            continue;
        }
        if (std::memcmp(&gpu_addr[i * 20], &cpu_addr[i * 20], 20) == 0) ++eq;
        else {
            std::fprintf(stderr, "i=%d MISMATCH\n", i);
            ++g_failures;
        }
    }
    std::fprintf(stdout, "byte-equal: %d/%d\n", eq, N);
    if (eq != N) ++g_failures;
#else
    std::fprintf(stdout, "(non-Apple host: GPU comparison skipped)\n");
#endif

    std::fprintf(stdout, "=== %s (%d failure%s) ===\n",
        g_failures == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED",
        g_failures, g_failures == 1 ? "" : "s");
    return g_failures == 0 ? 0 : 1;
}
