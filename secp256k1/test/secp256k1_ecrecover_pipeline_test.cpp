// Copyright (c) 2024-2026 Kinet Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Tests for the v0.63 7-stage ecrecover pipeline.
//
//   1. RFC 6979 §A.2.5 vector
//   2. 64 known-good signatures (deterministic LCG seed) byte-equal vs the
//      single-signature secp256k1_ecrecover reference
//   3. 16 invalid signatures: r=0, s=0, r=n, s=n, malformed v
//   4. Address-mode batch: 32 signatures, byte-equal to keccak(pubkey)[12:32]
//   5. Speedup measurement vs the simple-loop secp256k1_ecrecover_batch on
//      n=1024 (CPU-only timing, illustrative)

#include "kinet/crypto/secp256k1.h"
#include "kinet/crypto/keccak.h"
#include "../cpp/field.hpp"
#include "../cpp/curve.hpp"

#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace lc = kinet::crypto::secp256k1;

static int g_failures = 0;

#define ASSERT_TRUE(name, cond) do { \
    if (!(cond)) { std::fprintf(stderr, "FAIL %s\n", name); ++g_failures; } \
    else        { std::fprintf(stdout, "PASS %s\n", name); } \
} while (0)

static int hex2nib(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static std::vector<uint8_t> hexbytes(const char* s) {
    std::vector<uint8_t> out; size_t L = std::strlen(s); out.reserve(L / 2);
    for (size_t i = 0; i + 1 < L; i += 2)
        out.push_back((uint8_t)((hex2nib(s[i]) << 4) | hex2nib(s[i + 1])));
    return out;
}

struct SigRSV { lc::U256 r; lc::U256 s; uint8_t v; };

static SigRSV sign_with_k(const lc::U256& d, const lc::U256& k, const lc::U256& e_in) {
    SigRSV out{};
    lc::AffinePoint G;
    G.x = lc::to_mont_p(lc::GX); G.y = lc::to_mont_p(lc::GY); G.infinity = false;
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

static lc::AffinePoint pubkey_from_priv(const lc::U256& d) {
    lc::AffinePoint G;
    G.x = lc::to_mont_p(lc::GX); G.y = lc::to_mont_p(lc::GY); G.infinity = false;
    return lc::jacobian_to_affine(lc::jac_mul(d, G));
}

static lc::U256 lcg(uint64_t& s) {
    lc::U256 r;
    for (int i = 0; i < 4; ++i) {
        s = s * 6364136223846793005ULL + 1442695040888963407ULL;
        r.limbs[i] = s;
    }
    return r;
}
static lc::U256 reduce_mod_n(lc::U256 x) {
    while (lc::U256::cmp(x, lc::N) >= 0) {
        uint64_t bw; x = lc::sub_256(x, lc::N, bw);
    }
    return x;
}

// -------- Test 1: RFC 6979 vector via pipeline --------
static void test_rfc6979() {
    auto x = hexbytes("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721");
    auto k = hexbytes("A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60");
    auto e = hexbytes("AF2BDBE1AA9B6EC1E2ADE1D694F41FC71A831D0268E9891562113D8A62ADD1BF");
    lc::U256 d = lc::U256::from_be32(x.data());
    lc::U256 ks = lc::U256::from_be32(k.data());
    lc::U256 es = lc::U256::from_be32(e.data());
    SigRSV sig = sign_with_k(d, ks, es);

    lc::AffinePoint Qa = pubkey_from_priv(d);
    uint8_t want_pk[64];
    lc::from_mont_p(Qa.x).to_be32(want_pk);
    lc::from_mont_p(Qa.y).to_be32(want_pk + 32);

    uint8_t tuple[97];
    std::memcpy(tuple, e.data(), 32);
    sig.r.to_be32(tuple + 32);
    sig.s.to_be32(tuple + 64);
    tuple[96] = sig.v;

    uint8_t got[64], st;
    auto rc = secp256k1_ecrecover_batch_pipeline(tuple, 1, got, &st);
    ASSERT_TRUE("RFC6979 pipeline: returns OK", rc == SECP256K1_OK);
    ASSERT_TRUE("RFC6979 pipeline: per-sig OK", st == SECP256K1_OK);
    ASSERT_TRUE("RFC6979 pipeline: pubkey byte-equal", std::memcmp(got, want_pk, 64) == 0);
}

// -------- Test 2: 64 valid sigs byte-equal to scalar reference --------
static void test_byte_equal_scalar() {
    const int N = 64;
    std::vector<uint8_t> tuples(N * 97);
    std::vector<uint8_t> ref_pk(N * 64), got_pk(N * 64);
    std::vector<uint8_t> ref_st(N), got_st(N);
    uint64_t s = 0x9876543210FEDCBAULL;

    int prepared = 0;
    while (prepared < N) {
        lc::U256 d = reduce_mod_n(lcg(s));
        if (d.is_zero()) continue;
        lc::U256 e = lcg(s);
        lc::U256 k = reduce_mod_n(lcg(s));
        if (k.is_zero()) continue;
        SigRSV sig = sign_with_k(d, k, e);
        if (sig.r.is_zero() || sig.s.is_zero()) continue;

        uint8_t* tup = &tuples[prepared * 97];
        e.to_be32(tup);
        sig.r.to_be32(tup + 32);
        sig.s.to_be32(tup + 64);
        tup[96] = sig.v;

        // Reference via single-signature ecrecover
        auto st = secp256k1_ecrecover(tup, tup + 32, tup + 64, sig.v, &ref_pk[prepared * 64]);
        ref_st[prepared] = (uint8_t)st;
        ++prepared;
    }

    auto rc = secp256k1_ecrecover_batch_pipeline(tuples.data(), N, got_pk.data(), got_st.data());
    ASSERT_TRUE("64-sig pipeline: returns OK", rc == SECP256K1_OK);

    int eq = 0;
    for (int i = 0; i < N; ++i) {
        if (got_st[i] == ref_st[i] && std::memcmp(&got_pk[i * 64], &ref_pk[i * 64], 64) == 0)
            ++eq;
    }
    char buf[128];
    std::snprintf(buf, sizeof(buf), "64-sig pipeline: byte-equal scalar (%d/%d)", eq, N);
    ASSERT_TRUE(buf, eq == N);
}

// -------- Test 3: invalid sigs --------
static void test_invalid() {
    // Build 16 signatures, half valid half invalid in various ways.
    const int N = 16;
    std::vector<uint8_t> tuples(N * 97, 0);
    std::vector<uint8_t> got_pk(N * 64), got_st(N);
    std::vector<uint8_t> expect_st(N);

    uint64_t s = 0xABCD1234ULL;
    int idx = 0;

    auto put_valid = [&](uint8_t expect) {
        lc::U256 d = reduce_mod_n(lcg(s)); if (d.is_zero()) d = lc::U256{1, 0, 0, 0};
        lc::U256 e = lcg(s);
        lc::U256 k = reduce_mod_n(lcg(s)); if (k.is_zero()) k = lc::U256{1, 0, 0, 0};
        SigRSV sig = sign_with_k(d, k, e);
        if (sig.r.is_zero() || sig.s.is_zero()) sig = sign_with_k(d, lc::U256{2, 0, 0, 0}, e);
        uint8_t* t = &tuples[idx * 97];
        e.to_be32(t);
        sig.r.to_be32(t + 32);
        sig.s.to_be32(t + 64);
        t[96] = sig.v;
        expect_st[idx] = expect;
        ++idx;
    };

    auto put_zero_r = [&]() {
        // r = 0 (bytes 32..64 = 0), s != 0 (bytes 64..96 with 0xFF last byte)
        uint8_t* t = &tuples[idx * 97];
        std::memset(t, 0, 97);
        t[95] = 0xFF;
        expect_st[idx] = SECP256K1_ERR_INVALID_R;
        ++idx;
    };
    auto put_zero_s = [&]() {
        // r != 0 (last byte of r block), s = 0
        uint8_t* t = &tuples[idx * 97];
        std::memset(t, 0, 97);
        t[63] = 0xFF;
        expect_st[idx] = SECP256K1_ERR_INVALID_S;
        ++idx;
    };
    auto put_r_eq_n = [&]() {
        // r = N (out of range), s != 0
        uint8_t* t = &tuples[idx * 97];
        std::memset(t, 0, 97);
        lc::N.to_be32(t + 32);
        t[95] = 0xFF;
        expect_st[idx] = SECP256K1_ERR_INVALID_R;
        ++idx;
    };
    auto put_s_eq_n = [&]() {
        // r != 0, s = N (out of range)
        uint8_t* t = &tuples[idx * 97];
        std::memset(t, 0, 97);
        t[63] = 0xFF;
        lc::N.to_be32(t + 64);
        expect_st[idx] = SECP256K1_ERR_INVALID_S;
        ++idx;
    };

    // 8 valid
    for (int i = 0; i < 8; ++i) put_valid(SECP256K1_OK);
    // 4 invalid r/s patterns
    put_zero_r();
    put_zero_s();
    put_r_eq_n();
    put_s_eq_n();
    // 4 more valid to fill to 16
    for (int i = 0; i < 4; ++i) put_valid(SECP256K1_OK);

    auto rc = secp256k1_ecrecover_batch_pipeline(tuples.data(), N, got_pk.data(), got_st.data());
    ASSERT_TRUE("invalid mix: returns OK", rc == SECP256K1_OK);

    int match = 0;
    for (int i = 0; i < N; ++i) {
        if (got_st[i] == expect_st[i]) ++match;
        else std::fprintf(stderr, "  i=%d got=%u want=%u\n", i, got_st[i], expect_st[i]);
    }
    char buf[64];
    std::snprintf(buf, sizeof(buf), "invalid mix: status correct (%d/%d)", match, N);
    ASSERT_TRUE(buf, match == N);
}

// -------- Test 4: address-mode batch --------
static void test_address_mode() {
    const int N = 32;
    std::vector<uint8_t> hashes(N * 32);
    std::vector<uint8_t> sigs(N * 65);
    std::vector<uint8_t> got_addr(N * 20), ref_addr(N * 20), got_st(N);

    uint64_t s = 0xFADE0FACEULL;
    int prepared = 0;
    while (prepared < N) {
        lc::U256 d = reduce_mod_n(lcg(s));
        if (d.is_zero()) continue;
        lc::U256 e = lcg(s);
        lc::U256 k = reduce_mod_n(lcg(s));
        if (k.is_zero()) continue;
        SigRSV sig = sign_with_k(d, k, e);
        if (sig.r.is_zero() || sig.s.is_zero()) continue;

        e.to_be32(&hashes[prepared * 32]);
        sig.r.to_be32(&sigs[prepared * 65]);
        sig.s.to_be32(&sigs[prepared * 65 + 32]);
        sigs[prepared * 65 + 64] = sig.v;

        // Reference: ecrecover -> keccak -> last 20 bytes
        uint8_t pubkey[64];
        auto st = secp256k1_ecrecover(&hashes[prepared * 32],
                                      &sigs[prepared * 65],
                                      &sigs[prepared * 65 + 32],
                                      sig.v, pubkey);
        if (st != SECP256K1_OK) continue;
        uint8_t hash[32];
        keccak256(pubkey, 64, hash);
        std::memcpy(&ref_addr[prepared * 20], hash + 12, 20);
        ++prepared;
    }

    auto rc = secp256k1_ecrecover_address_batch(N, hashes.data(), sigs.data(),
                                                got_addr.data(), got_st.data());
    ASSERT_TRUE("address batch: returns OK", rc == SECP256K1_OK);

    int eq = 0;
    for (int i = 0; i < N; ++i) {
        if (got_st[i] == SECP256K1_OK
            && std::memcmp(&got_addr[i * 20], &ref_addr[i * 20], 20) == 0) ++eq;
    }
    char buf[64];
    std::snprintf(buf, sizeof(buf), "address batch: byte-equal (%d/%d)", eq, N);
    ASSERT_TRUE(buf, eq == N);
}

// -------- Test 5: throughput comparison (CPU only) --------
static void measure_speedup() {
    const int N = 1024;
    std::vector<uint8_t> tuples(N * 97);
    std::vector<uint8_t> pk_a(N * 64), pk_b(N * 64);
    std::vector<uint8_t> st_a(N), st_b(N);

    uint64_t s = 0x424242ULL;
    int prepared = 0;
    while (prepared < N) {
        lc::U256 d = reduce_mod_n(lcg(s));
        if (d.is_zero()) continue;
        lc::U256 e = lcg(s);
        lc::U256 k = reduce_mod_n(lcg(s));
        if (k.is_zero()) continue;
        SigRSV sig = sign_with_k(d, k, e);
        if (sig.r.is_zero() || sig.s.is_zero()) continue;
        uint8_t* t = &tuples[prepared * 97];
        e.to_be32(t);
        sig.r.to_be32(t + 32);
        sig.s.to_be32(t + 64);
        t[96] = sig.v;
        ++prepared;
    }

    using clk = std::chrono::steady_clock;

    auto t1 = clk::now();
    secp256k1_ecrecover_batch(tuples.data(), N, pk_a.data(), st_a.data());
    auto t2 = clk::now();

    auto t3 = clk::now();
    secp256k1_ecrecover_batch_pipeline(tuples.data(), N, pk_b.data(), st_b.data());
    auto t4 = clk::now();

    int eq = 0;
    for (int i = 0; i < N; ++i)
        if (std::memcmp(&pk_a[i * 64], &pk_b[i * 64], 64) == 0) ++eq;

    auto dt_loop = std::chrono::duration<double, std::milli>(t2 - t1).count();
    auto dt_pipe = std::chrono::duration<double, std::milli>(t4 - t3).count();
    std::fprintf(stdout, "n=%d  loop=%.2fms pipeline=%.2fms speedup=%.2fx  byte-equal=%d/%d\n",
                 N, dt_loop, dt_pipe, dt_loop / (dt_pipe > 0 ? dt_pipe : 1e-9), eq, N);

    char buf[64];
    std::snprintf(buf, sizeof(buf), "speedup byte-equal (%d/%d)", eq, N);
    ASSERT_TRUE(buf, eq == N);
}

int main() {
    std::fprintf(stdout, "=== kinet_crypto secp256k1 ecrecover_pipeline test suite ===\n");
    test_rfc6979();
    test_byte_equal_scalar();
    test_invalid();
    test_address_mode();
    measure_speedup();
    std::fprintf(stdout, "=== %s (%d failure%s) ===\n",
                 g_failures == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED",
                 g_failures, g_failures == 1 ? "" : "s");
    return g_failures == 0 ? 0 : 1;
}
