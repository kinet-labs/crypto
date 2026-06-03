// Test Montgomery batch inversion for secp256k1 Fp and Fn.
//
// Three sizes (16, 256, 4096):
//   * batch_inv_fp / batch_inv_fn output i satisfies out[i] * in[i] == 1 (mod m)
//   * compared against fp_inv / fn_inv element-by-element (byte-equal)
//   * a batch with one zero entry leaves out[i]=0 and zero_mask bit set
//
// CPU only here. The Metal kernel (see secp256k1_batch_inv.metal) is exercised
// by secp256k1_ecrecover_pipeline_test.

#include "../cpp/batch_inv.hpp"
#include "../cpp/field.hpp"

#include <cassert>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>

namespace lc = kinet::crypto::secp256k1;

static int g_failures = 0;

#define ASSERT_TRUE(name, cond) do { \
    if (!(cond)) { std::fprintf(stderr, "FAIL %s\n", name); ++g_failures; } \
    else        { std::fprintf(stdout, "PASS %s\n", name); } \
} while (0)

static lc::U256 lcg(uint64_t& s) {
    lc::U256 r;
    for (int i = 0; i < 4; ++i) {
        s = s * 6364136223846793005ULL + 1442695040888963407ULL;
        r.limbs[i] = s;
    }
    return r;
}

static lc::U256 reduce_mod(lc::U256 x, const lc::U256& m) {
    while (lc::U256::cmp(x, m) >= 0) {
        uint64_t bw;
        x = lc::sub_256(x, m, bw);
    }
    return x;
}

static bool fp_one_check(const lc::U256& a_mont, const lc::U256& b_mont) {
    // Verify a*b == 1 (in Mont form: a*b*R^-1 == R, i.e. fp_mul(a,b) == ONE_MONT).
    lc::U256 prod = lc::fp_mul(a_mont, b_mont);
    lc::U256 one_mont = lc::to_mont_p(lc::U256{1, 0, 0, 0});
    return lc::U256::cmp(prod, one_mont) == 0;
}

static bool fn_one_check(const lc::U256& a_mont, const lc::U256& b_mont) {
    lc::U256 prod = lc::fn_mul(a_mont, b_mont);
    lc::U256 one_mont = lc::to_mont_n(lc::U256{1, 0, 0, 0});
    return lc::U256::cmp(prod, one_mont) == 0;
}

static void run_size_fp(size_t n) {
    uint64_t s = 0xC0FFEE0BADBEEFULL ^ (uint64_t)n;
    std::vector<lc::U256> in_v(n), out_v(n), ref_v(n);
    for (size_t i = 0; i < n; ++i) {
        // Pull random plain values, reduce mod p, ensure non-zero, encode Mont.
        lc::U256 plain = reduce_mod(lcg(s), lc::P);
        if (plain.is_zero()) plain = lc::U256{1, 0, 0, 0};
        in_v[i] = lc::to_mont_p(plain);
        ref_v[i] = lc::fp_inv(in_v[i]);
    }
    lc::batch_inv_fp(n, in_v.data(), out_v.data(), nullptr);

    int eq = 0, one_ok = 0;
    for (size_t i = 0; i < n; ++i) {
        if (lc::U256::cmp(out_v[i], ref_v[i]) == 0) ++eq;
        if (fp_one_check(in_v[i], out_v[i])) ++one_ok;
    }
    char buf[128];
    std::snprintf(buf, sizeof(buf), "fp batch_inv n=%zu equals fp_inv (%d/%zu)", n, eq, n);
    ASSERT_TRUE(buf, eq == (int)n);
    std::snprintf(buf, sizeof(buf), "fp batch_inv n=%zu out*in == 1 (%d/%zu)", n, one_ok, n);
    ASSERT_TRUE(buf, one_ok == (int)n);
}

static void run_size_fn(size_t n) {
    uint64_t s = 0xDEADC0DECAFEBABEULL ^ ((uint64_t)n << 7);
    std::vector<lc::U256> in_v(n), out_v(n), ref_v(n);
    for (size_t i = 0; i < n; ++i) {
        lc::U256 plain = reduce_mod(lcg(s), lc::N);
        if (plain.is_zero()) plain = lc::U256{1, 0, 0, 0};
        in_v[i] = lc::to_mont_n(plain);
        ref_v[i] = lc::fn_inv(in_v[i]);
    }
    lc::batch_inv_fn(n, in_v.data(), out_v.data(), nullptr);

    int eq = 0, one_ok = 0;
    for (size_t i = 0; i < n; ++i) {
        if (lc::U256::cmp(out_v[i], ref_v[i]) == 0) ++eq;
        if (fn_one_check(in_v[i], out_v[i])) ++one_ok;
    }
    char buf[128];
    std::snprintf(buf, sizeof(buf), "fn batch_inv n=%zu equals fn_inv (%d/%zu)", n, eq, n);
    ASSERT_TRUE(buf, eq == (int)n);
    std::snprintf(buf, sizeof(buf), "fn batch_inv n=%zu out*in == 1 (%d/%zu)", n, one_ok, n);
    ASSERT_TRUE(buf, one_ok == (int)n);
}

// Zero-element handling: insert one zero at position 7 in a batch of 16.
static void test_zero_handling() {
    const size_t n = 16;
    std::vector<lc::U256> in_v(n), out_v(n);
    std::vector<uint8_t> mask(2, 0);
    uint64_t s = 0x1234ULL;
    for (size_t i = 0; i < n; ++i) {
        if (i == 7) { in_v[i] = lc::U256{}; continue; }
        lc::U256 plain = reduce_mod(lcg(s), lc::P);
        if (plain.is_zero()) plain = lc::U256{1, 0, 0, 0};
        in_v[i] = lc::to_mont_p(plain);
    }
    lc::batch_inv_fp(n, in_v.data(), out_v.data(), mask.data());

    bool zero_at_7 = (mask[0] & (1u << 7)) != 0;
    ASSERT_TRUE("zero handling: mask bit 7 set", zero_at_7);
    ASSERT_TRUE("zero handling: out[7] is zero", out_v[7].is_zero());

    int one_ok = 0, total = 0;
    for (size_t i = 0; i < n; ++i) {
        if (i == 7) continue;
        ++total;
        if (fp_one_check(in_v[i], out_v[i])) ++one_ok;
    }
    char buf[128];
    std::snprintf(buf, sizeof(buf), "zero handling: live entries inverted (%d/%d)", one_ok, total);
    ASSERT_TRUE(buf, one_ok == total);
}

int main() {
    std::fprintf(stdout, "=== kinet_crypto secp256k1 batch_inv test suite ===\n");
    run_size_fp(16);
    run_size_fp(256);
    run_size_fp(4096);
    run_size_fn(16);
    run_size_fn(256);
    run_size_fn(4096);
    test_zero_handling();
    std::fprintf(stdout, "=== %s (%d failure%s) ===\n",
                 g_failures == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED",
                 g_failures, g_failures == 1 ? "" : "s");
    return g_failures == 0 ? 0 : 1;
}
