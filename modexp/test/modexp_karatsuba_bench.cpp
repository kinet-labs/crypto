// =============================================================================
// modexp_karatsuba_bench - mul-only and end-to-end modexp microbenchmarks.
//
// Reports:
//   * Schoolbook vs Karatsuba multiply timing at 1024/2048/4096 bits.
//   * modexp() vs modexp_karatsuba() end-to-end timing at the same sizes
//     with RSA public-exponent e=65537.
//
// Output is human-readable, single-process, no thread-pool dependencies.
// =============================================================================

#include "crypto.h"
#include "../cpp/karatsuba.hpp"

#include <intx/intx.hpp>

#include <array>
#include <chrono>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <random>
#include <vector>

namespace
{
using clk = std::chrono::steady_clock;

double seconds(clk::time_point a, clk::time_point b)
{
    return std::chrono::duration<double>(b - a).count();
}

std::mt19937_64 prng(0x900DC0FFEEULL);

void fill_random(uint64_t* limbs, size_t n) noexcept
{
    for (size_t i = 0; i < n; ++i)
        limbs[i] = prng();
}

// Plain schoolbook full-product multiply for the bench oracle. Identical to
// the routine used internally by modexp.cpp's mul_schoolbook (extracted here
// to keep the bench self-contained).
void schoolbook(std::span<uint64_t> r,
                std::span<const uint64_t> x,
                std::span<const uint64_t> y) noexcept
{
    std::fill(r.begin(), r.end(), uint64_t{0});
    for (size_t j = 0; j < y.size(); ++j)
    {
        uint64_t carry = 0;
        for (size_t i = 0; i < x.size(); ++i)
        {
            const auto t = intx::umul(x[i], y[j]) + r[i + j] + carry;
            r[i + j] = t[0];
            carry = t[1];
        }
        r[j + x.size()] = carry;
    }
}

template <unsigned BITS>
void bench_mul(int rounds)
{
    constexpr size_t N = BITS / 64;
    std::vector<uint64_t> a(N), b(N), r(2 * N);
    fill_random(a.data(), N);
    fill_random(b.data(), N);

    // Warmup.
    for (int i = 0; i < 4; ++i)
        schoolbook(r, a, b);

    const auto t0 = clk::now();
    for (int i = 0; i < rounds; ++i)
        schoolbook(r, a, b);
    const auto t1 = clk::now();
    for (int i = 0; i < rounds; ++i)
        cevm::crypto::karatsuba::kmul(r, a, b);
    const auto t2 = clk::now();

    const double sb_us = seconds(t0, t1) / rounds * 1e6;
    const double ka_us = seconds(t1, t2) / rounds * 1e6;
    std::printf("  mul %4u-bit  schoolbook=%9.2f us  karatsuba=%9.2f us  speedup=%.2fx\n",
                BITS, sb_us, ka_us, sb_us / ka_us);
}

template <unsigned BITS>
intx::uint<BITS> make_odd_modulus()
{
    constexpr size_t N = BITS / 64;
    intx::uint<BITS> m;
    for (size_t i = 0; i < N; ++i)
        m[i] = prng();
    m[0] |= 1ULL;
    m[N - 1] |= (1ULL << 63);
    return m;
}

template <unsigned BITS>
std::vector<uint8_t> to_be_bytes(const intx::uint<BITS>& x)
{
    constexpr size_t BYTES = BITS / 8;
    std::vector<uint8_t> out(BYTES, 0);
    intx::be::unsafe::store(out.data(), x);
    return out;
}

template <unsigned BITS>
void bench_modexp(int rounds)
{
    constexpr size_t BYTES = BITS / 8;

    intx::uint<BITS> base;
    for (size_t i = 0; i < BITS / 64; ++i)
        base[i] = prng();
    const auto modulus = make_odd_modulus<BITS>();
    const auto base_bytes = to_be_bytes<BITS>(base);
    const auto mod_bytes = to_be_bytes<BITS>(modulus);
    const uint8_t e_bytes[3] = {0x01, 0x00, 0x01};
    std::vector<uint8_t> out(BYTES);

    // Warmup.
    for (int i = 0; i < 2; ++i)
        modexp(base_bytes.data(), BYTES, e_bytes, 3, mod_bytes.data(), BYTES, out.data());

    const auto t0 = clk::now();
    for (int i = 0; i < rounds; ++i)
        modexp(base_bytes.data(), BYTES, e_bytes, 3, mod_bytes.data(), BYTES, out.data());
    const auto t1 = clk::now();
    for (int i = 0; i < rounds; ++i)
        modexp_karatsuba(base_bytes.data(), BYTES, e_bytes, 3, mod_bytes.data(), BYTES, out.data());
    const auto t2 = clk::now();

    const double base_ms = seconds(t0, t1) / rounds * 1e3;
    const double kara_ms = seconds(t1, t2) / rounds * 1e3;
    std::printf("  modexp %4u-bit  CIOS=%8.3f ms  Karatsuba-SOS=%8.3f ms  speedup=%.2fx\n",
                BITS, base_ms, kara_ms, base_ms / kara_ms);
}

}  // namespace

int main()
{
    std::printf("modexp_karatsuba bench (single-thread, deterministic)\n");
    std::printf("Mul-only (full product, no reduction):\n");
    bench_mul<1024>(2000);
    bench_mul<2048>(800);
    bench_mul<4096>(300);

    std::printf("End-to-end modexp (RSA e=65537):\n");
    bench_modexp<1024>(20);
    bench_modexp<2048>(8);
    bench_modexp<4096>(3);
    return 0;
}
