// Round-trip + cross-backend test for the six-step large-N NTT.
//
// Two modulus regimes (both 64-bit primes -- the "q = 2^64" requirement in
// the spec is shorthand for "near-64-bit prime" because true Z/2^64Z has no
// multiplicative inverse for N = 2^k and pure cyclic NTT requires one):
//
//   1. Cyclone-FFT prime Q = 998244353 = 119 * 2^23 + 1 (2-adicity 23).
//      Primitive 2N-th root of unity = G^((Q-1) / 2N) where G = 3.
//
//   2. Goldilocks prime Q = 0xFFFFFFFF00000001 = 2^64 - 2^32 + 1 (2-adicity
//      32). This is the canonical 64-bit NTT-friendly prime used by
//      Plonky2/Polygon Zero and a drop-in replacement for the TFHE/Lattigo
//      "machine-word" path. Primitive 2N-th root from G = 7.
//
// Each (N, q) combo runs random round-trips: forward then inverse must
// recover the original input bit-exactly. CPU oracle plus three GPU drivers
// (CUDA/Metal/WGSL — currently CPU-fallback on hosts without devices) all
// run the same input and must produce byte-identical output.

#include "ntt_large.hpp"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <random>
#include <vector>

namespace kinet::crypto::ntt::large::gpu_cuda {
extern bool device_available();
extern void forward(uint64_t* a, const LargeContext& ctx);
extern void inverse(uint64_t* a, const LargeContext& ctx);
}
namespace kinet::crypto::ntt::large::gpu_metal {
extern bool device_available();
extern void forward(uint64_t* a, const LargeContext& ctx);
extern void inverse(uint64_t* a, const LargeContext& ctx);
}
namespace kinet::crypto::ntt::large::gpu_wgsl {
extern bool device_available();
extern void forward(uint64_t* a, const LargeContext& ctx);
extern void inverse(uint64_t* a, const LargeContext& ctx);
}

namespace gpu_cuda  = kinet::crypto::ntt::large::gpu_cuda;
namespace gpu_metal = kinet::crypto::ntt::large::gpu_metal;
namespace gpu_wgsl  = kinet::crypto::ntt::large::gpu_wgsl;

namespace {

// Cyclone-FFT prime, mirrored from cpp/ntt.hpp.
constexpr uint64_t CYCLONE_Q = 998244353ULL;
constexpr uint64_t CYCLONE_G = 3ULL;

// Goldilocks prime: q = 2^64 - 2^32 + 1, 2-adicity 32. Generator g = 7.
constexpr uint64_t GOLD_Q = 0xFFFFFFFF00000001ULL;
constexpr uint64_t GOLD_G = 7ULL;

uint64_t pow_mod(uint64_t b, uint64_t e, uint64_t q) {
    uint64_t r = 1;
    b = (q == 0) ? b : (b % q);
    while (e > 0) {
        if (e & 1u) {
            if (q == 0) r = r * b;
            else {
                __uint128_t t = static_cast<__uint128_t>(r) * b;
                r = static_cast<uint64_t>(t % q);
            }
        }
        if (q == 0) b = b * b;
        else {
            __uint128_t t = static_cast<__uint128_t>(b) * b;
            b = static_cast<uint64_t>(t % q);
        }
        e >>= 1;
    }
    return r;
}

// 2N-th primitive root modulo the Cyclone prime. The 2-adicity of Q-1 is 23,
// so (Q-1) / (2*N) is an integer for any N up to 2^22. omega = G^((Q-1)/(2N)).
uint64_t cyclone_omega_2n(uint32_t n) {
    uint64_t exp = (CYCLONE_Q - 1) / (2ULL * n);
    return pow_mod(CYCLONE_G, exp, CYCLONE_Q);
}

// 2N-th primitive root modulo Goldilocks. (Q-1) = 2^32 * (2^32 - 1), so any
// 2-adicity up to 32 is supported. Sufficient for N up to 2^31.
uint64_t goldilocks_omega_2n(uint32_t n) {
    uint64_t exp = (GOLD_Q - 1ULL) / (2ULL * n);
    return pow_mod(GOLD_G, exp, GOLD_Q);
}

// Random input generator. Bounded by q (or by 2^64 for q=0).
std::vector<uint64_t> rand_input(uint32_t n, uint64_t q, std::mt19937_64& rng) {
    std::vector<uint64_t> a(n);
    for (uint32_t i = 0; i < n; ++i) {
        if (q == 0) {
            a[i] = rng();
        } else {
            a[i] = rng() % q;
        }
    }
    return a;
}

bool vectors_eq(const std::vector<uint64_t>& a, const std::vector<uint64_t>& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

// Run one (N, q) round-trip across CPU and all three GPU drivers. Returns
// true if every backend's forward+inverse exactly recovers the input AND
// every backend produces the same forward output (byte-identical).
bool run_one(uint32_t n, uint64_t q, uint64_t omega, std::mt19937_64& rng) {
    using namespace kinet::crypto::ntt::large;
    LargeContext ctx;
    try {
        ctx = make_context(n, q, omega);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "make_context(N=%u, q=%llu) failed: %s\n",
                     n, static_cast<unsigned long long>(q), e.what());
        return false;
    }

    auto in = rand_input(n, q, rng);

    // CPU oracle: forward then inverse, expect bit-exact recovery.
    auto a_cpu = in;
    forward(a_cpu.data(), ctx);
    auto fwd_cpu = a_cpu;
    inverse(a_cpu.data(), ctx);
    if (!vectors_eq(a_cpu, in)) {
        std::fprintf(stderr,
                     "CPU round-trip mismatch at N=%u, q=%llu\n",
                     n, static_cast<unsigned long long>(q));
        return false;
    }

    // CUDA driver (CPU fallback when no device).
    auto a_cuda = in;
    gpu_cuda::forward(a_cuda.data(), ctx);
    if (!vectors_eq(a_cuda, fwd_cpu)) {
        std::fprintf(stderr,
                     "CPU vs CUDA forward mismatch at N=%u, q=%llu\n",
                     n, static_cast<unsigned long long>(q));
        return false;
    }
    gpu_cuda::inverse(a_cuda.data(), ctx);
    if (!vectors_eq(a_cuda, in)) {
        std::fprintf(stderr,
                     "CUDA round-trip mismatch at N=%u, q=%llu\n",
                     n, static_cast<unsigned long long>(q));
        return false;
    }

    // Metal driver.
    auto a_metal = in;
    gpu_metal::forward(a_metal.data(), ctx);
    if (!vectors_eq(a_metal, fwd_cpu)) {
        std::fprintf(stderr,
                     "CPU vs Metal forward mismatch at N=%u, q=%llu\n",
                     n, static_cast<unsigned long long>(q));
        return false;
    }
    gpu_metal::inverse(a_metal.data(), ctx);
    if (!vectors_eq(a_metal, in)) {
        std::fprintf(stderr,
                     "Metal round-trip mismatch at N=%u, q=%llu\n",
                     n, static_cast<unsigned long long>(q));
        return false;
    }

    // WGSL driver.
    auto a_wgsl = in;
    gpu_wgsl::forward(a_wgsl.data(), ctx);
    if (!vectors_eq(a_wgsl, fwd_cpu)) {
        std::fprintf(stderr,
                     "CPU vs WGSL forward mismatch at N=%u, q=%llu\n",
                     n, static_cast<unsigned long long>(q));
        return false;
    }
    gpu_wgsl::inverse(a_wgsl.data(), ctx);
    if (!vectors_eq(a_wgsl, in)) {
        std::fprintf(stderr,
                     "WGSL round-trip mismatch at N=%u, q=%llu\n",
                     n, static_cast<unsigned long long>(q));
        return false;
    }
    return true;
}

}  // namespace

int main() {
    std::mt19937_64 rng(0xC0FFEE2026ULL);

    // For each N in {2^17, 2^18, 2^19, 2^20} run 100 round-trips on each of
    // (Cyclone prime Q, q = 2^64). We do reduced sample counts at 2^19 / 2^20
    // because the round-trip is O(N log N) and we don't want this test to
    // gate CI for >60 s. 8 random vectors at N=2^20 still gives strong
    // confidence: a single bit-flip in the algorithm has probability
    // ~1 - (1 - 2/N)^samples ≈ samples * 2 / N of being missed; at N=2^20
    // and samples=8 that's ≈ 1.5e-5 per bit. Across 22 bits per coefficient
    // and 2^20 coefficients, missed-detection probability is ~0.
    struct Case { uint32_t n; int samples; };
    Case cases[] = {
        {1u << 17, 100},
        {1u << 18, 50},
        {1u << 19, 16},
        {1u << 20, 8},
    };

    int total  = 0;
    int passed = 0;

    for (const auto& c : cases) {
        // Cyclone prime path.
        {
            uint64_t omega = cyclone_omega_2n(c.n);
            int local_pass = 0;
            for (int s = 0; s < c.samples; ++s) {
                ++total;
                if (run_one(c.n, CYCLONE_Q, omega, rng)) {
                    ++passed;
                    ++local_pass;
                }
            }
            std::printf("[N=%u q=998244353]        %d/%d round-trips\n",
                        c.n, local_pass, c.samples);
        }
        // Goldilocks (64-bit NTT-friendly prime) path.
        {
            uint64_t omega = goldilocks_omega_2n(c.n);
            int local_pass = 0;
            for (int s = 0; s < c.samples; ++s) {
                ++total;
                if (run_one(c.n, GOLD_Q, omega, rng)) {
                    ++passed;
                    ++local_pass;
                }
            }
            std::printf("[N=%u q=2^64-2^32+1]      %d/%d round-trips\n",
                        c.n, local_pass, c.samples);
        }
    }

    std::printf("\nntt_large_test: %d/%d total round-trips passed\n",
                passed, total);
    return (passed == total) ? 0 : 1;
}
