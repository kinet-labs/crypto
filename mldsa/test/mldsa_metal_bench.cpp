// Dispatch-latency sweep for the ML-DSA Metal verify orchestrator.
//
// The orchestrator currently emits CRYPTO_ERR_NOTIMPL (sentinel byte 0xFB)
// per thread because the full FIPS-204 verify pipeline is not yet wired
// in Metal — see mldsa/gpu/metal/mldsa_batch.metal for the residual.
// What we measure here is therefore the dispatch+probe latency, not the
// full verify time. Useful as a floor for the future full-verify port.
// Median of 10 runs each.

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

#if __APPLE__
extern "C" int mldsa_batch_verify_metal(
    const uint8_t* pubkeys,
    const uint8_t* messages,
    const uint8_t* signatures,
    size_t         n,
    uint8_t*       results,
    const char*    metallib_path);
#endif

static double median(std::vector<double>& v) {
    std::sort(v.begin(), v.end());
    return v[v.size() / 2];
}

int main() {
    std::fprintf(stdout, "=== mldsa Metal dispatch sweep (NOTIMPL orchestrator) ===\n");
#if __APPLE__
    const char* metallib = std::getenv("CRYPTO_MLDSA_METALLIB");
    if (!metallib) {
        std::fprintf(stdout, "(skip: CRYPTO_MLDSA_METALLIB unset)\n");
        return 0;
    }
    constexpr size_t SIZES[] = {1, 16, 64, 256, 1024, 4096};
    constexpr int RUNS = 10;
    std::fprintf(stdout, "%6s %14s\n", "N", "Dispatch_us");
    for (size_t s : SIZES) {
        std::vector<uint8_t> pks(s * 1952, 0xA5);
        std::vector<uint8_t> msgs(s * 64,   0x5A);
        std::vector<uint8_t> sigs(s * 3320, 0x3C);
        std::vector<uint8_t> res(s, 0);
        // warm-up
        mldsa_batch_verify_metal(pks.data(), msgs.data(), sigs.data(),
                                 s, res.data(), metallib);
        std::vector<double> us;
        for (int r = 0; r < RUNS; ++r) {
            auto t0 = std::chrono::steady_clock::now();
            mldsa_batch_verify_metal(pks.data(), msgs.data(), sigs.data(),
                                     s, res.data(), metallib);
            auto t1 = std::chrono::steady_clock::now();
            us.push_back(std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count());
        }
        std::fprintf(stdout, "%6zu %14.0f\n", s, median(us));
    }
    std::fprintf(stdout,
        "\nN_threshold: orchestrator returns NOTIMPL until full FIPS-204 verify\n"
        "(SHAKE-driven ExpandA/Mask/S + SampleInBall + UseHint + range checks)\n"
        "is byte-equal NIST KAT in Metal. SHAKE128/256 primitives ARE landed\n"
        "byte-equal NIST FIPS 202 KAT — see mldsa_metal_test for proof.\n");
#endif
    return 0;
}
