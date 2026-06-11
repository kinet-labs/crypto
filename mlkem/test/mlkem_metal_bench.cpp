// Dispatch-latency sweep for the ML-KEM Metal decap orchestrator.
//
// The orchestrator currently emits CRYPTO_ERR_NOTIMPL (sentinel byte 0xFB)
// per thread because the full FIPS-203 K-PKE.Decrypt + FO re-encrypt pipeline
// is not yet wired in Metal — see mlkem/gpu/metal/mlkem_batch.metal for the
// residual. What we measure here is therefore the dispatch+probe latency,
// not the full decap time. SHAKE128/256 primitives ARE landed byte-equal
// NIST FIPS 202 KAT (see mlkem_metal_test).

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

#if __APPLE__
extern "C" int mlkem_batch_decapsulate_metal(
    const uint8_t* secret_keys,
    const uint8_t* ciphertexts,
    size_t         n,
    uint8_t*       shared_secrets,
    uint8_t*       results,
    const char*    metallib_path);
#endif

static double median(std::vector<double>& v) {
    std::sort(v.begin(), v.end());
    return v[v.size() / 2];
}

int main() {
    std::fprintf(stdout, "=== mlkem Metal dispatch sweep (NOTIMPL orchestrator) ===\n");
#if __APPLE__
    const char* metallib = std::getenv("KINET_CRYPTO_MLKEM_METALLIB");
    if (!metallib) {
        std::fprintf(stdout, "(skip: KINET_CRYPTO_MLKEM_METALLIB unset)\n");
        return 0;
    }
    constexpr size_t SIZES[] = {1, 16, 64, 256, 1024, 4096};
    constexpr int RUNS = 10;
    std::fprintf(stdout, "%6s %14s\n", "N", "Dispatch_us");
    for (size_t s : SIZES) {
        std::vector<uint8_t> sks(s * 2400, 0xC3);
        std::vector<uint8_t> cts(s * 1088, 0x3C);
        std::vector<uint8_t> ss(s * 32,    0);
        std::vector<uint8_t> res(s, 0);
        mlkem_batch_decapsulate_metal(sks.data(), cts.data(),
                                      s, ss.data(), res.data(), metallib);
        std::vector<double> us;
        for (int r = 0; r < RUNS; ++r) {
            auto t0 = std::chrono::steady_clock::now();
            mlkem_batch_decapsulate_metal(sks.data(), cts.data(),
                                          s, ss.data(), res.data(), metallib);
            auto t1 = std::chrono::steady_clock::now();
            us.push_back(std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count());
        }
        std::fprintf(stdout, "%6zu %14.0f\n", s, median(us));
    }
    std::fprintf(stdout,
        "\nN_threshold: orchestrator returns NOTIMPL until full FIPS-203 decap\n"
        "(K-PKE.Decrypt + FO re-encrypt + constant-time compare) is byte-equal\n"
        "NIST KAT in Metal. SHAKE128/256 primitives ARE landed byte-equal\n"
        "NIST FIPS 202 KAT — see mlkem_metal_test for proof.\n");
#endif
    return 0;
}
