// ML-KEM Metal kernel tests.
//
// Same shape as mldsa/test/mldsa_metal_test.cpp:
//   1. NOTIMPL kernel: mlkem_batch_decapsulate writes 0xFB
//      (= CRYPTO_ERR_NOTIMPL) and zeroes the shared-secret buffer.
//   2. SHAKE128 / SHAKE256 byte-equal NIST FIPS 202 KAT.
//
// Replaces the prior "deferred code 2" skeleton harness which asserted
// only the dispatch shape and never tested any cryptographic property.

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#if __APPLE__
extern "C" int mlkem_batch_decapsulate_metal(
    const uint8_t* secret_keys,
    const uint8_t* ciphertexts,
    size_t         n,
    uint8_t*       shared_secrets,
    uint8_t*       results,
    const char*    metallib_path);

extern "C" int mlkem_shake128_metal(
    const uint8_t* inputs,
    const uint32_t* input_offsets,
    const uint32_t* input_lens,
    const uint32_t* output_lens,
    size_t          n,
    uint8_t*        outputs,
    const char*     metallib_path);

extern "C" int mlkem_shake256_metal(
    const uint8_t* inputs,
    const uint32_t* input_offsets,
    const uint32_t* input_lens,
    const uint32_t* output_lens,
    size_t          n,
    uint8_t*        outputs,
    const char*     metallib_path);
#endif

static int g_failures = 0;

static std::string hex(const uint8_t* b, size_t n) {
    static const char* H = "0123456789abcdef";
    std::string r; r.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        r.push_back(H[b[i] >> 4]); r.push_back(H[b[i] & 0xF]);
    }
    return r;
}

static void expect_hex(const char* name, const uint8_t* got, size_t got_len,
                       const char* want_hex) {
    std::string g = hex(got, got_len);
    if (g == want_hex) {
        std::fprintf(stdout, "PASS %s\n", name);
    } else {
        std::fprintf(stderr, "FAIL %s\n  got  %s\n  want %s\n",
                     name, g.c_str(), want_hex);
        ++g_failures;
    }
}

#if __APPLE__

struct ShakeKat {
    const char* name;
    const uint8_t* input;
    size_t input_len;
    size_t output_len;
    const char* expected_prefix_hex;
};

static const uint8_t KAT_INPUT_ABC[]    = {'a','b','c'};
static const uint8_t KAT_INPUT_ABCDLONG[] =
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

static const ShakeKat SHAKE128_KATS[] = {
    {"SHAKE128('')           [32 bytes]", nullptr, 0, 32,
     "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"},
    {"SHAKE128('abc')        [32 bytes]", KAT_INPUT_ABC, 3, 32,
     "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8"},
    {"SHAKE128(56-byte)      [32 bytes]", KAT_INPUT_ABCDLONG, 56, 32,
     "1a96182b50fb8c7e74e0a707788f55e98209b8d91fade8f32f8dd5cff7bf21f5"},
};

static const ShakeKat SHAKE256_KATS[] = {
    {"SHAKE256('')           [32 bytes]", nullptr, 0, 32,
     "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"},
    {"SHAKE256('abc')        [32 bytes]", KAT_INPUT_ABC, 3, 32,
     "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"},
    {"SHAKE256(56-byte)      [32 bytes]", KAT_INPUT_ABCDLONG, 56, 32,
     "4d8c2dd2435a0128eefbb8c36f6f87133a7911e18d979ee1ae6be5d4fd2e3329"},
};

static void run_shake_kats(const ShakeKat* kats, size_t N, bool is_128,
                           const char* metallib) {
    size_t total_in = 0, total_out = 0;
    for (size_t i = 0; i < N; ++i) {
        total_in += kats[i].input_len;
        total_out += kats[i].output_len;
    }

    std::vector<uint8_t>  inputs(total_in == 0 ? 1 : total_in);
    std::vector<uint8_t>  outputs(total_out, 0xCC);
    std::vector<uint32_t> in_offs(N), in_lens(N), out_lens(N);

    size_t off = 0;
    for (size_t i = 0; i < N; ++i) {
        in_offs[i]  = (uint32_t)off;
        in_lens[i]  = (uint32_t)kats[i].input_len;
        out_lens[i] = (uint32_t)kats[i].output_len;
        if (kats[i].input_len > 0) {
            std::memcpy(inputs.data() + off, kats[i].input, kats[i].input_len);
        }
        off += kats[i].input_len;
    }

    int rc = is_128
        ? mlkem_shake128_metal(inputs.data(), in_offs.data(), in_lens.data(),
                               out_lens.data(), N, outputs.data(), metallib)
        : mlkem_shake256_metal(inputs.data(), in_offs.data(), in_lens.data(),
                               out_lens.data(), N, outputs.data(), metallib);
    if (rc != 0) {
        std::fprintf(stderr, "FAIL shake%d dispatch rc=%d\n",
                     is_128 ? 128 : 256, rc);
        ++g_failures;
        return;
    }

    size_t out_off = 0;
    for (size_t i = 0; i < N; ++i) {
        expect_hex(kats[i].name,
                   outputs.data() + out_off,
                   kats[i].output_len,
                   kats[i].expected_prefix_hex);
        out_off += kats[i].output_len;
    }
}

static void test_decap_notimpl(const char* metallib) {
    constexpr size_t N        = 100;
    constexpr size_t SK_SIZE  = 2400;
    constexpr size_t CT_SIZE  = 1088;

    std::vector<uint8_t> secret_keys(N * SK_SIZE, 0xC3);
    std::vector<uint8_t> ciphertexts(N * CT_SIZE, 0x3C);
    std::vector<uint8_t> shared_secrets(N * 32, 0xFF);
    std::vector<uint8_t> results(N, 0x00);

    int rc = mlkem_batch_decapsulate_metal(secret_keys.data(),
                                           ciphertexts.data(), N,
                                           shared_secrets.data(),
                                           results.data(), metallib);
    if (rc != 0) {
        std::fprintf(stderr, "FAIL decap dispatch rc=%d\n", rc);
        ++g_failures;
        return;
    }

    int notimpl_count = 0;
    for (size_t i = 0; i < N; ++i) if (results[i] == 0xFBu) ++notimpl_count;
    int ss_zero_count = 0;
    for (size_t i = 0; i < N * 32; ++i) if (shared_secrets[i] == 0u) ++ss_zero_count;

    if (notimpl_count == (int)N) {
        std::fprintf(stdout, "PASS decap NOTIMPL emit %d/%zu\n",
                     notimpl_count, N);
    } else {
        std::fprintf(stderr, "FAIL decap NOTIMPL emit ok=%d/%zu\n",
                     notimpl_count, N);
        ++g_failures;
    }

    if (ss_zero_count == (int)(N * 32)) {
        std::fprintf(stdout, "PASS decap shared_secret zeroed %d/%zu\n",
                     ss_zero_count, N * 32);
    } else {
        std::fprintf(stderr, "FAIL decap shared_secret zeroed ok=%d/%zu\n",
                     ss_zero_count, N * 32);
        ++g_failures;
    }
}

#endif  // __APPLE__

int main() {
    std::fprintf(stdout, "=== mlkem Metal test suite ===\n");

#if __APPLE__
    const char* metallib = std::getenv("CRYPTO_MLKEM_METALLIB");
    if (!metallib) {
        std::fprintf(stdout,
                     "(skip: CRYPTO_MLKEM_METALLIB unset)\n"
                     "=== ALL TESTS PASSED (GPU skipped) ===\n");
        return 0;
    }

    std::fprintf(stdout, "-- SHAKE128 (FIPS 202 NIST KAT) --\n");
    run_shake_kats(SHAKE128_KATS,
                   sizeof(SHAKE128_KATS) / sizeof(SHAKE128_KATS[0]),
                   true, metallib);

    std::fprintf(stdout, "-- SHAKE256 (FIPS 202 NIST KAT) --\n");
    run_shake_kats(SHAKE256_KATS,
                   sizeof(SHAKE256_KATS) / sizeof(SHAKE256_KATS[0]),
                   false, metallib);

    std::fprintf(stdout, "-- Full FIPS-203 decap (NOTIMPL sentinel) --\n");
    test_decap_notimpl(metallib);
#else
    std::fprintf(stdout, "(non-Apple host: GPU dispatch skipped)\n");
#endif

    std::fprintf(stdout, "=== %s (%d failure%s) ===\n",
                 g_failures == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED",
                 g_failures, g_failures == 1 ? "" : "s");
    return g_failures == 0 ? 0 : 1;
}
