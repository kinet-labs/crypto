// ML-DSA Metal kernel tests.
//
// This harness asserts honest cryptographic properties of the kernels at
// mldsa/gpu/metal/mldsa_batch.metal:
//
//   1. NOTIMPL kernel: mldsa_batch_verify writes the C-ABI sentinel byte
//      0xFB (= (uint8_t)(-5) = CRYPTO_ERR_NOTIMPL) for every input. This
//      replaces the previous "deferred code 2" fraud where the test
//      asserted dispatch shape only and the kernel was silent on real
//      verify correctness.
//
//   2. SHAKE128 / SHAKE256 (FIPS 202) byte-equal NIST KAT. These are
//      cryptographically real Metal kernels — the building blocks of
//      ML-DSA's ExpandA / ExpandMask / SampleInBall / etc. The full
//      FIPS-204 verify pipeline is not yet wired; the SHAKE primitives
//      are landed correctly so future work composes them into a verify
//      kernel without revisiting the hash core.
//
// Tests skip silently when CRYPTO_MLDSA_METALLIB is unset (non-Apple
// builds, CI without Metal).

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#if __APPLE__
extern "C" int mldsa_batch_verify_metal(
    const uint8_t* pubkeys,
    const uint8_t* messages,
    const uint8_t* signatures,
    size_t         n,
    uint8_t*       results,
    const char*    metallib_path);

extern "C" int mldsa_shake128_metal(
    const uint8_t* inputs,
    const uint32_t* input_offsets,
    const uint32_t* input_lens,
    const uint32_t* output_lens,
    size_t          n,
    uint8_t*        outputs,
    const char*     metallib_path);

extern "C" int mldsa_shake256_metal(
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

// =============================================================================
// FIPS 202 NIST KAT vectors for SHAKE128 / SHAKE256.
// All values are canonical output prefixes published by NIST and confirmed
// independently across multiple reference implementations
// (xkcp/keccak, golang.org/x/crypto/sha3, openssl).
// =============================================================================

struct ShakeKat {
    const char* name;
    const uint8_t* input;
    size_t input_len;
    size_t output_len;
    const char* expected_prefix_hex;   // first output_len bytes
};

#if __APPLE__

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

static void test_shake128(const char* metallib) {
    constexpr size_t N = sizeof(SHAKE128_KATS) / sizeof(SHAKE128_KATS[0]);

    // Pack inputs: total_in_len = sum of input_lens.
    size_t total_in = 0, total_out = 0;
    for (size_t i = 0; i < N; ++i) {
        total_in += SHAKE128_KATS[i].input_len;
        total_out += SHAKE128_KATS[i].output_len;
    }

    std::vector<uint8_t>  inputs(total_in == 0 ? 1 : total_in);
    std::vector<uint8_t>  outputs(total_out, 0xCC);
    std::vector<uint32_t> in_offs(N), in_lens(N), out_lens(N);

    size_t off = 0;
    for (size_t i = 0; i < N; ++i) {
        in_offs[i] = (uint32_t)off;
        in_lens[i] = (uint32_t)SHAKE128_KATS[i].input_len;
        out_lens[i] = (uint32_t)SHAKE128_KATS[i].output_len;
        if (SHAKE128_KATS[i].input_len > 0) {
            std::memcpy(inputs.data() + off,
                        SHAKE128_KATS[i].input,
                        SHAKE128_KATS[i].input_len);
        }
        off += SHAKE128_KATS[i].input_len;
    }

    int rc = mldsa_shake128_metal(
        inputs.data(), in_offs.data(), in_lens.data(),
        out_lens.data(), N, outputs.data(), metallib);
    if (rc != 0) {
        std::fprintf(stderr, "FAIL shake128 dispatch rc=%d\n", rc);
        ++g_failures;
        return;
    }

    size_t out_off = 0;
    for (size_t i = 0; i < N; ++i) {
        expect_hex(SHAKE128_KATS[i].name,
                   outputs.data() + out_off,
                   SHAKE128_KATS[i].output_len,
                   SHAKE128_KATS[i].expected_prefix_hex);
        out_off += SHAKE128_KATS[i].output_len;
    }
}

static void test_shake256(const char* metallib) {
    constexpr size_t N = sizeof(SHAKE256_KATS) / sizeof(SHAKE256_KATS[0]);

    size_t total_in = 0, total_out = 0;
    for (size_t i = 0; i < N; ++i) {
        total_in += SHAKE256_KATS[i].input_len;
        total_out += SHAKE256_KATS[i].output_len;
    }

    std::vector<uint8_t>  inputs(total_in == 0 ? 1 : total_in);
    std::vector<uint8_t>  outputs(total_out, 0xCC);
    std::vector<uint32_t> in_offs(N), in_lens(N), out_lens(N);

    size_t off = 0;
    for (size_t i = 0; i < N; ++i) {
        in_offs[i] = (uint32_t)off;
        in_lens[i] = (uint32_t)SHAKE256_KATS[i].input_len;
        out_lens[i] = (uint32_t)SHAKE256_KATS[i].output_len;
        if (SHAKE256_KATS[i].input_len > 0) {
            std::memcpy(inputs.data() + off,
                        SHAKE256_KATS[i].input,
                        SHAKE256_KATS[i].input_len);
        }
        off += SHAKE256_KATS[i].input_len;
    }

    int rc = mldsa_shake256_metal(
        inputs.data(), in_offs.data(), in_lens.data(),
        out_lens.data(), N, outputs.data(), metallib);
    if (rc != 0) {
        std::fprintf(stderr, "FAIL shake256 dispatch rc=%d\n", rc);
        ++g_failures;
        return;
    }

    size_t out_off = 0;
    for (size_t i = 0; i < N; ++i) {
        expect_hex(SHAKE256_KATS[i].name,
                   outputs.data() + out_off,
                   SHAKE256_KATS[i].output_len,
                   SHAKE256_KATS[i].expected_prefix_hex);
        out_off += SHAKE256_KATS[i].output_len;
    }
}

static void test_verify_notimpl(const char* metallib) {
    // The full FIPS-204 verify is not yet wired in Metal. The kernel
    // returns the C-ABI sentinel CRYPTO_ERR_NOTIMPL = -5 which surfaces
    // as 0xFB per result byte. This is honest: the previous skeleton
    // emitted "code 2 deferred" and asserted that — pretending to verify
    // when no verify happened.
    constexpr size_t N         = 100;
    constexpr size_t PK_SIZE   = 1952;
    constexpr size_t SIG_SIZE  = 3320;
    constexpr size_t MSG_SIZE  = 64;

    std::vector<uint8_t> pubkeys(N * PK_SIZE, 0xA5);
    std::vector<uint8_t> messages(N * MSG_SIZE, 0x5A);
    std::vector<uint8_t> signatures(N * SIG_SIZE, 0x3C);
    std::vector<uint8_t> results(N, 0x00);

    int rc = mldsa_batch_verify_metal(pubkeys.data(), messages.data(),
                                      signatures.data(), N,
                                      results.data(), metallib);
    if (rc != 0) {
        std::fprintf(stderr, "FAIL verify dispatch rc=%d\n", rc);
        ++g_failures;
        return;
    }

    int notimpl_count = 0;
    for (size_t i = 0; i < N; ++i) if (results[i] == 0xFBu) ++notimpl_count;
    if (notimpl_count == (int)N) {
        std::fprintf(stdout, "PASS verify NOTIMPL emit %d/%zu\n",
                     notimpl_count, N);
    } else {
        std::fprintf(stderr, "FAIL verify NOTIMPL emit ok=%d/%zu\n",
                     notimpl_count, N);
        ++g_failures;
    }
}

#endif  // __APPLE__

int main() {
    std::fprintf(stdout, "=== mldsa Metal test suite ===\n");

#if __APPLE__
    const char* metallib = std::getenv("CRYPTO_MLDSA_METALLIB");
    if (!metallib) {
        std::fprintf(stdout,
                     "(skip: CRYPTO_MLDSA_METALLIB unset)\n"
                     "=== ALL TESTS PASSED (GPU skipped) ===\n");
        return 0;
    }

    std::fprintf(stdout, "-- SHAKE128 (FIPS 202 NIST KAT) --\n");
    test_shake128(metallib);

    std::fprintf(stdout, "-- SHAKE256 (FIPS 202 NIST KAT) --\n");
    test_shake256(metallib);

    std::fprintf(stdout, "-- Full FIPS-204 verify (NOTIMPL sentinel) --\n");
    test_verify_notimpl(metallib);
#else
    std::fprintf(stdout, "(non-Apple host: GPU dispatch skipped)\n");
#endif

    std::fprintf(stdout, "=== %s (%d failure%s) ===\n",
                 g_failures == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED",
                 g_failures, g_failures == 1 ? "" : "s");
    return g_failures == 0 ? 0 : 1;
}
