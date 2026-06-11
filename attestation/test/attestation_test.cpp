// Tests for the SEV-SNP, TDX, and NRAS evidence parsers.
//
// Fixtures are real, vendor-published reference reports loaded from
// attestation/testdata/ at runtime. Each parser's expected output is hard-
// coded as a compile-time constexpr -- the byte values that the parser
// MUST produce for that exact fixture. A drift in either the fixture or
// the parser fails the test.
//
// Provenance + license per fixture: see attestation/testdata/README.md.

#include "kinet/crypto/attestation/attestation.h"
#include "kinet/crypto/keccak.h"

#include <array>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#ifndef ATTESTATION_TESTDATA_DIR
#error "ATTESTATION_TESTDATA_DIR must be set by CMake."
#endif

static int g_failures = 0;

static std::string hex(const uint8_t* b, size_t n) {
    static const char* H = "0123456789abcdef";
    std::string r; r.reserve(n*2);
    for (size_t i = 0; i < n; ++i) {
        r.push_back(H[b[i] >> 4]);
        r.push_back(H[b[i] & 0xF]);
    }
    return r;
}

static std::vector<uint8_t> load_fixture(const char* name) {
    std::string path = std::string(ATTESTATION_TESTDATA_DIR) + "/" + name;
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        std::fprintf(stderr, "FATAL: cannot open fixture %s\n", path.c_str());
        std::exit(2);
    }
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)),
                                 std::istreambuf_iterator<char>());
}

static void check_ok(const char* name, int rc) {
    if (rc == ATTESTATION_OK) {
        std::fprintf(stdout, "PASS %s\n", name);
    } else {
        std::fprintf(stderr, "FAIL %s (rc=%d)\n", name, rc);
        ++g_failures;
    }
}

static void check_err(const char* name, int rc, int expected) {
    if (rc == expected) {
        std::fprintf(stdout, "PASS %s\n", name);
    } else {
        std::fprintf(stderr, "FAIL %s (got rc=%d, expected %d)\n",
                     name, rc, expected);
        ++g_failures;
    }
}

template <size_t N>
static void check_eq(const char* name,
                     const uint8_t* got,
                     const std::array<uint8_t, N>& want) {
    if (std::memcmp(got, want.data(), N) == 0) {
        std::fprintf(stdout, "PASS %s\n", name);
    } else {
        std::fprintf(stderr, "FAIL %s\n  got  %s\n  want %s\n",
                     name, hex(got, N).c_str(), hex(want.data(), N).c_str());
        ++g_failures;
    }
}

static void check_neq32(const char* name, const uint8_t* a, const uint8_t* b) {
    if (std::memcmp(a, b, 32) != 0) {
        std::fprintf(stdout, "PASS %s\n", name);
    } else {
        std::fprintf(stderr, "FAIL %s (unexpected equal)\n", name);
        ++g_failures;
    }
}

// ---------------------------------------------------------------------------
// Expected outputs are compile-time constants. They are the exact 32-byte
// keccak256 (Ethereum padding, delimiter 0x01) of the vendor-published
// measurement bytes inside each fixture. Computed once, embedded here.
// Recompute via the procedure documented in attestation/testdata/README.md.
// ---------------------------------------------------------------------------

// keccak256 of sev_snp_milan_sample.bin[0x90 .. 0x90+48]
static constexpr std::array<uint8_t, 32> kExpectedSevSnpMilanMeasurement = {
    0x10, 0x1a, 0x9c, 0x0a, 0xca, 0x96, 0xe1, 0x81,
    0xb7, 0xcb, 0x05, 0x66, 0x86, 0x00, 0xff, 0xc7,
    0x22, 0x5f, 0x16, 0xc8, 0x2c, 0xde, 0x74, 0xcb,
    0xd1, 0x7e, 0xfc, 0xc4, 0x32, 0x9d, 0x3c, 0x9b,
};

// keccak256 of tdx_sample_quote.bin[48+16 .. 48+16+48]
static constexpr std::array<uint8_t, 32> kExpectedTdxMrtd = {
    0xc9, 0x80, 0xe5, 0x91, 0x63, 0xce, 0x24, 0x4b,
    0xb4, 0xbb, 0x62, 0x11, 0xf4, 0x8c, 0x7b, 0x46,
    0xf8, 0x8a, 0x4f, 0x40, 0x94, 0x3e, 0x84, 0xeb,
    0x99, 0xbd, 0xc4, 0x1e, 0x12, 0x9b, 0xd2, 0x93,
};

// keccak256 of nras_h100_evidence.bin (entire file)
static constexpr std::array<uint8_t, 32> kExpectedNrasH100Hash = {
    0x0d, 0xf7, 0xd9, 0xfc, 0xec, 0xba, 0xdc, 0x11,
    0x57, 0xc9, 0x9b, 0xde, 0xbe, 0x9f, 0x3c, 0x59,
    0xbd, 0x7b, 0xca, 0x37, 0xa1, 0x8a, 0x62, 0xd6,
    0x7f, 0x65, 0x94, 0x4c, 0x84, 0xbe, 0x49, 0x33,
};

int main() {
    std::fprintf(stdout, "=== attestation_test (parsers, vendor fixtures) ===\n");

    // -----------------------------------------------------------------
    // 1. AMD SEV-SNP Milan: real PSP-signed report from virtee/sev
    // -----------------------------------------------------------------
    {
        auto report = load_fixture("sev_snp_milan_sample.bin");
        if (report.size() != SEV_SNP_REPORT_SIZE) {
            std::fprintf(stderr, "FAIL sev_snp.fixture_size (got %zu, want %d)\n",
                         report.size(), SEV_SNP_REPORT_SIZE);
            ++g_failures;
        } else {
            std::fprintf(stdout, "PASS sev_snp.fixture_size\n");
        }

        uint8_t got[32];
        check_ok("sev_snp.parse_milan",
                 attestation_parse_sev_snp(report.data(), report.size(), got));
        check_eq("sev_snp.measurement_matches_expected",
                 got, kExpectedSevSnpMilanMeasurement);

        // Negative test: flip a byte in the measurement region. The output
        // must change. This proves the parser actually reads those bits.
        auto flipped = report;
        flipped[SEV_SNP_MEASUREMENT_OFFSET] ^= 0x01;
        uint8_t flipped_out[32];
        check_ok("sev_snp.parse_flipped",
                 attestation_parse_sev_snp(flipped.data(), flipped.size(),
                                           flipped_out));
        check_neq32("sev_snp.flipped_changes_output",
                    flipped_out, kExpectedSevSnpMilanMeasurement.data());

        // Negative test: flip a byte outside the measurement region. The
        // current parser hashes only the measurement field, so this must
        // NOT change the output (regression guard against a parser that
        // accidentally hashes the whole report).
        auto outside = report;
        outside[SEV_SNP_MEASUREMENT_OFFSET + SEV_SNP_MEASUREMENT_SIZE] ^= 0x01;
        uint8_t outside_out[32];
        check_ok("sev_snp.parse_outside_flip",
                 attestation_parse_sev_snp(outside.data(), outside.size(),
                                           outside_out));
        check_eq("sev_snp.outside_flip_unchanged",
                 outside_out, kExpectedSevSnpMilanMeasurement);
    }

    // SEV-SNP: wrong length rejected
    {
        std::vector<uint8_t> short_r(64, 0);
        uint8_t out[32];
        check_err("sev_snp.length_check",
                  attestation_parse_sev_snp(short_r.data(), short_r.size(), out),
                  ATTESTATION_ERR_LENGTH);
    }

    // SEV-SNP: bad version rejected
    {
        auto report = load_fixture("sev_snp_milan_sample.bin");
        report[0] = 99;  // invalid version
        uint8_t out[32];
        check_err("sev_snp.bad_version",
                  attestation_parse_sev_snp(report.data(), report.size(), out),
                  ATTESTATION_ERR_VERIFY);
    }

    // SEV-SNP: NULL inputs rejected
    {
        uint8_t out[32];
        check_err("sev_snp.null_input",
                  attestation_parse_sev_snp(nullptr, SEV_SNP_REPORT_SIZE, out),
                  ATTESTATION_ERR_INPUT);
    }

    // -----------------------------------------------------------------
    // 2. Intel TDX: real TD Quote v4 from
    //    SGX-TDX-DCAP-QuoteVerificationLibrary
    // -----------------------------------------------------------------
    {
        auto quote = load_fixture("tdx_sample_quote.bin");
        if (quote.size() < TDX_QUOTE_MIN_SIZE) {
            std::fprintf(stderr, "FAIL tdx.fixture_size (got %zu, want >= %d)\n",
                         quote.size(), TDX_QUOTE_MIN_SIZE);
            ++g_failures;
        } else {
            std::fprintf(stdout, "PASS tdx.fixture_size\n");
        }

        uint8_t got[32];
        check_ok("tdx.parse_intel_sample",
                 attestation_parse_tdx(quote.data(), quote.size(), got));
        check_eq("tdx.mrtd_matches_expected", got, kExpectedTdxMrtd);

        // Negative test: byte flip inside MRTD changes output.
        auto flipped = quote;
        const size_t mrtd_off = TDX_REPORT_BODY_OFFSET + TDX_MRTD_OFFSET_IN_BODY;
        flipped[mrtd_off] ^= 0x01;
        uint8_t flipped_out[32];
        check_ok("tdx.parse_flipped",
                 attestation_parse_tdx(flipped.data(), flipped.size(),
                                       flipped_out));
        check_neq32("tdx.flipped_changes_output",
                    flipped_out, kExpectedTdxMrtd.data());

        // Negative test: flip outside MRTD must not change the output.
        auto outside = quote;
        outside[mrtd_off + TDX_MRTD_SIZE] ^= 0x01;
        uint8_t outside_out[32];
        check_ok("tdx.parse_outside_flip",
                 attestation_parse_tdx(outside.data(), outside.size(),
                                       outside_out));
        check_eq("tdx.outside_flip_unchanged", outside_out, kExpectedTdxMrtd);
    }

    // TDX: short quote rejected
    {
        std::vector<uint8_t> short_q(48, 0);
        uint8_t out[32];
        check_err("tdx.length_check",
                  attestation_parse_tdx(short_q.data(), short_q.size(), out),
                  ATTESTATION_ERR_LENGTH);
    }

    // TDX: bad version rejected (current parser accepts 4 and 5)
    {
        auto quote = load_fixture("tdx_sample_quote.bin");
        quote[0] = 7;  // invalid version
        quote[1] = 0;
        uint8_t out[32];
        check_err("tdx.bad_version",
                  attestation_parse_tdx(quote.data(), quote.size(), out),
                  ATTESTATION_ERR_VERIFY);
    }

    // -----------------------------------------------------------------
    // 3. NVIDIA NRAS H100: real Hopper SPDM evidence from nvtrust
    // -----------------------------------------------------------------
    {
        auto evidence = load_fixture("nras_h100_evidence.bin");
        if (evidence.size() < NV_EVIDENCE_MIN_SIZE) {
            std::fprintf(stderr, "FAIL nv.fixture_size (got %zu, want >= %d)\n",
                         evidence.size(), NV_EVIDENCE_MIN_SIZE);
            ++g_failures;
        } else {
            std::fprintf(stdout, "PASS nv.fixture_size\n");
        }

        uint8_t got[32];
        check_ok("nv.parse_h100",
                 attestation_parse_nv(evidence.data(), evidence.size(), got));
        check_eq("nv.hash_matches_expected", got, kExpectedNrasH100Hash);

        // Negative test: any byte flip changes the output (parser hashes
        // the whole blob).
        auto flipped = evidence;
        flipped[37] ^= 0x01;
        uint8_t flipped_out[32];
        check_ok("nv.parse_flipped",
                 attestation_parse_nv(flipped.data(), flipped.size(),
                                      flipped_out));
        check_neq32("nv.flipped_changes_output",
                    flipped_out, kExpectedNrasH100Hash.data());
    }

    // NRAS: too-small evidence rejected
    {
        std::vector<uint8_t> tiny(64, 0);
        uint8_t out[32];
        check_err("nv.length_check",
                  attestation_parse_nv(tiny.data(), tiny.size(), out),
                  ATTESTATION_ERR_LENGTH);
    }

    std::fprintf(stdout, "=== %s (%d failure%s) ===\n",
        g_failures == 0 ? "ALL PARSER TESTS PASSED" : "SOME PARSER TESTS FAILED",
        g_failures, g_failures == 1 ? "" : "s");
    return g_failures == 0 ? 0 : 1;
}
