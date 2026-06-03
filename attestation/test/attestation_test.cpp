// Tests for the SEV-SNP, TDX, and NRAS evidence parsers.
//
// Fixtures are synthesized in-test so they are deterministic, version-pinned,
// and don't require checked-in binary blobs. Real hardware reports are out
// of scope for v0.1; the parsers ship before live hardware is on hand.

#include "kinet/crypto/attestation/attestation.h"
#include "kinet/crypto/keccak.h"

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

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

static void check_eq(const char* name, const uint8_t* got, const uint8_t* want, size_t n) {
    if (std::memcmp(got, want, n) == 0) {
        std::fprintf(stdout, "PASS %s\n", name);
    } else {
        std::fprintf(stderr, "FAIL %s\n  got  %s\n  want %s\n",
                     name, hex(got, n).c_str(), hex(want, n).c_str());
        ++g_failures;
    }
}

// Build a synthetic SEV-SNP report: 1184 bytes, version=2, with a known
// 48-byte measurement at offset 0x90.
static std::vector<uint8_t> make_sev_snp_report(uint8_t measurement_seed) {
    std::vector<uint8_t> r(SEV_SNP_REPORT_SIZE, 0);
    // version=2, little-endian
    r[0] = 2; r[1] = 0; r[2] = 0; r[3] = 0;
    // measurement: 48 bytes filled from a deterministic seed
    for (size_t i = 0; i < SEV_SNP_MEASUREMENT_SIZE; ++i) {
        r[SEV_SNP_MEASUREMENT_OFFSET + i] =
            static_cast<uint8_t>((measurement_seed + i) & 0xFF);
    }
    return r;
}

// Build a synthetic TDX TD Quote: header (48) + body (584).
static std::vector<uint8_t> make_tdx_quote(uint8_t mrtd_seed) {
    std::vector<uint8_t> q(TDX_QUOTE_MIN_SIZE, 0);
    // version=4, little-endian uint16
    q[0] = 4; q[1] = 0;
    // MRTD inside the body
    const size_t mrtd_off = TDX_REPORT_BODY_OFFSET + TDX_MRTD_OFFSET_IN_BODY;
    for (size_t i = 0; i < TDX_MRTD_SIZE; ++i) {
        q[mrtd_off + i] = static_cast<uint8_t>((mrtd_seed + i) & 0xFF);
    }
    return q;
}

// Build a synthetic NRAS evidence blob (128 bytes of typed fields).
static std::vector<uint8_t> make_nv_evidence(uint8_t seed) {
    std::vector<uint8_t> e(NV_EVIDENCE_MIN_SIZE, 0);
    for (size_t i = 0; i < NV_EVIDENCE_MIN_SIZE; ++i) {
        e[i] = static_cast<uint8_t>((seed + i) & 0xFF);
    }
    return e;
}

int main() {
    std::fprintf(stdout, "=== attestation_test (parsers) ===\n");

    // -------------------------------------------------------------------
    // 1. SEV-SNP: parse a canned report, verify measurement matches keccak(48 bytes)
    // -------------------------------------------------------------------
    {
        auto r = make_sev_snp_report(0x10);
        uint8_t got[32];
        check_ok("sev_snp.parse_canned",
                 attestation_parse_sev_snp(r.data(), r.size(), got));

        uint8_t expect[32];
        keccak256(r.data() + SEV_SNP_MEASUREMENT_OFFSET,
                  SEV_SNP_MEASUREMENT_SIZE, expect);
        check_eq("sev_snp.measurement_matches", got, expect, 32);
    }

    // SEV-SNP: wrong length rejected
    {
        std::vector<uint8_t> short_r(64, 0);
        uint8_t out[32];
        check_err("sev_snp.length_check",
                  attestation_parse_sev_snp(short_r.data(), short_r.size(), out),
                  ATTESTATION_ERR_LENGTH);
    }

    // SEV-SNP: bad version rejected (treats as malformed evidence)
    {
        auto r = make_sev_snp_report(0x10);
        r[0] = 99;  // invalid version
        uint8_t out[32];
        check_err("sev_snp.bad_version",
                  attestation_parse_sev_snp(r.data(), r.size(), out),
                  ATTESTATION_ERR_VERIFY);
    }

    // SEV-SNP: NULL inputs rejected (don't crash on garbage in)
    {
        uint8_t out[32];
        check_err("sev_snp.null_input",
                  attestation_parse_sev_snp(nullptr, SEV_SNP_REPORT_SIZE, out),
                  ATTESTATION_ERR_INPUT);
    }

    // -------------------------------------------------------------------
    // 2. TDX: parse canned quote, verify MRTD matches expected
    // -------------------------------------------------------------------
    {
        auto q = make_tdx_quote(0x40);
        uint8_t got[32];
        check_ok("tdx.parse_canned",
                 attestation_parse_tdx(q.data(), q.size(), got));

        const size_t mrtd_off = TDX_REPORT_BODY_OFFSET + TDX_MRTD_OFFSET_IN_BODY;
        uint8_t expect[32];
        keccak256(q.data() + mrtd_off, TDX_MRTD_SIZE, expect);
        check_eq("tdx.mrtd_matches", got, expect, 32);
    }

    // TDX: short quote rejected
    {
        std::vector<uint8_t> short_q(48, 0);
        uint8_t out[32];
        check_err("tdx.length_check",
                  attestation_parse_tdx(short_q.data(), short_q.size(), out),
                  ATTESTATION_ERR_LENGTH);
    }

    // -------------------------------------------------------------------
    // 3. NRAS: parse evidence, verify hash
    // -------------------------------------------------------------------
    {
        auto e = make_nv_evidence(0x80);
        uint8_t got[32];
        check_ok("nv.parse_canned",
                 attestation_parse_nv(e.data(), e.size(), got));
        uint8_t expect[32];
        keccak256(e.data(), e.size(), expect);
        check_eq("nv.hash_matches", got, expect, 32);
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
