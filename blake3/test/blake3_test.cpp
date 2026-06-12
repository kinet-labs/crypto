// BLAKE3 KAT test. Reads test_vectors.json from
// blake3/test/vectors/blake3_test_vectors.json (vendored from
// github.com/BLAKE3-team/BLAKE3) and asserts byte-equality against all 35
// official cases across the three modes (hash, keyed_hash, derive_key) and
// the XOF output.
//
// The KAT path may be overridden via the CRYPTO_BLAKE3_VECTORS env var
// (used by CTest fixture).

#include "../cpp/blake3.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

static int g_failures = 0;

static std::string slurp(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        std::fprintf(stderr, "FAIL open %s\n", path.c_str());
        std::exit(1);
    }
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

// Tiny JSON helpers — sufficient for the BLAKE3 test_vectors.json shape.
static std::string find_string(const std::string& s, const std::string& key,
                               size_t from = 0) {
    std::string needle = "\"" + key + "\"";
    auto k = s.find(needle, from);
    if (k == std::string::npos) return {};
    auto colon = s.find(':', k);
    if (colon == std::string::npos) return {};
    auto q1 = s.find('"', colon);
    if (q1 == std::string::npos) return {};
    auto q2 = s.find('"', q1 + 1);
    if (q2 == std::string::npos) return {};
    return s.substr(q1 + 1, q2 - q1 - 1);
}

static int find_int(const std::string& s, const std::string& key, size_t from) {
    std::string needle = "\"" + key + "\"";
    auto k = s.find(needle, from);
    if (k == std::string::npos) return -1;
    auto colon = s.find(':', k);
    auto end = s.find_first_of(",}", colon + 1);
    return std::atoi(s.substr(colon + 1, end - colon - 1).c_str());
}

static uint8_t hexnib(char c) {
    if (c >= '0' && c <= '9') return uint8_t(c - '0');
    if (c >= 'a' && c <= 'f') return uint8_t(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return uint8_t(c - 'A' + 10);
    return 0xFF;
}

static std::vector<uint8_t> unhex(const std::string& s) {
    std::vector<uint8_t> out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i + 1 < s.size(); i += 2) {
        out.push_back(uint8_t((hexnib(s[i]) << 4) | hexnib(s[i + 1])));
    }
    return out;
}

static std::string hex(const uint8_t* b, size_t n) {
    static const char* H = "0123456789abcdef";
    std::string r; r.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        r.push_back(H[b[i] >> 4]);
        r.push_back(H[b[i] & 0xF]);
    }
    return r;
}

// BLAKE3 KAT input: repeating sequence 0..250 of given length.
static std::vector<uint8_t> kat_input(size_t n) {
    std::vector<uint8_t> v(n);
    for (size_t i = 0; i < n; ++i) v[i] = uint8_t(i % 251);
    return v;
}

struct Case {
    int input_len;
    std::string hash_hex;
    std::string keyed_hex;
    std::string derive_hex;
};

static std::vector<Case> parse_cases(const std::string& s) {
    std::vector<Case> out;
    auto k = s.find("\"cases\"");
    if (k == std::string::npos) return out;
    auto bracket = s.find('[', k);
    if (bracket == std::string::npos) return out;
    size_t pos = bracket + 1;
    while (pos < s.size()) {
        auto open = s.find('{', pos);
        auto close_bracket = s.find(']', pos);
        if (open == std::string::npos ||
            (close_bracket != std::string::npos && close_bracket < open)) break;
        auto close = s.find('}', open);
        if (close == std::string::npos) break;
        Case c;
        c.input_len  = find_int(s, "input_len", open);
        c.hash_hex   = find_string(s, "hash", open);
        c.keyed_hex  = find_string(s, "keyed_hash", open);
        c.derive_hex = find_string(s, "derive_key", open);
        out.push_back(c);
        pos = close + 1;
    }
    return out;
}

static void check_eq(const char* name, const uint8_t* got, size_t got_n,
                     const std::string& want_hex) {
    std::string g = hex(got, got_n);
    if (g.size() > want_hex.size()) g = g.substr(0, want_hex.size());
    if (g == want_hex) {
        std::fprintf(stdout, "PASS %s\n", name);
    } else {
        std::fprintf(stderr, "FAIL %s\n  got  %s\n  want %s\n",
                     name, g.c_str(), want_hex.c_str());
        ++g_failures;
    }
}

int main() {
    std::fprintf(stdout, "=== blake3 KAT (BLAKE3 spec, test_vectors.json) ===\n");

    const char* env = std::getenv("CRYPTO_BLAKE3_VECTORS");
    std::string path = env ? env :
        "blake3/test/vectors/blake3_test_vectors.json";
    std::string raw = slurp(path);

    std::string key = find_string(raw, "key");
    std::string ctx = find_string(raw, "context_string");
    if (key.size() != 32) {
        std::fprintf(stderr, "FAIL key length %zu\n", key.size());
        return 1;
    }
    std::vector<Case> cases = parse_cases(raw);
    if (cases.size() < 10) {
        std::fprintf(stderr, "FAIL only %zu cases (need >= 10)\n", cases.size());
        return 1;
    }
    std::fprintf(stdout, "loaded %zu KAT cases\n", cases.size());

    int hash_pass = 0, keyed_pass = 0, derive_pass = 0, xof_pass = 0;

    for (const auto& c : cases) {
        std::vector<uint8_t> in = kat_input(size_t(c.input_len));

        // Mode 1: hash, 32 bytes
        {
            uint8_t out[32];
            kinet::crypto::blake3::hash32(in.data(), in.size(), out);
            std::string g = hex(out, 32);
            std::string w = c.hash_hex.substr(0, 64);
            if (g == w) { ++hash_pass; }
            else {
                std::fprintf(stderr, "FAIL hash[len=%d]\n  got  %s\n  want %s\n",
                             c.input_len, g.c_str(), w.c_str());
                ++g_failures;
            }
        }

        // Mode 2: keyed_hash, 32 bytes
        {
            uint8_t out[32];
            uint8_t k32[32];
            std::memcpy(k32, key.data(), 32);
            kinet::crypto::blake3::keyed_hash(k32, in.data(), in.size(), out, 32);
            std::string g = hex(out, 32);
            std::string w = c.keyed_hex.substr(0, 64);
            if (g == w) { ++keyed_pass; }
            else {
                std::fprintf(stderr, "FAIL keyed[len=%d]\n  got  %s\n  want %s\n",
                             c.input_len, g.c_str(), w.c_str());
                ++g_failures;
            }
        }

        // Mode 3: derive_key, 32 bytes
        {
            uint8_t out[32];
            kinet::crypto::blake3::derive_key(ctx.data(), ctx.size(),
                                            in.data(), in.size(), out, 32);
            std::string g = hex(out, 32);
            std::string w = c.derive_hex.substr(0, 64);
            if (g == w) { ++derive_pass; }
            else {
                std::fprintf(stderr, "FAIL derive[len=%d]\n  got  %s\n  want %s\n",
                             c.input_len, g.c_str(), w.c_str());
                ++g_failures;
            }
        }

        // Mode 4: full XOF (KAT outputs are 131 bytes per mode; check the
        // hash mode XOF here as additional coverage).
        {
            size_t xof_len = c.hash_hex.size() / 2;
            std::vector<uint8_t> out(xof_len);
            kinet::crypto::blake3::hash(in.data(), in.size(),
                                       out.data(), xof_len);
            std::string g = hex(out.data(), xof_len);
            if (g == c.hash_hex) { ++xof_pass; }
            else {
                std::fprintf(stderr, "FAIL xof[len=%d, out=%zu]\n",
                             c.input_len, xof_len);
                ++g_failures;
            }
        }
    }

    std::fprintf(stdout, "PASS hash       %d/%zu\n", hash_pass,   cases.size());
    std::fprintf(stdout, "PASS keyed_hash %d/%zu\n", keyed_pass,  cases.size());
    std::fprintf(stdout, "PASS derive_key %d/%zu\n", derive_pass, cases.size());
    std::fprintf(stdout, "PASS xof        %d/%zu\n", xof_pass,    cases.size());

    std::fprintf(stdout, "=== %s (%d failure%s) ===\n",
                 g_failures == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED",
                 g_failures, g_failures == 1 ? "" : "s");
    return g_failures == 0 ? 0 : 1;
}
