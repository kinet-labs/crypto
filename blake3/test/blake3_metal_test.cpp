// BLAKE3 Metal KAT test. Hashes >= 100 inputs across the GPU batch kernel
// and asserts byte-equality directly against the BLAKE3 spec test_vectors.json
// (no CPU oracle indirection — each output is checked against the published
// KAT digest). Skipped silently on non-Apple hosts or when the metallib path
// env var is unset.

#include "../cpp/blake3.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#if __APPLE__
extern "C" int blake3_batch_metal(
    const uint8_t* inputs_arena,
    size_t inputs_arena_len,
    const uint32_t* input_offsets,
    const uint32_t* input_lens,
    size_t n,
    uint8_t* outputs_arena,
    const char* metallib_path);
#endif

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

static std::string find_string(const std::string& s, const std::string& key,
                               size_t from = 0) {
    std::string needle = "\"" + key + "\"";
    auto k = s.find(needle, from);
    if (k == std::string::npos) return {};
    auto colon = s.find(':', k);
    auto q1 = s.find('"', colon);
    auto q2 = s.find('"', q1 + 1);
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

static std::vector<uint8_t> kat_input(size_t n) {
    std::vector<uint8_t> v(n);
    for (size_t i = 0; i < n; ++i) v[i] = uint8_t(i % 251);
    return v;
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

struct Case {
    int input_len;
    std::string hash_hex;
};

static std::vector<Case> parse_cases(const std::string& s) {
    std::vector<Case> out;
    auto k = s.find("\"cases\"");
    auto bracket = s.find('[', k);
    size_t pos = bracket + 1;
    while (pos < s.size()) {
        auto open = s.find('{', pos);
        auto close_bracket = s.find(']', pos);
        if (open == std::string::npos ||
            (close_bracket != std::string::npos && close_bracket < open)) break;
        auto close = s.find('}', open);
        if (close == std::string::npos) break;
        Case c;
        c.input_len = find_int(s, "input_len", open);
        c.hash_hex  = find_string(s, "hash", open);
        out.push_back(c);
        pos = close + 1;
    }
    return out;
}

int main() {
    std::fprintf(stdout, "=== blake3 Metal KAT (BLAKE3 spec) ===\n");

#if __APPLE__
    const char* metallib = std::getenv("CRYPTO_BLAKE3_METALLIB");
    if (!metallib) {
        std::fprintf(stdout, "(skip GPU equality: CRYPTO_BLAKE3_METALLIB unset)\n");
        std::fprintf(stdout, "=== ALL TESTS PASSED (GPU skipped) ===\n");
        return 0;
    }

    const char* kat_path_env = std::getenv("CRYPTO_BLAKE3_VECTORS");
    std::string kat_path = kat_path_env ? kat_path_env :
        "blake3/test/vectors/blake3_test_vectors.json";
    std::string raw = slurp(kat_path);
    std::vector<Case> kat = parse_cases(raw);
    if (kat.size() < 10) {
        std::fprintf(stderr, "FAIL only %zu KAT cases\n", kat.size());
        return 1;
    }

    // Build vector list: include all 35 KAT cases, then duplicate them with
    // varied offsets to reach >= 100 batched inputs (acceptance criterion).
    std::vector<size_t> sizes;
    std::vector<size_t> kat_idx;
    for (size_t i = 0; i < kat.size(); ++i) {
        sizes.push_back(size_t(kat[i].input_len));
        kat_idx.push_back(i);
    }
    // Pad to >= 100 by repeating the first 65 cases (cycling through KAT).
    while (sizes.size() < 100) {
        size_t i = sizes.size() % kat.size();
        sizes.push_back(size_t(kat[i].input_len));
        kat_idx.push_back(i);
    }

    size_t n = sizes.size();
    std::vector<uint32_t> offsets(n), lens(n);
    std::vector<uint8_t> arena;
    for (size_t i = 0; i < n; ++i) {
        offsets[i] = (uint32_t)arena.size();
        lens[i]    = (uint32_t)sizes[i];
        std::vector<uint8_t> in = kat_input(sizes[i]);
        arena.insert(arena.end(), in.begin(), in.end());
    }

    std::vector<uint8_t> gpu_out(n * 32, 0);
    int rc = blake3_batch_metal(arena.data(), arena.size(),
                                offsets.data(), lens.data(),
                                n, gpu_out.data(), metallib);
    if (rc != 0) {
        std::fprintf(stderr, "FAIL Metal dispatch rc=%d\n", rc);
        return 1;
    }
    std::fprintf(stdout, "PASS Metal dispatch rc=0 (%zu inputs)\n", n);

    int eq = 0;
    for (size_t i = 0; i < n; ++i) {
        std::string g = hex(gpu_out.data() + i * 32, 32);
        std::string w = kat[kat_idx[i]].hash_hex.substr(0, 64);
        if (g == w) {
            ++eq;
        } else {
            std::fprintf(stderr,
                "FAIL i=%zu len=%u\n  got  %s\n  want %s\n",
                i, lens[i], g.c_str(), w.c_str());
            ++g_failures;
        }
    }
    if (eq == (int)n) {
        std::fprintf(stdout, "PASS Metal byte-equal KAT %d/%zu\n", eq, n);
    } else {
        std::fprintf(stderr, "FAIL Metal byte-equal KAT %d/%zu\n", eq, n);
    }
#else
    std::fprintf(stdout, "(non-Apple host: GPU KAT skipped)\n");
#endif

    std::fprintf(stdout, "=== %s (%d failure%s) ===\n",
                 g_failures == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED",
                 g_failures, g_failures == 1 ? "" : "s");
    return g_failures == 0 ? 0 : 1;
}
