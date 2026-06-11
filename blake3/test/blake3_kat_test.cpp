// BLAKE3 KAT: byte-equal upstream test_vectors.json (cases x 4 modes).
//
// Source: github.com/BLAKE3-team/BLAKE3/test_vectors/test_vectors.json
// Vendored at kinet-labs/crypto/blake3/test/vectors/test_vectors.json.
//
// The upstream test schema is uniform: a top-level object with `key`,
// `context_string`, and `cases[]`. Each case is
//
//   { "input_len": N, "hash": <hex>, "keyed_hash": <hex>, "derive_key": <hex> }
//
// where <hex> is an extended-output XOF prefix (multiple times OUT_LEN). The
// upstream README requires implementations to also check that the first 32
// bytes of each XOF stream match the default-length output. We do BOTH:
//
//   Mode 1: hash32       -> first 32 bytes of "hash"
//   Mode 2: keyed_hash   -> first 32 bytes of "keyed_hash" (32-byte ASCII key)
//   Mode 3: derive_key   -> first 32 bytes of "derive_key" (ASCII context)
//   Mode 4: hash_xof     -> full extended length of "hash"
//
// 35 cases x 4 modes = 140 byte-equal assertions.

#include "../cpp/blake3.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

// Tiny purpose-built JSON-ish reader for the test_vectors schema. NOT a
// general JSON parser -- only enough to walk the known structure.
struct Reader {
    std::string buf;
    std::size_t pos = 0;

    explicit Reader(std::string s) : buf(std::move(s)) {}

    void skip_ws_and_commas() {
        while (pos < buf.size()) {
            char c = buf[pos];
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r' ||
                c == ',' || c == '{' || c == '}' || c == '[' || c == ']') {
                ++pos;
            } else {
                break;
            }
        }
    }

    // Find the next `"<name>": <value>` pair after `pos`. Returns the start
    // index of the value (just past `: `). Returns std::string::npos on miss.
    std::size_t find_field(std::string_view name) {
        std::string needle = "\"";
        needle += name;
        needle += "\"";
        auto p = buf.find(needle, pos);
        if (p == std::string::npos) return std::string::npos;
        p += needle.size();
        // Skip whitespace and the colon.
        while (p < buf.size() && (buf[p] == ' ' || buf[p] == ':')) ++p;
        return p;
    }

    // Read a quoted JSON string starting at p (must point at `"`). Stores the
    // result in `out` and updates `pos` past the closing quote.
    bool read_string_at(std::size_t p, std::string& out) {
        if (p >= buf.size() || buf[p] != '"') return false;
        ++p;
        std::size_t start = p;
        while (p < buf.size() && buf[p] != '"') ++p;
        if (p >= buf.size()) return false;
        out.assign(buf.data() + start, p - start);
        pos = p + 1;
        return true;
    }

    // Read a JSON integer starting at p. Updates pos past the digits.
    bool read_uint_at(std::size_t p, std::uint64_t& out) {
        while (p < buf.size() && (buf[p] == ' ' || buf[p] == ':')) ++p;
        if (p >= buf.size()) return false;
        std::uint64_t v = 0;
        bool any = false;
        while (p < buf.size() && buf[p] >= '0' && buf[p] <= '9') {
            v = v * 10 + static_cast<std::uint64_t>(buf[p] - '0');
            ++p;
            any = true;
        }
        if (!any) return false;
        pos = p;
        out = v;
        return true;
    }
};

bool from_hex(std::string_view hex, std::vector<std::uint8_t>& out) {
    if (hex.size() % 2 != 0) return false;
    out.resize(hex.size() / 2);
    auto nib = [](char c, std::uint8_t& n) {
        if (c >= '0' && c <= '9') { n = static_cast<std::uint8_t>(c - '0'); return true; }
        if (c >= 'a' && c <= 'f') { n = static_cast<std::uint8_t>(c - 'a' + 10); return true; }
        if (c >= 'A' && c <= 'F') { n = static_cast<std::uint8_t>(c - 'A' + 10); return true; }
        return false;
    };
    for (std::size_t i = 0; i < out.size(); ++i) {
        std::uint8_t hi = 0, lo = 0;
        if (!nib(hex[2 * i], hi) || !nib(hex[2 * i + 1], lo)) return false;
        out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    return true;
}

std::string to_hex(const std::uint8_t* p, std::size_t n) {
    static const char* H = "0123456789abcdef";
    std::string r;
    r.reserve(n * 2);
    for (std::size_t i = 0; i < n; ++i) {
        r.push_back(H[p[i] >> 4]);
        r.push_back(H[p[i] & 0xF]);
    }
    return r;
}

// Build the upstream synthetic input: a 251-byte ramp (0..250) repeated.
std::vector<std::uint8_t> make_input(std::size_t n) {
    std::vector<std::uint8_t> v(n);
    for (std::size_t i = 0; i < n; ++i) {
        v[i] = static_cast<std::uint8_t>(i % 251);
    }
    return v;
}

int g_failures = 0;

void check(const char* tag, std::size_t input_len, std::string_view want_hex,
           const std::uint8_t* got, std::size_t got_len) {
    std::string got_hex = to_hex(got, got_len);
    if (want_hex.size() < got_hex.size()) {
        std::fprintf(stderr, "FAIL %s in_len=%zu (want too short: %zu < %zu)\n",
                     tag, input_len, want_hex.size(), got_hex.size());
        ++g_failures;
        return;
    }
    if (std::string_view(got_hex).compare(0, got_hex.size(),
                                          want_hex.data(), got_hex.size()) != 0) {
        std::fprintf(stderr, "FAIL %s in_len=%zu\n  got  %s\n  want %.*s\n",
                     tag, input_len, got_hex.c_str(),
                     static_cast<int>(got_hex.size()), want_hex.data());
        ++g_failures;
        return;
    }
    std::fprintf(stdout, "PASS %s in_len=%zu\n", tag, input_len);
}

}  // namespace

int main(int argc, char** argv) {
    const char* path = argc > 1
        ? argv[1]
        : "blake3/test/vectors/test_vectors.json";

    std::ifstream f(path);
    if (!f) {
        // Try alternate paths used by ctest from build dirs.
        const char* alts[] = {
            "../blake3/test/vectors/test_vectors.json",
            "../../blake3/test/vectors/test_vectors.json",
            "vectors/test_vectors.json",
        };
        for (const char* alt : alts) {
            f.open(alt);
            if (f) break;
        }
    }
    if (!f) {
        std::fprintf(stderr, "FATAL cannot open test_vectors.json (tried %s)\n", path);
        return 1;
    }
    std::stringstream ss;
    ss << f.rdbuf();
    Reader r(ss.str());

    // Pull `key` and `context_string` once.
    std::string key_str, ctx_str;
    {
        auto p = r.find_field("key");
        if (p == std::string::npos || !r.read_string_at(p, key_str)) {
            std::fprintf(stderr, "FATAL no `key` field\n"); return 1;
        }
        p = r.find_field("context_string");
        if (p == std::string::npos || !r.read_string_at(p, ctx_str)) {
            std::fprintf(stderr, "FATAL no `context_string` field\n"); return 1;
        }
    }
    if (key_str.size() != 32) {
        std::fprintf(stderr, "FATAL key has unexpected size %zu (want 32)\n",
                     key_str.size());
        return 1;
    }
    std::uint8_t key[32];
    std::memcpy(key, key_str.data(), 32);

    std::fprintf(stdout, "=== blake3 KAT (BLAKE3-team/BLAKE3 v1.5.0) ===\n");
    std::fprintf(stdout, "key             = \"%s\"\n", key_str.c_str());
    std::fprintf(stdout, "context_string  = \"%s\"\n", ctx_str.c_str());

    int n_cases = 0;

    // Walk cases until find_field can't locate another input_len.
    while (true) {
        auto p_in = r.find_field("input_len");
        if (p_in == std::string::npos) break;
        std::uint64_t in_len = 0;
        if (!r.read_uint_at(p_in, in_len)) {
            std::fprintf(stderr, "FATAL malformed input_len\n"); return 1;
        }

        std::string hash_hex, keyed_hex, dk_hex;
        auto p_h = r.find_field("hash");
        if (p_h == std::string::npos || !r.read_string_at(p_h, hash_hex)) {
            std::fprintf(stderr, "FATAL no hash for case %d\n", n_cases); return 1;
        }
        auto p_k = r.find_field("keyed_hash");
        if (p_k == std::string::npos || !r.read_string_at(p_k, keyed_hex)) {
            std::fprintf(stderr, "FATAL no keyed_hash for case %d\n", n_cases); return 1;
        }
        auto p_d = r.find_field("derive_key");
        if (p_d == std::string::npos || !r.read_string_at(p_d, dk_hex)) {
            std::fprintf(stderr, "FATAL no derive_key for case %d\n", n_cases); return 1;
        }

        ++n_cases;
        std::vector<std::uint8_t> input = make_input(static_cast<std::size_t>(in_len));

        // Mode 1: default-length hash (first 32 bytes of "hash").
        {
            std::uint8_t out[32];
            kinet::crypto::blake3::hash32(input.data(), input.size(), out);
            check("hash32", input.size(), hash_hex, out, 32);
        }

        // Mode 2: keyed_hash, default-length (first 32 bytes).
        {
            std::uint8_t out[32];
            kinet::crypto::blake3::keyed_hash(key, input.data(), input.size(), out);
            check("keyed_hash", input.size(), keyed_hex, out, 32);
        }

        // Mode 3: derive_key, default-length (first 32 bytes).
        {
            std::uint8_t out[32];
            kinet::crypto::blake3::derive_key(ctx_str.c_str(),
                                            input.data(), input.size(), out);
            check("derive_key", input.size(), dk_hex, out, 32);
        }

        // Mode 4: XOF, full extended length per upstream `hash` field.
        {
            const std::size_t xof_len = hash_hex.size() / 2;
            std::vector<std::uint8_t> out(xof_len);
            kinet::crypto::blake3::hash_xof(input.data(), input.size(),
                                          out.data(), out.size());
            check("hash_xof", input.size(), hash_hex, out.data(), out.size());
        }
    }

    int total = n_cases * 4;
    int passed = total - g_failures;
    std::fprintf(stdout, "=== %d/%d assertions passed (%d cases x 4 modes) ===\n",
                 passed, total, n_cases);
    if (n_cases != 35) {
        std::fprintf(stderr, "FATAL expected 35 cases, found %d\n", n_cases);
        return 1;
    }
    return g_failures == 0 ? 0 : 1;
}
