// Poseidon2-BN254 KAT (CPU). Reads poseidon2_t2_kat.json (generated from
// gnark-crypto v0.20.1 with default parameters t=2, rF=6, rP=50, d=5) and
// asserts byte-equality of the t=2 permutation across all KAT cases.

#include "../cpp/poseidon.hpp"
#include "../cpp/fr_bn254.hpp"

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

static int find_int(const std::string& s, const std::string& key, size_t from) {
    std::string needle = "\"" + key + "\"";
    auto k = s.find(needle, from);
    if (k == std::string::npos) return -1;
    auto colon = s.find(':', k);
    auto end = s.find_first_of(",}", colon + 1);
    return std::atoi(s.substr(colon + 1, end - colon - 1).c_str());
}

// Parse all hex strings inside the array starting at `from`. Returns the
// closing-bracket position via `end_out`.
static std::vector<std::string> parse_string_array(const std::string& s,
                                                    size_t from,
                                                    size_t& end_out) {
    std::vector<std::string> out;
    auto open = s.find('[', from);
    auto close = s.find(']', open);
    end_out = close;
    size_t pos = open + 1;
    while (pos < close) {
        auto q1 = s.find('"', pos);
        if (q1 == std::string::npos || q1 > close) break;
        auto q2 = s.find('"', q1 + 1);
        if (q2 == std::string::npos || q2 > close) break;
        out.push_back(s.substr(q1 + 1, q2 - q1 - 1));
        pos = q2 + 1;
    }
    return out;
}

struct KATCase {
    std::vector<std::string> input_hex;
    std::vector<std::string> output_hex;
};

static std::vector<KATCase> parse_kat(const std::string& s) {
    std::vector<KATCase> out;
    auto kat = s.find("\"kat\"");
    if (kat == std::string::npos) return out;
    auto open = s.find('[', kat);
    if (open == std::string::npos) return out;
    size_t pos = open + 1;
    while (pos < s.size()) {
        auto obj_open = s.find('{', pos);
        auto end_arr = s.find(']', pos);
        if (obj_open == std::string::npos ||
            (end_arr != std::string::npos && end_arr < obj_open)) break;
        auto obj_close = s.find('}', obj_open);
        if (obj_close == std::string::npos) break;
        KATCase c;
        size_t end_in;
        auto in_pos = s.find("\"input_hex\"", obj_open);
        c.input_hex = parse_string_array(s, in_pos, end_in);
        size_t end_out;
        auto out_pos = s.find("\"output_hex\"", obj_open);
        c.output_hex = parse_string_array(s, out_pos, end_out);
        out.push_back(c);
        pos = obj_close + 1;
    }
    return out;
}

static void to_hex(const uint8_t b[32], char out[65]) {
    static const char* H = "0123456789abcdef";
    for (int i = 0; i < 32; ++i) {
        out[i * 2]     = H[b[i] >> 4];
        out[i * 2 + 1] = H[b[i] & 0xF];
    }
    out[64] = '\0';
}

static bool from_hex32(const std::string& s, uint8_t out[32]) {
    const char* p = s.c_str();
    if (s.size() >= 2 && p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
    int len = (int)std::strlen(p);
    if (len > 64) return false;
    int pad = 64 - len;
    std::memset(out, 0, 32);
    auto h = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (int i = 0; i < len; ++i) {
        int v = h(p[i]);
        if (v < 0) return false;
        int dst = (pad + i) / 2;
        if ((pad + i) % 2 == 0) out[dst] = uint8_t(v << 4);
        else out[dst] |= uint8_t(v);
    }
    return true;
}

int main() {
    std::fprintf(stdout, "=== poseidon2-bn254 KAT (gnark-crypto compatible) ===\n");

    const char* env = std::getenv("CRYPTO_POSEIDON_VECTORS");
    std::string path = env ? env :
        "poseidon/test/vectors/poseidon2_t2_kat.json";
    std::string raw = slurp(path);

    int width = find_int(raw, "width", 0);
    int rf    = find_int(raw, "full_rounds", 0);
    int rp    = find_int(raw, "partial_rounds", 0);
    if (width != 2 || rf != 6 || rp != 50) {
        std::fprintf(stderr, "FAIL params w=%d rF=%d rP=%d\n", width, rf, rp);
        return 1;
    }

    std::vector<KATCase> cases = parse_kat(raw);
    if (cases.size() < 10) {
        std::fprintf(stderr, "FAIL only %zu KAT cases (need >= 10)\n",
                     cases.size());
        return 1;
    }
    std::fprintf(stdout, "loaded %zu KAT cases\n", cases.size());

    int eq = 0;
    for (size_t i = 0; i < cases.size(); ++i) {
        const KATCase& c = cases[i];
        if (c.input_hex.size() != 2 || c.output_hex.size() != 2) {
            std::fprintf(stderr, "FAIL case %zu: bad shape\n", i);
            ++g_failures;
            continue;
        }
        uint8_t l[32], r[32];
        if (!from_hex32(c.input_hex[0], l) ||
            !from_hex32(c.input_hex[1], r)) {
            std::fprintf(stderr, "FAIL case %zu: hex decode\n", i);
            ++g_failures;
            continue;
        }
        if (!kinet::crypto::poseidon::permutation_t2(l, r)) {
            std::fprintf(stderr, "FAIL case %zu: permutation rejected input\n", i);
            ++g_failures;
            continue;
        }
        char gl[65], gr[65];
        to_hex(l, gl);
        to_hex(r, gr);

        std::string wl = c.output_hex[0];
        std::string wr = c.output_hex[1];
        if (wl.substr(0, 2) == "0x") wl = wl.substr(2);
        if (wr.substr(0, 2) == "0x") wr = wr.substr(2);
        // Pad to 64 hex.
        while (wl.size() < 64) wl = "0" + wl;
        while (wr.size() < 64) wr = "0" + wr;

        if (gl == wl && gr == wr) {
            ++eq;
        } else {
            std::fprintf(stderr,
                "FAIL case %zu\n  got  (%s, %s)\n  want (%s, %s)\n",
                i, gl, gr, wl.c_str(), wr.c_str());
            ++g_failures;
        }
    }
    std::fprintf(stdout, "PASS Poseidon2 t=2 byte-equal %d/%zu\n",
                 eq, cases.size());

    std::fprintf(stdout, "=== %s (%d failure%s) ===\n",
                 g_failures == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED",
                 g_failures, g_failures == 1 ? "" : "s");
    return g_failures == 0 ? 0 : 1;
}
