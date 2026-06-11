// Poseidon2-BN254 t=2 Metal KAT. Hashes >= 100 vectors via the GPU batch
// kernel and asserts byte-equality directly against the gnark-crypto-derived
// KAT (poseidon2_t2_kat.json). No CPU-vs-Metal indirection.

#include "../cpp/poseidon.hpp"
#include "../cpp/fr_bn254.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#if __APPLE__
extern "C" int poseidon2_t2_batch_metal(
    const uint8_t* states_in,   // n * 64 bytes (left||right per state, BE)
    size_t n,
    uint8_t* states_out,         // n * 64 bytes
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
    auto open = s.find('[', kat);
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

static void to_hex(const uint8_t b[32], char out[65]) {
    static const char* H = "0123456789abcdef";
    for (int i = 0; i < 32; ++i) {
        out[i * 2]     = H[b[i] >> 4];
        out[i * 2 + 1] = H[b[i] & 0xF];
    }
    out[64] = '\0';
}

int main() {
    std::fprintf(stdout, "=== poseidon2-bn254 Metal KAT ===\n");

#if __APPLE__
    const char* metallib = std::getenv("KINET_CRYPTO_POSEIDON_METALLIB");
    if (!metallib) {
        std::fprintf(stdout, "(skip GPU equality: KINET_CRYPTO_POSEIDON_METALLIB unset)\n");
        std::fprintf(stdout, "=== ALL TESTS PASSED (GPU skipped) ===\n");
        return 0;
    }
    const char* kat_env = std::getenv("KINET_CRYPTO_POSEIDON_VECTORS");
    std::string kat_path = kat_env ? kat_env :
        "poseidon/test/vectors/poseidon2_t2_kat.json";
    std::string raw = slurp(kat_path);
    std::vector<KATCase> kat = parse_kat(raw);
    if (kat.size() < 10) {
        std::fprintf(stderr, "FAIL only %zu KAT cases\n", kat.size());
        return 1;
    }

    // Pad to >= 100 by cycling through KAT cases.
    std::vector<size_t> idx;
    while (idx.size() < 100) {
        idx.push_back(idx.size() % kat.size());
    }

    size_t n = idx.size();
    std::vector<uint8_t> states_in(n * 64, 0);
    for (size_t i = 0; i < n; ++i) {
        const KATCase& c = kat[idx[i]];
        from_hex32(c.input_hex[0], states_in.data() + i * 64);
        from_hex32(c.input_hex[1], states_in.data() + i * 64 + 32);
    }

    std::vector<uint8_t> states_out(n * 64, 0);
    int rc = poseidon2_t2_batch_metal(states_in.data(), n,
                                       states_out.data(), metallib);
    if (rc != 0) {
        std::fprintf(stderr, "FAIL Metal dispatch rc=%d\n", rc);
        return 1;
    }
    std::fprintf(stdout, "PASS Metal dispatch rc=0 (%zu states)\n", n);

    int eq = 0;
    for (size_t i = 0; i < n; ++i) {
        const KATCase& c = kat[idx[i]];
        char gl[65], gr[65];
        to_hex(states_out.data() + i * 64,        gl);
        to_hex(states_out.data() + i * 64 + 32,   gr);
        std::string wl = c.output_hex[0];
        std::string wr = c.output_hex[1];
        if (wl.substr(0, 2) == "0x") wl = wl.substr(2);
        if (wr.substr(0, 2) == "0x") wr = wr.substr(2);
        while (wl.size() < 64) wl = "0" + wl;
        while (wr.size() < 64) wr = "0" + wr;
        if (gl == wl && gr == wr) {
            ++eq;
        } else {
            std::fprintf(stderr,
                "FAIL i=%zu\n  got  (%s, %s)\n  want (%s, %s)\n",
                i, gl, gr, wl.c_str(), wr.c_str());
            ++g_failures;
        }
    }
    std::fprintf(stdout, "PASS Metal byte-equal KAT %d/%zu\n", eq, n);
#else
    std::fprintf(stdout, "(non-Apple host: GPU KAT skipped)\n");
#endif

    std::fprintf(stdout, "=== %s (%d failure%s) ===\n",
                 g_failures == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED",
                 g_failures, g_failures == 1 ? "" : "s");
    return g_failures == 0 ? 0 : 1;
}
