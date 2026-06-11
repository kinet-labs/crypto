// NTT Known-Answer Tests against the Go reference at
// github.com/kinet-labs/crypto/poly_mul (NTTForward).
//
// Vector file: ntt/test/vectors/ntt_kat.json — produced by the Go-side
// generator; same LCG seed schedule, same Cooley-Tukey iteration order, same
// per-coefficient byte output. Any drift in this binding fails here.
//
// Path: parse JSON minimally (no external deps), call ntt::forward, compare
// every coefficient against the recorded `forward` vector.

#include "ntt.hpp"

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

// Trivial JSON tokenizer for the strict-format vectors we generate. Not a
// full parser; it only handles the exact structure: an array of objects with
// known string keys mapping to either a string, integer, or integer array.
struct Lexer {
    const std::string& s;
    size_t i = 0;
    void skip_ws() { while (i < s.size() && (s[i]==' '||s[i]=='\t'||s[i]=='\n'||s[i]=='\r')) ++i; }
    bool peek(char c) { skip_ws(); return i < s.size() && s[i] == c; }
    bool eat(char c)  { skip_ws(); if (peek(c)) { ++i; return true; } return false; }
    std::string read_string() {
        skip_ws();
        if (s[i] != '"') return {};
        ++i;
        std::string out;
        while (i < s.size() && s[i] != '"') out.push_back(s[i++]);
        if (i < s.size()) ++i;
        return out;
    }
    uint64_t read_uint() {
        skip_ws();
        uint64_t v = 0;
        while (i < s.size() && s[i] >= '0' && s[i] <= '9') {
            v = v * 10 + static_cast<uint64_t>(s[i++] - '0');
        }
        return v;
    }
    std::vector<uint64_t> read_uint_array() {
        std::vector<uint64_t> out;
        if (!eat('[')) return out;
        if (eat(']')) return out;
        for (;;) {
            out.push_back(read_uint());
            if (eat(',')) continue;
            if (eat(']')) break;
        }
        return out;
    }
};

struct Vector {
    std::string name;
    uint32_t    n = 0;
    uint64_t    seed = 0;
    std::vector<uint64_t> input;
    std::vector<uint64_t> forward;
};

std::vector<Vector> parse_vectors(const std::string& path) {
    std::ifstream f(path);
    if (!f) {
        std::fprintf(stderr, "ntt_kat_test: cannot open %s\n", path.c_str());
        std::exit(1);
    }
    std::stringstream buf; buf << f.rdbuf();
    std::string s = buf.str();
    Lexer lx{s};
    std::vector<Vector> out;
    if (!lx.eat('[')) return out;
    if (lx.eat(']')) return out;
    for (;;) {
        if (!lx.eat('{')) break;
        Vector v;
        for (;;) {
            std::string key = lx.read_string();
            lx.eat(':');
            if      (key == "name")    v.name    = lx.read_string();
            else if (key == "n")       v.n       = static_cast<uint32_t>(lx.read_uint());
            else if (key == "seed")    v.seed    = lx.read_uint();
            else if (key == "input")   v.input   = lx.read_uint_array();
            else if (key == "forward") v.forward = lx.read_uint_array();
            else {
                // Skip unknown value types. This shouldn't happen with our
                // generator output but is harmless.
                if (lx.peek('"')) lx.read_string();
                else if (lx.peek('[')) lx.read_uint_array();
                else lx.read_uint();
            }
            if (lx.eat(',')) continue;
            if (lx.eat('}')) break;
        }
        out.push_back(std::move(v));
        if (lx.eat(',')) continue;
        if (lx.eat(']')) break;
    }
    return out;
}

bool run_one(const Vector& v) {
    if (v.input.size() != v.n || v.forward.size() != v.n) {
        std::fprintf(stderr, "[%s] bad vector: sizes mismatch\n", v.name.c_str());
        return false;
    }
    std::vector<uint64_t> a = v.input;
    auto ctx = kinet::crypto::ntt::make_context(v.n);
    kinet::crypto::ntt::forward(a.data(), v.n, ctx);
    for (uint32_t i = 0; i < v.n; ++i) {
        if (a[i] != v.forward[i]) {
            std::fprintf(stderr,
                "[%s] forward mismatch at i=%u: got %llu want %llu\n",
                v.name.c_str(), i,
                static_cast<unsigned long long>(a[i]),
                static_cast<unsigned long long>(v.forward[i]));
            return false;
        }
    }
    // Round-trip: forward then inverse should restore the input.
    std::vector<uint64_t> b = v.forward;
    kinet::crypto::ntt::inverse(b.data(), v.n, ctx);
    for (uint32_t i = 0; i < v.n; ++i) {
        if (b[i] != v.input[i]) {
            std::fprintf(stderr,
                "[%s] roundtrip mismatch at i=%u: got %llu want %llu\n",
                v.name.c_str(), i,
                static_cast<unsigned long long>(b[i]),
                static_cast<unsigned long long>(v.input[i]));
            return false;
        }
    }
    std::printf("[%s] PASS (n=%u)\n", v.name.c_str(), v.n);
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: %s <ntt_kat.json>\n", argv[0]);
        return 1;
    }
    auto vectors = parse_vectors(argv[1]);
    if (vectors.empty()) {
        std::fprintf(stderr, "no vectors parsed\n");
        return 1;
    }
    int failed = 0;
    for (const auto& v : vectors) {
        if (!run_one(v)) ++failed;
    }
    std::printf("\nntt_kat_test: %zu vectors, %d failed\n",
                vectors.size(), failed);
    return failed == 0 ? 0 : 1;
}
