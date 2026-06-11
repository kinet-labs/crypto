// Polynomial-multiplication Known-Answer Tests against the Go reference at
// github.com/kinet-labs/crypto/poly_mul (MulSchoolbook + MulNTT + Mul).
//
// Vector file: poly_mul/test/vectors/poly_mul_kat.json — produced by the
// Go-side generator. For each vector we exercise both schoolbook and NTT
// (where size allows) and assert byte-equality against the reference c[].

#include "poly_mul.hpp"

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

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
    std::vector<uint64_t> a, b, c;
    uint64_t    sum = 0, first = 0, last = 0;
};

std::vector<Vector> parse_vectors(const std::string& path) {
    std::ifstream f(path);
    if (!f) {
        std::fprintf(stderr, "poly_mul_kat_test: cannot open %s\n", path.c_str());
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
            if      (key == "name")  v.name  = lx.read_string();
            else if (key == "n")     v.n     = static_cast<uint32_t>(lx.read_uint());
            else if (key == "a")     v.a     = lx.read_uint_array();
            else if (key == "b")     v.b     = lx.read_uint_array();
            else if (key == "c")     v.c     = lx.read_uint_array();
            else if (key == "sum")   v.sum   = lx.read_uint();
            else if (key == "first") v.first = lx.read_uint();
            else if (key == "last")  v.last  = lx.read_uint();
            else {
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

constexpr uint64_t Q = kinet::crypto::poly_mul::Q;

bool check_against(const std::vector<uint64_t>& got, const Vector& v, const char* label) {
    if (got.size() != v.n) {
        std::fprintf(stderr, "[%s/%s] size mismatch: %zu vs %u\n",
                     v.name.c_str(), label, got.size(), v.n);
        return false;
    }
    for (uint32_t i = 0; i < v.n; ++i) {
        if (got[i] != v.c[i]) {
            std::fprintf(stderr,
                "[%s/%s] coef[%u]=%llu want %llu\n",
                v.name.c_str(), label, i,
                static_cast<unsigned long long>(got[i]),
                static_cast<unsigned long long>(v.c[i]));
            return false;
        }
    }
    // Sum/first/last sanity
    uint64_t sum = 0;
    for (auto x : got) sum = (sum + x) % Q;
    if (sum != v.sum || got.front() != v.first || got.back() != v.last) {
        std::fprintf(stderr,
            "[%s/%s] sum/first/last mismatch: got (%llu,%llu,%llu) want (%llu,%llu,%llu)\n",
            v.name.c_str(), label,
            (unsigned long long)sum, (unsigned long long)got.front(), (unsigned long long)got.back(),
            (unsigned long long)v.sum, (unsigned long long)v.first, (unsigned long long)v.last);
        return false;
    }
    return true;
}

bool run_one(const Vector& v) {
    if (v.a.size() != v.n || v.b.size() != v.n || v.c.size() != v.n) {
        std::fprintf(stderr, "[%s] bad vector: sizes mismatch\n", v.name.c_str());
        return false;
    }

    // 1) Schoolbook always.
    std::vector<uint64_t> rs(v.n, 0);
    if (!kinet::crypto::poly_mul::multiply_schoolbook(rs.data(),
                                                     v.a.data(), v.n,
                                                     v.b.data())) {
        std::fprintf(stderr, "[%s] multiply_schoolbook returned false\n", v.name.c_str());
        return false;
    }
    if (!check_against(rs, v, "schoolbook")) return false;

    // 2) NTT path when supported.
    bool can_ntt = (v.n >= 2) && ((v.n & (v.n - 1)) == 0) && (v.n <= (1u << 15));
    if (can_ntt) {
        std::vector<uint64_t> rn(v.n, 0);
        if (!kinet::crypto::poly_mul::multiply_ntt(rn.data(),
                                                  v.a.data(), v.n,
                                                  v.b.data())) {
            std::fprintf(stderr, "[%s] multiply_ntt returned false\n", v.name.c_str());
            return false;
        }
        if (!check_against(rn, v, "ntt")) return false;
        // Cross-check: schoolbook == NTT byte-for-byte.
        for (uint32_t i = 0; i < v.n; ++i) {
            if (rs[i] != rn[i]) {
                std::fprintf(stderr,
                    "[%s] schoolbook != ntt at i=%u: %llu vs %llu\n",
                    v.name.c_str(), i,
                    (unsigned long long)rs[i],
                    (unsigned long long)rn[i]);
                return false;
            }
        }
    }

    // 3) Public dispatcher.
    std::vector<uint64_t> rd(v.n, 0);
    if (!kinet::crypto::poly_mul::multiply(rd.data(),
                                          v.a.data(), v.n,
                                          v.b.data(), v.n)) {
        std::fprintf(stderr, "[%s] multiply returned false\n", v.name.c_str());
        return false;
    }
    if (!check_against(rd, v, "Mul")) return false;

    std::printf("[%s] PASS (n=%u)\n", v.name.c_str(), v.n);
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: %s <poly_mul_kat.json>\n", argv[0]);
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
    std::printf("\npoly_mul_kat_test: %zu vectors, %d failed\n",
                vectors.size(), failed);
    return failed == 0 ? 0 : 1;
}
