// Sweeps batch sizes N in {1, 16, 64, 256, 1024, 4096} for batched ed25519
// verify, comparing CPU (per-input scalar verify with the same field /
// curve / SHA-512 ops) vs Metal kernel dispatch. Median of 10 runs each,
// Release build. Reports the crossover N_threshold where Metal wins.
//
// Skipped silently when CRYPTO_ED25519_METALLIB is unset.

#include "../cpp/sha512_minimal.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#if __APPLE__
extern "C" int ed25519_batch_verify_metal(
    const uint8_t* pubkeys,
    const uint8_t* signatures,
    const uint8_t* challenges,
    size_t         n,
    uint8_t*       results,
    const char*    metallib_path);
#endif

namespace {

// Minimal CPU-side ed25519 verify, structurally identical to the Metal
// kernel: 256-bit limb arithmetic, point decompression, scalar mul,
// affine compare. This is the "per-input serial" baseline -- not the
// hardware-tuned circl path -- so the comparison is GPU-vs-equivalent-
// CPU work, isolating the dispatch overhead.

struct U {
    uint64_t l[4];
};

constexpr U P  = {{0xFFFFFFFFFFFFFFEDUL, 0xFFFFFFFFFFFFFFFFUL,
                   0xFFFFFFFFFFFFFFFFUL, 0x7FFFFFFFFFFFFFFFUL}};
constexpr U D  = {{0x75EB4DCA135978A3UL, 0x00700A4D4141D8ABUL,
                   0x8CC740797779E898UL, 0x52036CEE2B6FFE73UL}};
constexpr U TD = {{0xEBD69B9426B2F159UL, 0x00E0149A8283B156UL,
                   0x198E80F2EEF3D130UL, 0x2406D9DC56DFFCE7UL}};
constexpr U L  = {{0x5812631A5CF5D3EDUL, 0x14DEF9DEA2F79CD6UL,
                   0x0000000000000000UL, 0x1000000000000000UL}};
constexpr U BX = {{0xC9562D608F25D51AUL, 0x692CC7609525A7B2UL,
                   0xC0A4E231FDD6DC5CUL, 0x216936D3CD6E53FEUL}};
constexpr U BY = {{0x6666666666666658UL, 0x6666666666666666UL,
                   0x6666666666666666UL, 0x6666666666666666UL}};
constexpr U S1 = {{0xC4EE1B274A0EA0B0UL, 0x2F431806AD2FE478UL,
                   0x2B4D00993DFBD7A7UL, 0x2B8324804FC1DF0BUL}};
constexpr U Z  = {{0,0,0,0}};
constexpr U O  = {{1,0,0,0}};

int cmp(U a, U b) {
    for (int i = 3; i >= 0; --i) {
        if (a.l[i] < b.l[i]) return -1;
        if (a.l[i] > b.l[i]) return 1;
    }
    return 0;
}
bool z_(U a) { return (a.l[0]|a.l[1]|a.l[2]|a.l[3]) == 0UL; }
U add_(U a, U b, uint64_t& cy) {
    U r; uint64_t c = 0;
    for (int i = 0; i < 4; ++i) {
        uint64_t s1 = a.l[i] + c;
        uint64_t c1 = (s1 < a.l[i]) ? 1UL : 0UL;
        uint64_t s2 = s1 + b.l[i];
        uint64_t c2 = (s2 < s1) ? 1UL : 0UL;
        r.l[i] = s2; c = c1 + c2;
    }
    cy = c; return r;
}
U sub_(U a, U b, uint64_t& bw) {
    U r; uint64_t w = 0;
    for (int i = 0; i < 4; ++i) {
        uint64_t d1 = a.l[i] - w;
        uint64_t b1 = (d1 > a.l[i]) ? 1UL : 0UL;
        uint64_t d2 = d1 - b.l[i];
        uint64_t b2 = (d2 > d1) ? 1UL : 0UL;
        r.l[i] = d2; w = b1 + b2;
    }
    bw = w; return r;
}
void mul64(uint64_t a, uint64_t b, uint64_t& lo, uint64_t& hi) {
    __uint128_t p = (__uint128_t)a * b;
    lo = (uint64_t)p; hi = (uint64_t)(p >> 64);
}
U canon(U a) {
    while (cmp(a, P) >= 0) { uint64_t bw; a = sub_(a, P, bw); }
    return a;
}
U fadd(U a, U b) {
    uint64_t c; U r = add_(a, b, c);
    if (c || cmp(r, P) >= 0) { uint64_t bw; r = sub_(r, P, bw); }
    return r;
}
U fsub(U a, U b) {
    uint64_t bw; U r = sub_(a, b, bw);
    if (bw) { uint64_t c; r = add_(r, P, c); }
    return r;
}
U fmul(U a, U b) {
    uint64_t t[8] = {};
    for (int i = 0; i < 4; ++i) {
        uint64_t cy = 0;
        for (int j = 0; j < 4; ++j) {
            uint64_t lo, hi; mul64(a.l[i], b.l[j], lo, hi);
            uint64_t s = lo + cy;
            uint64_t c1 = (s < lo) ? 1UL : 0UL;
            uint64_t s2 = t[i+j] + s;
            uint64_t c2 = (s2 < t[i+j]) ? 1UL : 0UL;
            t[i+j] = s2;
            cy = hi + c1 + c2;
        }
        t[i+4] = cy;
    }
    U lo_p = {{t[0], t[1], t[2], t[3]}};
    U hi_p = {{t[4], t[5], t[6], t[7]}};
    uint64_t cy = 0; U h38;
    for (int i = 0; i < 4; ++i) {
        uint64_t lo, hi; mul64(hi_p.l[i], 38UL, lo, hi);
        uint64_t s = lo + cy;
        cy = hi + ((s < lo) ? 1UL : 0UL);
        h38.l[i] = s;
    }
    uint64_t c; U r = add_(lo_p, h38, c);
    if (c || cy) {
        uint64_t e = (c + cy) * 38UL;
        U ex = {{e, 0, 0, 0}};
        r = add_(r, ex, c);
    }
    return canon(r);
}
U fsqr(U a) { return fmul(a, a); }
U fneg(U a) { if (z_(a)) return a; uint64_t bw; return sub_(P, a, bw); }
U finv(U a) {
    U exp = P; exp.l[0] -= 2;
    U r = O, b = a;
    for (int i = 0; i < 4; ++i) {
        uint64_t lm = exp.l[i];
        for (int j = 0; j < 64; ++j) {
            if ((lm >> j) & 1UL) r = fmul(r, b);
            b = fsqr(b);
        }
    }
    return r;
}

struct Pt { U X, Y, Z, T; };
Pt id_() { return {Z, O, O, Z}; }
Pt dbl_(Pt P_) {
    U A = fsqr(P_.X), B = fsqr(P_.Y);
    U C = fadd(fsqr(P_.Z), fsqr(P_.Z));
    U Dn = fneg(A);
    U XY = fadd(P_.X, P_.Y);
    U E = fsub(fsqr(XY), fadd(A, B));
    U G = fadd(Dn, B);
    U F = fsub(G, C);
    U H = fsub(Dn, B);
    Pt R; R.X = fmul(E, F); R.Y = fmul(G, H);
    R.T = fmul(E, H); R.Z = fmul(F, G);
    return R;
}
Pt add_pt(Pt P_, Pt Q_) {
    U A = fmul(fsub(P_.Y, P_.X), fsub(Q_.Y, Q_.X));
    U B = fmul(fadd(P_.Y, P_.X), fadd(Q_.Y, Q_.X));
    U C = fmul(fmul(P_.T, TD), Q_.T);
    U ZZ = fmul(P_.Z, Q_.Z);
    U Dn = fadd(ZZ, ZZ);
    U E = fsub(B, A), F = fsub(Dn, C), G = fadd(Dn, C), H = fadd(B, A);
    Pt R; R.X = fmul(E, F); R.Y = fmul(G, H);
    R.T = fmul(E, H); R.Z = fmul(F, G);
    return R;
}
Pt mul_pt(U k, Pt P_) {
    Pt r = id_();
    for (int i = 3; i >= 0; --i) {
        uint64_t lm = k.l[i];
        for (int j = 63; j >= 0; --j) {
            r = dbl_(r);
            if ((lm >> j) & 1UL) r = add_pt(r, P_);
        }
    }
    return r;
}
void to_aff(Pt p, U& x, U& y) {
    U zi = finv(p.Z);
    x = fmul(p.X, zi); y = fmul(p.Y, zi);
}
bool dec(const uint8_t* enc, Pt& P_) {
    U y;
    for (int i = 0; i < 4; ++i) {
        uint64_t v = 0;
        for (int b = 0; b < 8; ++b) v |= (uint64_t)enc[i*8+b] << (b*8);
        y.l[i] = v;
    }
    bool sg = (enc[31] >> 7) & 1u;
    y.l[3] &= 0x7FFFFFFFFFFFFFFFUL;
    if (cmp(y, P) >= 0) return false;
    U y2 = fsqr(y), num = fsub(y2, O);
    U den = fadd(fmul(D, y2), O);
    U di = finv(den);
    U x2 = fmul(num, di);
    if (z_(x2)) {
        if (sg) return false;
        P_.X = Z; P_.Y = y; P_.Z = O; P_.T = Z;
        return true;
    }
    U exp = P; exp.l[0] += 3UL;
    for (int i = 0; i < 3; ++i) exp.l[i] = (exp.l[i] >> 3) | (exp.l[i+1] << 61);
    exp.l[3] >>= 3;
    U x = O, b = x2;
    for (int i = 0; i < 4; ++i) {
        uint64_t lm = exp.l[i];
        for (int j = 0; j < 64; ++j) {
            if ((lm >> j) & 1UL) x = fmul(x, b);
            b = fsqr(b);
        }
    }
    if (cmp(fsqr(x), x2) != 0) {
        x = fmul(x, S1);
        if (cmp(fsqr(x), x2) != 0) return false;
    }
    bool odd = (x.l[0] & 1UL) != 0UL;
    if (odd != sg) x = fneg(x);
    P_.X = x; P_.Y = y; P_.Z = O; P_.T = fmul(x, y);
    return true;
}

bool cpu_verify(const uint8_t* pub, const uint8_t* sig, const uint8_t* h32) {
    Pt A_; if (!dec(pub, A_)) return false;
    Pt R_; if (!dec(sig, R_)) return false;
    U S; for (int i = 0; i < 4; ++i) {
        uint64_t v = 0;
        for (int b = 0; b < 8; ++b) v |= (uint64_t)sig[32+i*8+b] << (b*8);
        S.l[i] = v;
    }
    if (cmp(S, L) >= 0) return false;
    U h; for (int i = 0; i < 4; ++i) {
        uint64_t v = 0;
        for (int b = 0; b < 8; ++b) v |= (uint64_t)h32[i*8+b] << (b*8);
        h.l[i] = v;
    }
    Pt B = {BX, BY, O, fmul(BX, BY)};
    Pt SB = mul_pt(S, B), hA = mul_pt(h, A_), RhA = add_pt(R_, hA);
    U sx, sy, rx, ry;
    to_aff(SB, sx, sy); to_aff(RhA, rx, ry);
    return cmp(sx, rx) == 0 && cmp(sy, ry) == 0;
}

double median_us(std::vector<double>& v) {
    std::sort(v.begin(), v.end());
    return v[v.size() / 2];
}

}  // namespace

int main() {
    std::fprintf(stdout, "=== ed25519 batch-verify CPU vs Metal sweep ===\n");

#if __APPLE__
    const char* metallib = std::getenv("CRYPTO_ED25519_METALLIB");
    if (!metallib) {
        std::fprintf(stdout, "(skip: CRYPTO_ED25519_METALLIB unset)\n");
        return 0;
    }

    using namespace kinetcrypto::ed25519;

    // Reference RFC 8032 TEST 1 triple, tiled to N copies for the bench.
    uint8_t pub_t[32] = {
        0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7,0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a,
        0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25,0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a
    };
    uint8_t sig_t[64] = {
        0xe5,0x56,0x43,0x00,0xc3,0x60,0xac,0x72,0x90,0x86,0xe2,0xcc,0x80,0x6e,0x82,0x8a,
        0x84,0x87,0x7f,0x1e,0xb8,0xe5,0xd9,0x74,0xd8,0x73,0xe0,0x65,0x22,0x49,0x01,0x55,
        0x5f,0xb8,0x82,0x15,0x90,0xa3,0x3b,0xac,0xc6,0x1e,0x39,0x70,0x1c,0xf9,0xb4,0x6b,
        0xd2,0x5b,0xf5,0xf0,0x59,0x5b,0xbe,0x24,0x65,0x51,0x41,0x43,0x8e,0x7a,0x10,0x0b
    };
    // Pre-compute h = SHA-512(R||A||M) mod L for the empty message.
    uint8_t ram[64];
    std::memcpy(ram, sig_t, 32);
    std::memcpy(ram + 32, pub_t, 32);
    uint8_t hash[64], h32[32];
    sha512(hash, ram, 64);
    reduce_mod_l(h32, hash);

    constexpr size_t SIZES[] = {1, 16, 64, 256, 1024, 4096};
    constexpr int RUNS = 10;

    std::fprintf(stdout, "%6s %14s %14s %14s\n", "N", "CPU_us", "Metal_us", "Speedup");
    int crossover = -1;
    for (size_t s : SIZES) {
        std::vector<uint8_t> pubs(s * 32), sigs(s * 64), chs(s * 32);
        for (size_t i = 0; i < s; ++i) {
            std::memcpy(pubs.data() + i * 32, pub_t, 32);
            std::memcpy(sigs.data() + i * 64, sig_t, 64);
            std::memcpy(chs.data()  + i * 32, h32,   32);
        }
        std::vector<uint8_t> results_metal(s, 0), results_cpu(s, 0);

        // CPU runs
        std::vector<double> cpu_us;
        for (int r = 0; r < RUNS; ++r) {
            auto t0 = std::chrono::steady_clock::now();
            for (size_t i = 0; i < s; ++i) {
                results_cpu[i] = cpu_verify(pubs.data() + i*32,
                                            sigs.data() + i*64,
                                            chs.data()  + i*32) ? 1u : 0u;
            }
            auto t1 = std::chrono::steady_clock::now();
            cpu_us.push_back(
                std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count());
        }

        // Metal runs (warm-up dispatched first to amortise pipeline build).
        ed25519_batch_verify_metal(pubs.data(), sigs.data(), chs.data(),
                                   s, results_metal.data(), metallib);
        std::vector<double> m_us;
        for (int r = 0; r < RUNS; ++r) {
            auto t0 = std::chrono::steady_clock::now();
            ed25519_batch_verify_metal(pubs.data(), sigs.data(), chs.data(),
                                       s, results_metal.data(), metallib);
            auto t1 = std::chrono::steady_clock::now();
            m_us.push_back(
                std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count());
        }

        double mc = median_us(cpu_us);
        double mm = median_us(m_us);
        double speed = mc / mm;
        std::fprintf(stdout, "%6zu %14.0f %14.0f %14.2fx%s\n",
                     s, mc, mm, speed,
                     speed >= 1.0 ? " (Metal wins)" : "");
        if (crossover < 0 && speed >= 1.0) crossover = (int)s;
    }
    if (crossover >= 0) {
        std::fprintf(stdout, "\nN_threshold (Metal >= CPU): %d\n", crossover);
    } else {
        std::fprintf(stdout, "\nN_threshold: NONE -- Metal slower than CPU at all tested N.\n");
        std::fprintf(stdout, "  Per-thread serial work (256-bit fp_mul-heavy curve scalar mul)\n");
        std::fprintf(stdout, "  is dominated by Metal compute unit's mul64 emulation overhead\n");
        std::fprintf(stdout, "  on Apple Silicon. dGPU (CUDA H100/Ada) closes this gap;\n");
        std::fprintf(stdout, "  precedent: aivm v0.59 + V2 EVM kernel (LP-137 §47).\n");
    }
#else
    std::fprintf(stdout, "(non-Apple host: bench skipped)\n");
#endif
    return 0;
}
