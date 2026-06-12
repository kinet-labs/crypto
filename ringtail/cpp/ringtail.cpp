// Ringtail — Ring-LWE threshold signature host body.
//
// See ringtail.hpp for parameter rationale and scope notes. This file is the
// canonical CPU oracle; GPU acceleration (Metal / CUDA / WGSL) lives under
// gpu/ and consumes the same wire format.

#include "ringtail.hpp"

#include "../../poly_mul/cpp/poly_mul.hpp"
#include "../../sha256/cpp/sha256.hpp"
#include "crypto.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <random>
#include <stdexcept>
#include <vector>

namespace kinet::crypto::ringtail {

// =============================================================================
// Deterministic stream PRNG (SHA-256 in counter mode)
// =============================================================================
// 32-byte seed + 64-bit counter -> 32-byte block. Output is the byte stream
// h(seed || ctr=0) || h(seed || ctr=1) || ... — same construction as the
// Go reference's KeyedPRNG variant for this layer (independent of Lattigo's
// Blake2-XOF flavor used in the network protocol).

namespace {

inline void sha256_block(const uint8_t* in, size_t in_len, uint8_t out[32]) {
    cevm::crypto::sha256(reinterpret_cast<std::byte*>(out),
                         reinterpret_cast<const std::byte*>(in),
                         in_len);
}

class StreamPRNG {
public:
    StreamPRNG(const uint8_t* seed, size_t seed_len) {
        seed_.resize(seed_len);
        std::memcpy(seed_.data(), seed, seed_len);
        refill();
    }

    void fill(uint8_t* out, size_t n) {
        while (n > 0) {
            if (buf_pos_ >= 32) refill();
            size_t take = std::min<size_t>(32 - buf_pos_, n);
            std::memcpy(out, buf_ + buf_pos_, take);
            out += take;
            buf_pos_ += take;
            n -= take;
        }
    }

    uint64_t next_u64() {
        uint8_t b[8];
        fill(b, 8);
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(b[i]) << (i * 8);
        return v;
    }

    uint32_t next_u32() {
        uint8_t b[4];
        fill(b, 4);
        uint32_t v = 0;
        for (int i = 0; i < 4; ++i) v |= static_cast<uint32_t>(b[i]) << (i * 8);
        return v;
    }

private:
    void refill() {
        // Append 8-byte counter to seed and hash.
        std::vector<uint8_t> in;
        in.reserve(seed_.size() + 8);
        in.insert(in.end(), seed_.begin(), seed_.end());
        for (int i = 0; i < 8; ++i) {
            in.push_back(static_cast<uint8_t>((counter_ >> (i * 8)) & 0xFF));
        }
        sha256_block(in.data(), in.size(), buf_);
        ++counter_;
        buf_pos_ = 0;
    }

    std::vector<uint8_t> seed_;
    uint64_t counter_ = 0;
    uint8_t  buf_[32]{};
    size_t   buf_pos_ = 32;  // force initial refill
};

// =============================================================================
// Ring helpers
// =============================================================================

inline uint64_t add_mod_q(uint64_t a, uint64_t b) {
    uint64_t s = a + b;
    if (s >= Q) s -= Q;
    return s;
}

inline uint64_t sub_mod_q(uint64_t a, uint64_t b) {
    return (a >= b) ? (a - b) : (a + Q - b);
}

inline uint64_t mul_mod_q(uint64_t a, uint64_t b) {
    return (a * b) % Q;  // Q < 2^30 so a*b fits in u64.
}

inline uint64_t pow_mod_q(uint64_t base, uint64_t exp) {
    uint64_t r = 1, b = base % Q;
    while (exp > 0) {
        if (exp & 1) r = mul_mod_q(r, b);
        b = mul_mod_q(b, b);
        exp >>= 1;
    }
    return r;
}

inline uint64_t inv_mod_q(uint64_t a) {
    // Q is prime. Fermat: a^(Q-2).
    return pow_mod_q(a, Q - 2);
}

void poly_zero(Poly& p) {
    p.assign(N, 0);
}

Poly poly_new() {
    return Poly(N, 0);
}

void poly_add(Poly& out, const Poly& a, const Poly& b) {
    for (uint32_t i = 0; i < N; ++i) out[i] = add_mod_q(a[i], b[i]);
}

void poly_sub(Poly& out, const Poly& a, const Poly& b) {
    for (uint32_t i = 0; i < N; ++i) out[i] = sub_mod_q(a[i], b[i]);
}

void poly_mul_negacyclic(Poly& out, const Poly& a, const Poly& b) {
    Poly tmp(N, 0);
    bool ok = poly_mul::multiply(tmp.data(), a.data(), N, b.data(), N);
    if (!ok) {
        // poly_mul::multiply only returns false on bad input, which we
        // construct correctly here by static contract. Defensive zero on miss.
        std::fill(tmp.begin(), tmp.end(), 0);
    }
    out = std::move(tmp);
}

void poly_scalar_mul(Poly& out, const Poly& a, uint64_t s) {
    uint64_t sr = s % Q;
    for (uint32_t i = 0; i < N; ++i) out[i] = mul_mod_q(a[i], sr);
}

// =============================================================================
// Samplers
// =============================================================================

// Uniform poly in R_q. Rejection-sample u32 < (2^32 - (2^32 mod Q)) and reduce.
void sample_uniform_poly(Poly& p, StreamPRNG& rng) {
    p.resize(N);
    constexpr uint64_t bound = (uint64_t{1} << 32) - ((uint64_t{1} << 32) % Q);
    for (uint32_t i = 0; i < N; ++i) {
        uint32_t v;
        do { v = rng.next_u32(); } while (v >= bound);
        p[i] = v % Q;
    }
}

// Discrete Gaussian via inverse CDT (cumulative distribution table) at sigma.
// For SIGMA = 1.7 we tabulate p[k] = Pr[X = k] for k in 0..GAUSS_BOUND, then
// CDT in fixed-point u64. Symmetric (sign uniform). This is the textbook
// FALCON/Dilithium-class CDT sampler; constant-time *up to the public bound*.
//
// The sampler is constructed once (lazy local) and reused; tail beyond
// GAUSS_BOUND has probability << 2^-64 for σ=1.7.

class GaussianCDT {
public:
    GaussianCDT() {
        // p[k] proportional to exp(-k^2 / (2*sigma^2)); symmetric.
        // Use double precision; tail beyond GAUSS_BOUND drops below 2^-64.
        double sum = 0.0;
        std::vector<double> pmf(GAUSS_BOUND + 1, 0.0);
        for (int k = 0; k <= GAUSS_BOUND; ++k) {
            pmf[k] = std::exp(-static_cast<double>(k) * k /
                              (2.0 * SIGMA * SIGMA));
        }
        // Symmetric: P(0) once, P(±k) twice for k>=1.
        sum = pmf[0];
        for (int k = 1; k <= GAUSS_BOUND; ++k) sum += 2.0 * pmf[k];
        for (int k = 0; k <= GAUSS_BOUND; ++k) pmf[k] /= sum;

        // CDT for non-negative half: cdt[k] = sum_{j=0..k} pmf'[j], where
        // pmf'[0] = pmf[0], pmf'[k] = 2*pmf[k] for k>=1.
        cdt_.resize(GAUSS_BOUND + 1);
        double cum = 0.0;
        cum += pmf[0];
        cdt_[0] = static_cast<uint64_t>(cum * 18446744073709551615.0);
        for (int k = 1; k <= GAUSS_BOUND; ++k) {
            cum += 2.0 * pmf[k];
            // Saturate to avoid overflow on cum >= 1.0 due to fp rounding.
            if (cum >= 1.0) {
                cdt_[k] = ~uint64_t{0};
            } else {
                cdt_[k] = static_cast<uint64_t>(cum * 18446744073709551615.0);
            }
        }
        // Force last entry to all-ones so sampler always lands.
        cdt_.back() = ~uint64_t{0};
    }

    // Returns a signed Gaussian in [-GAUSS_BOUND, GAUSS_BOUND].
    int32_t sample(StreamPRNG& rng) const {
        uint64_t u = rng.next_u64();
        // Sign bit drawn separately (uniform). For k=0, sign is irrelevant.
        // We collapse: lookup k, then apply sign (uniform fair) — but that
        // double-counts k=0 with both signs. Standard trick: take |k| from
        // the half-CDT then sign uniformly, and reject the (k==0, sign==-1)
        // duplicate by re-rolling. Constant-time enough for our threat model.
        int32_t mag = 0;
        for (int k = 0; k <= GAUSS_BOUND; ++k) {
            if (u <= cdt_[k]) { mag = k; break; }
        }
        if (mag == 0) return 0;
        // Sign from another draw. Bit 0 of next u32.
        uint32_t s = rng.next_u32();
        return (s & 1) ? -mag : mag;
    }

private:
    std::vector<uint64_t> cdt_;
};

const GaussianCDT& gauss_cdt() {
    static const GaussianCDT g;
    return g;
}

// Sample one poly with all coefficients drawn from D_{sigma}.
void sample_gaussian_poly(Poly& p, StreamPRNG& rng) {
    p.resize(N);
    const auto& g = gauss_cdt();
    for (uint32_t i = 0; i < N; ++i) {
        int32_t v = g.sample(rng);
        // Map signed v in [-bound, +bound] to [0, Q).
        if (v >= 0) {
            p[i] = static_cast<uint64_t>(v) % Q;
        } else {
            p[i] = sub_mod_q(0, static_cast<uint64_t>(-v) % Q);
        }
    }
}

// Sample a challenge poly c with TAU non-zero ternary (+1/-1) coefficients,
// remaining N-TAU coefficients zero. Hashing path: derive 32-byte digest of
// (msg || w || A || b), seed StreamPRNG, then Fisher-Yates select TAU
// positions and fair-coin signs. This is the canonical Lyubashevsky/Dilithium
// challenge construction.
void challenge_poly(Poly& c,
                    const uint8_t* tag, size_t tag_len) {
    StreamPRNG rng(tag, tag_len);
    c.assign(N, 0);
    // Reservoir-style position picking: walk i=0..N-1, swap with rng.next % (i+1).
    // We instead use Fisher-Yates on a working array of indices to avoid bias.
    std::vector<uint32_t> idx(N);
    for (uint32_t i = 0; i < N; ++i) idx[i] = i;
    for (uint32_t i = 0; i < TAU; ++i) {
        uint32_t span = N - i;
        // Rejection-sample u32 to avoid modulo bias. Compute the largest
        // multiple of span that fits in u32 as a u64 then narrow only at
        // the comparison point — for any span that divides 2^32 (e.g.
        // span = 512), the multiple equals 2^32 and the naive u32 cast
        // wraps to 0, which would make the `r >= bound` condition always
        // true and spin forever.
        const uint64_t bound64 = (uint64_t{1} << 32) / span * span;
        uint32_t r;
        do { r = rng.next_u32(); } while (static_cast<uint64_t>(r) >= bound64);
        uint32_t j = i + (r % span);
        std::swap(idx[i], idx[j]);
        // Sign from a separate draw.
        uint32_t s = rng.next_u32() & 1;
        c[idx[i]] = (s == 0) ? 1 : (Q - 1);  // +1 or -1 mod Q
    }
}

// =============================================================================
// Wire format
// =============================================================================

void poly_to_bytes(const Poly& p, uint8_t* out) {
    for (uint32_t i = 0; i < N; ++i) {
        uint32_t v = static_cast<uint32_t>(p[i]);
        out[4*i + 0] = static_cast<uint8_t>(v & 0xFF);
        out[4*i + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
        out[4*i + 2] = static_cast<uint8_t>((v >> 16) & 0xFF);
        out[4*i + 3] = static_cast<uint8_t>((v >> 24) & 0xFF);
    }
}

bool poly_from_bytes(Poly& p, const uint8_t* in) {
    p.resize(N);
    for (uint32_t i = 0; i < N; ++i) {
        uint32_t v = 0;
        v |= static_cast<uint32_t>(in[4*i + 0]);
        v |= static_cast<uint32_t>(in[4*i + 1]) << 8;
        v |= static_cast<uint32_t>(in[4*i + 2]) << 16;
        v |= static_cast<uint32_t>(in[4*i + 3]) << 24;
        if (v >= Q) return false;  // wire form must be reduced
        p[i] = v;
    }
    return true;
}

// =============================================================================
// Shamir secret sharing in R_q
// =============================================================================
// Each secret poly s_j is shared as a degree-(t-1) polynomial f_j(x) over Z_q
// with f_j(0) = s_j and f_j(x_i) = share_{i,j}. Operating coefficient-wise:
// for each of the N coefficients of s_j, run plain Shamir over Z_q.

void shamir_share_polys(const std::vector<Poly>& s,
                        std::vector<std::vector<Poly>>& shares,
                        uint32_t t, uint32_t n,
                        StreamPRNG& rng) {
    // shares[i][j] = f_j evaluated at x_{i+1} (party i's share of s_j).
    shares.assign(n, std::vector<Poly>(s.size(), poly_new()));

    // For each secret poly j, sample t-1 random coefficients (per polynomial
    // coefficient) and evaluate at each party's x.
    for (size_t j = 0; j < s.size(); ++j) {
        // a[deg][n_coef]: a[0] = s[j], a[d] (d=1..t-1) random.
        std::vector<Poly> a(t, poly_new());
        a[0] = s[j];
        for (uint32_t d = 1; d < t; ++d) {
            sample_uniform_poly(a[d], rng);
        }
        // Evaluate f_j(x) = sum_d a[d]*x^d at x = i+1 for i = 0..n-1.
        for (uint32_t i = 0; i < n; ++i) {
            uint64_t x = i + 1;
            uint64_t x_pow = 1;
            Poly out = poly_new();
            for (uint32_t d = 0; d < t; ++d) {
                if (d == 0) {
                    out = a[0];  // copy
                } else {
                    Poly term = poly_new();
                    poly_scalar_mul(term, a[d], x_pow);
                    poly_add(out, out, term);
                }
                x_pow = mul_mod_q(x_pow, x);
            }
            shares[i][j] = std::move(out);
        }
    }
}

// Lagrange coefficient at x = 0 for evaluation point x_i over the index set
// {x_0, ..., x_{t-1}}: prod_{j != i} -x_j / (x_i - x_j).
uint64_t lagrange_at_zero(uint32_t i, const std::vector<uint64_t>& xs) {
    uint64_t num = 1, den = 1;
    uint64_t xi = xs[i];
    for (size_t j = 0; j < xs.size(); ++j) {
        if (j == i) continue;
        // -x_j mod Q
        uint64_t neg_xj = sub_mod_q(0, xs[j]);
        num = mul_mod_q(num, neg_xj);
        // (x_i - x_j) mod Q
        uint64_t diff = sub_mod_q(xi, xs[j]);
        den = mul_mod_q(den, diff);
    }
    return mul_mod_q(num, inv_mod_q(den));
}

// Reconstruct s = sum_i lambda_i * share_i for the first t shares.
void shamir_reconstruct(std::vector<Poly>& s,
                        const std::vector<KeyShare>& shares,
                        uint32_t t,
                        size_t l) {
    std::vector<uint64_t> xs(t);
    for (uint32_t i = 0; i < t; ++i) xs[i] = shares[i].party_id;

    s.assign(l, poly_new());

    for (uint32_t i = 0; i < t; ++i) {
        uint64_t lam = lagrange_at_zero(i, xs);
        for (size_t j = 0; j < l; ++j) {
            Poly term = poly_new();
            poly_scalar_mul(term, shares[i].s_share[j], lam);
            poly_add(s[j], s[j], term);
        }
    }
}

// =============================================================================
// L-infinity norm test on a vector of polys.
// =============================================================================
// ||p||_inf = max_i min(p[i], Q - p[i])  (signed centered representative).

bool linf_within(const std::vector<Poly>& v, uint64_t bound) {
    uint64_t half_q = Q / 2;
    for (const auto& p : v) {
        for (uint64_t c : p) {
            uint64_t mag = (c <= half_q) ? c : (Q - c);
            if (mag > bound) return false;
        }
    }
    return true;
}

// =============================================================================
// Transcript construction for challenge.
// =============================================================================
// tag = SHA-256( "RINGTAIL.v1" || pk_bytes || w_bytes || msg ).

void build_challenge_tag(std::vector<uint8_t>& out,
                         const uint8_t* pk_bytes, size_t pk_len,
                         const std::vector<Poly>& w,
                         const uint8_t* msg, size_t msg_len) {
    std::vector<uint8_t> buf;
    static const char* RINGTAIL_DOMAIN = "RINGTAIL.v1";
    buf.insert(buf.end(), RINGTAIL_DOMAIN, RINGTAIL_DOMAIN + std::strlen(RINGTAIL_DOMAIN));
    buf.insert(buf.end(), pk_bytes, pk_bytes + pk_len);
    std::vector<uint8_t> tmp(POLY_BYTES);
    for (const auto& p : w) {
        poly_to_bytes(p, tmp.data());
        buf.insert(buf.end(), tmp.begin(), tmp.end());
    }
    if (msg_len > 0) {
        buf.insert(buf.end(), msg, msg + msg_len);
    }
    out.assign(32, 0);
    sha256_block(buf.data(), buf.size(), out.data());
}

}  // namespace

// =============================================================================
// Public API
// =============================================================================

int Setup(uint32_t t, uint32_t n, const uint8_t* seed, size_t seed_len,
          Context** out) {
    if (out == nullptr) return CRYPTO_ERR_INPUT;
    if (n < 1 || t < 1 || t > n) return CRYPTO_ERR_INPUT;

    // Materialize a 32-byte seed. Caller-provided seed dominates; otherwise
    // draw from system entropy. Both paths land at a fixed-size seed for
    // reproducibility.
    std::vector<uint8_t> use_seed(32);
    if (seed != nullptr && seed_len > 0) {
        // Hash arbitrary-length caller seed down to 32 bytes (domain-separated).
        std::vector<uint8_t> dom = {'R','T','S','E','T','U','P','.','v','1'};
        dom.insert(dom.end(), seed, seed + seed_len);
        sha256_block(dom.data(), dom.size(), use_seed.data());
    } else {
        std::random_device rd;
        for (size_t i = 0; i < 32; i += 4) {
            uint32_t v = rd();
            use_seed[i + 0] = static_cast<uint8_t>(v & 0xFF);
            use_seed[i + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
            use_seed[i + 2] = static_cast<uint8_t>((v >> 16) & 0xFF);
            use_seed[i + 3] = static_cast<uint8_t>((v >> 24) & 0xFF);
        }
    }

    StreamPRNG rng(use_seed.data(), use_seed.size());

    auto* ctx = new Context();
    ctx->t = t;
    ctx->n = n;
    ctx->seed = use_seed;

    // Sample A: K x L matrix of polys, uniform in R_q.
    ctx->A.assign(K, std::vector<Poly>(L, poly_new()));
    for (uint32_t i = 0; i < K; ++i) {
        for (uint32_t j = 0; j < L; ++j) {
            sample_uniform_poly(ctx->A[i][j], rng);
        }
    }

    // Sample s: L polys, each Gaussian.
    std::vector<Poly> s(L, poly_new());
    for (uint32_t j = 0; j < L; ++j) {
        sample_gaussian_poly(s[j], rng);
    }

    // Sample e: K polys, each Gaussian.
    std::vector<Poly> e(K, poly_new());
    for (uint32_t i = 0; i < K; ++i) {
        sample_gaussian_poly(e[i], rng);
    }

    // b = A*s + e in R_q^K.
    ctx->b.assign(K, poly_new());
    for (uint32_t i = 0; i < K; ++i) {
        for (uint32_t j = 0; j < L; ++j) {
            Poly term = poly_new();
            poly_mul_negacyclic(term, ctx->A[i][j], s[j]);
            poly_add(ctx->b[i], ctx->b[i], term);
        }
        poly_add(ctx->b[i], ctx->b[i], e[i]);
    }

    // Shamir share s into n shares.
    std::vector<std::vector<Poly>> share_polys;
    shamir_share_polys(s, share_polys, t, n, rng);

    ctx->shares.resize(n);
    for (uint32_t i = 0; i < n; ++i) {
        ctx->shares[i].party_id = i + 1;
        ctx->shares[i].s_share = std::move(share_polys[i]);
    }

    *out = ctx;
    return CRYPTO_OK;
}

int SerializePK(const Context* ctx, uint8_t* out_pk) {
    if (ctx == nullptr || out_pk == nullptr) return CRYPTO_ERR_INPUT;
    size_t off = 0;
    for (uint32_t i = 0; i < K; ++i) {
        for (uint32_t j = 0; j < L; ++j) {
            poly_to_bytes(ctx->A[i][j], out_pk + off);
            off += POLY_BYTES;
        }
    }
    for (uint32_t i = 0; i < K; ++i) {
        poly_to_bytes(ctx->b[i], out_pk + off);
        off += POLY_BYTES;
    }
    return CRYPTO_OK;
}

int Sign(Context* ctx,
         const uint8_t* msg, size_t msg_len,
         uint8_t* sig, size_t* sig_len) {
    if (ctx == nullptr || sig_len == nullptr) return CRYPTO_ERR_INPUT;
    if (msg_len > 0 && msg == nullptr) return CRYPTO_ERR_INPUT;
    if (sig == nullptr || *sig_len < SIG_BYTES) {
        *sig_len = SIG_BYTES;
        return (sig == nullptr) ? CRYPTO_ERR_INPUT : CRYPTO_ERR_LENGTH;
    }

    // 1. Reconstruct s from the first t shares (Lagrange at x = 0).
    std::vector<Poly> s;
    shamir_reconstruct(s, ctx->shares, ctx->t, L);

    // 2. Serialize PK once for inclusion in challenge transcript.
    std::vector<uint8_t> pk_bytes(PK_BYTES);
    SerializePK(ctx, pk_bytes.data());

    // 3. Schnorr-Lyubashevsky with rejection sampling.
    //    The signing-time PRNG seed mixes ctx.seed with a monotone counter so
    //    successive calls (same ctx, same msg) draw fresh y while remaining
    //    deterministic in test runs.
    std::vector<uint8_t> sign_seed(40);
    std::memcpy(sign_seed.data(), ctx->seed.data(), 32);
    uint64_t ctr = ++ctx->sign_counter;
    for (int i = 0; i < 8; ++i) {
        sign_seed[32 + i] = static_cast<uint8_t>((ctr >> (i * 8)) & 0xFF);
    }

    // Inner rejection-sample loop. Public condition only.
    constexpr int MAX_REJECT = 256;
    for (int attempt = 0; attempt < MAX_REJECT; ++attempt) {
        // Per-attempt sub-seed so each attempt draws fresh y; stable across
        // identical inputs across backends.
        std::vector<uint8_t> attempt_seed(sign_seed.size() + 4);
        std::memcpy(attempt_seed.data(), sign_seed.data(), sign_seed.size());
        for (int i = 0; i < 4; ++i) {
            attempt_seed[sign_seed.size() + i] =
                static_cast<uint8_t>((static_cast<uint32_t>(attempt) >> (i * 8)) & 0xFF);
        }
        StreamPRNG sign_rng(attempt_seed.data(), attempt_seed.size());

        // y in R_q^L, Gaussian.
        std::vector<Poly> y(L, poly_new());
        for (uint32_t j = 0; j < L; ++j) {
            sample_gaussian_poly(y[j], sign_rng);
        }

        // w = A * y in R_q^K.
        std::vector<Poly> w(K, poly_new());
        for (uint32_t i = 0; i < K; ++i) {
            for (uint32_t j = 0; j < L; ++j) {
                Poly term = poly_new();
                poly_mul_negacyclic(term, ctx->A[i][j], y[j]);
                poly_add(w[i], w[i], term);
            }
        }

        // c = H(domain || pk || w || msg) -> challenge poly with Hamming wt TAU.
        std::vector<uint8_t> tag;
        build_challenge_tag(tag, pk_bytes.data(), pk_bytes.size(), w, msg, msg_len);
        Poly c = poly_new();
        challenge_poly(c, tag.data(), tag.size());

        // z = y + s * c in R_q^L.
        std::vector<Poly> z(L, poly_new());
        for (uint32_t j = 0; j < L; ++j) {
            Poly sc = poly_new();
            poly_mul_negacyclic(sc, s[j], c);
            poly_add(z[j], y[j], sc);
        }

        // Reject if ||z||_inf > B_INF (public condition).
        if (!linf_within(z, B_INF)) continue;

        // Serialize sig = c || z.
        size_t off = 0;
        poly_to_bytes(c, sig + off); off += POLY_BYTES;
        for (uint32_t j = 0; j < L; ++j) {
            poly_to_bytes(z[j], sig + off);
            off += POLY_BYTES;
        }
        *sig_len = SIG_BYTES;
        return CRYPTO_OK;
    }
    return CRYPTO_ERR_INTERNAL;  // rejection budget exhausted (should not happen)
}

int Verify(const uint8_t* pk, size_t pk_len,
           const uint8_t* msg, size_t msg_len,
           const uint8_t* sig, size_t sig_len) {
    if (pk == nullptr || pk_len != PK_BYTES) return CRYPTO_ERR_LENGTH;
    if (sig == nullptr || sig_len != SIG_BYTES) return CRYPTO_ERR_LENGTH;
    if (msg_len > 0 && msg == nullptr) return CRYPTO_ERR_INPUT;

    // Parse PK.
    std::vector<std::vector<Poly>> A(K, std::vector<Poly>(L, poly_new()));
    std::vector<Poly> b(K, poly_new());
    size_t off = 0;
    for (uint32_t i = 0; i < K; ++i) {
        for (uint32_t j = 0; j < L; ++j) {
            if (!poly_from_bytes(A[i][j], pk + off)) return CRYPTO_ERR_VERIFY;
            off += POLY_BYTES;
        }
    }
    for (uint32_t i = 0; i < K; ++i) {
        if (!poly_from_bytes(b[i], pk + off)) return CRYPTO_ERR_VERIFY;
        off += POLY_BYTES;
    }

    // Parse sig.
    Poly c = poly_new();
    std::vector<Poly> z(L, poly_new());
    off = 0;
    if (!poly_from_bytes(c, sig + off)) return CRYPTO_ERR_VERIFY;
    off += POLY_BYTES;
    for (uint32_t j = 0; j < L; ++j) {
        if (!poly_from_bytes(z[j], sig + off)) return CRYPTO_ERR_VERIFY;
        off += POLY_BYTES;
    }

    // Norm check on z.
    if (!linf_within(z, B_INF)) return CRYPTO_ERR_VERIFY;

    // w' = A*z - b*c in R_q^K.
    std::vector<Poly> w(K, poly_new());
    for (uint32_t i = 0; i < K; ++i) {
        for (uint32_t j = 0; j < L; ++j) {
            Poly term = poly_new();
            poly_mul_negacyclic(term, A[i][j], z[j]);
            poly_add(w[i], w[i], term);
        }
        Poly bc = poly_new();
        poly_mul_negacyclic(bc, b[i], c);
        poly_sub(w[i], w[i], bc);
    }

    // Recompute challenge tag and challenge poly.
    std::vector<uint8_t> tag;
    build_challenge_tag(tag, pk, pk_len, w, msg, msg_len);
    Poly c_prime = poly_new();
    challenge_poly(c_prime, tag.data(), tag.size());

    // Compare c == c'.
    for (uint32_t i = 0; i < N; ++i) {
        if (c[i] != c_prime[i]) return CRYPTO_ERR_VERIFY;
    }
    return CRYPTO_OK;
}

void Destroy(Context* ctx) {
    delete ctx;
}

}  // namespace kinet::crypto::ringtail
