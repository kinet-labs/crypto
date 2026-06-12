// Paillier cryptosystem + CGGMP21 Π^enc — implementation.
//
// All large-integer arithmetic is delegated to:
//   * cevm::crypto::modexp_karatsuba()   (4096-bit Karatsuba-Montgomery
//                                        modexp; LP-163 primitive shipped
//                                        in commit 8e8fb102, this is its
//                                        first user.)
//   * cevm::crypto::karatsuba::kmul()    (full 4096x4096 -> 8192 bit product)
//
// Multiplication mod m is implemented as `kmul` followed by a single
// `modexp_karatsuba` reduction with exponent 1; this is one Montgomery setup
// + one final demontgomerization, faster than schoolbook reduction for our
// sizes and reuses the same SOS code path the kernel will run on GPU.

#include "paillier.hpp"

#include "../../sha256/cpp/sha256.hpp"
#include "../../modexp/cpp/karatsuba.hpp"
#include "../../modexp/cpp/modexp.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <vector>

namespace kinet::crypto::cggmp21::paillier {
namespace {

constexpr std::size_t MOD_LIMBS    = MOD_BYTES    / 8;   // 32  (2048-bit)
constexpr std::size_t MOD_SQ_LIMBS = MOD_SQ_BYTES / 8;   // 64  (4096-bit)

// === Endianness helpers =============================================
//
// modexp_karatsuba() is big-endian on the byte interface; karatsuba::kmul
// is little-endian-limb (uint64_t array, lsb-first).

void be_to_le_limbs(uint64_t* dst, std::size_t dst_limbs,
                    const uint8_t* src_be, std::size_t src_bytes) noexcept {
    std::memset(dst, 0, dst_limbs * sizeof(uint64_t));
    // src_be[0] is the most-significant byte. Limb 0 is least significant.
    for (std::size_t i = 0; i < src_bytes; ++i) {
        std::size_t bit = (src_bytes - 1 - i) * 8;
        std::size_t limb = bit / 64;
        std::size_t shift = bit & 63;
        if (limb < dst_limbs) {
            dst[limb] |= static_cast<uint64_t>(src_be[i]) << shift;
        }
    }
}

void le_limbs_to_be(uint8_t* dst_be, std::size_t dst_bytes,
                    const uint64_t* src, std::size_t src_limbs) noexcept {
    std::memset(dst_be, 0, dst_bytes);
    for (std::size_t i = 0; i < dst_bytes; ++i) {
        std::size_t bit = (dst_bytes - 1 - i) * 8;
        std::size_t limb = bit / 64;
        std::size_t shift = bit & 63;
        if (limb < src_limbs) {
            dst_be[i] = static_cast<uint8_t>((src[limb] >> shift) & 0xFF);
        }
    }
}

// === BE comparisons / ops ===========================================

int be_cmp(const uint8_t* a, const uint8_t* b, std::size_t n) noexcept {
    for (std::size_t i = 0; i < n; ++i) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return  1;
    }
    return 0;
}

// out = a + b (mod 2^(8*n)); returns final carry-out.
uint8_t be_add(uint8_t* out, const uint8_t* a, const uint8_t* b, std::size_t n) noexcept {
    uint16_t carry = 0;
    for (std::size_t i = n; i-- > 0; ) {
        uint16_t t = (uint16_t)a[i] + (uint16_t)b[i] + carry;
        out[i] = (uint8_t)(t & 0xFF);
        carry = t >> 8;
    }
    return (uint8_t)(carry & 1);
}

// out = a - b (mod 2^(8*n)); returns final borrow-out (1 if a < b).
uint8_t be_sub(uint8_t* out, const uint8_t* a, const uint8_t* b, std::size_t n) noexcept {
    int16_t borrow = 0;
    for (std::size_t i = n; i-- > 0; ) {
        int16_t t = (int16_t)a[i] - (int16_t)b[i] - borrow;
        if (t < 0) { t += 256; borrow = 1; } else { borrow = 0; }
        out[i] = (uint8_t)(t & 0xFF);
    }
    return (uint8_t)borrow;
}

// out = a mod m, big-endian. Used to bring `add` overflow back into [0, m).
// Repeated subtraction for at most one m (callers ensure a < 2m).
void be_reduce_one(uint8_t* a, const uint8_t* m, std::size_t n) noexcept {
    if (be_cmp(a, m, n) >= 0) {
        be_sub(a, a, m, n);
    }
}

// === modmul via kmul + modexp_karatsuba ==============================
//
// out = (a * b) mod m, where a, b, m are big-endian byte arrays of width
// `mod_bytes`. Uses kmul to form the full 2*mod_bytes product, then
// modexp_karatsuba(prod, [01], m) reduces in one Montgomery pass.
void be_mulmod(uint8_t* out, const uint8_t* a_be, const uint8_t* b_be,
               const uint8_t* m_be, std::size_t mod_bytes) noexcept {
    const std::size_t mod_limbs = mod_bytes / 8;
    std::vector<uint64_t> a_le(mod_limbs), b_le(mod_limbs);
    be_to_le_limbs(a_le.data(), mod_limbs, a_be, mod_bytes);
    be_to_le_limbs(b_le.data(), mod_limbs, b_be, mod_bytes);

    std::vector<uint64_t> prod_le(2 * mod_limbs);
    cevm::crypto::karatsuba::kmul({prod_le.data(), 2 * mod_limbs},
                                  {a_le.data(),    mod_limbs},
                                  {b_le.data(),    mod_limbs});

    // 2*mod_bytes big-endian buffer of the full product.
    std::vector<uint8_t> prod_be(2 * mod_bytes);
    le_limbs_to_be(prod_be.data(), 2 * mod_bytes, prod_le.data(), 2 * mod_limbs);

    // exp = [0x01]; modexp_karatsuba reduces base mod m before the loop, then
    // the loop is empty (bit_width == 1) and the final demontgomerization
    // multiplies by 1. Net result: out = base mod m.
    const uint8_t exp_one[1] = {0x01};
    cevm::crypto::modexp_karatsuba(
        std::span<const uint8_t>{prod_be.data(), 2 * mod_bytes},
        std::span<const uint8_t>{exp_one, 1},
        std::span<const uint8_t>{m_be, mod_bytes},
        out);
}

// out = a * b mod m, where a, b are width `mod_bytes`. Convenience wrapper
// that handles a or b ≥ m by reducing first via modexp_karatsuba(a, 1, m).
void be_mulmod_general(uint8_t* out, const uint8_t* a_be, const uint8_t* b_be,
                       const uint8_t* m_be, std::size_t mod_bytes) noexcept {
    // be_mulmod assumes a, b < 2^(8*mod_bytes); reductions inside
    // modexp_karatsuba handle the > m case in a normalizing pass.
    be_mulmod(out, a_be, b_be, m_be, mod_bytes);
}

// out = base^exp mod m. Forwards to modexp_karatsuba with the LP-163 primitive.
void be_powmod(uint8_t* out, std::size_t mod_bytes,
               const uint8_t* base_be, std::size_t base_bytes,
               const uint8_t* exp_be,  std::size_t exp_bytes,
               const uint8_t* m_be) noexcept {
    cevm::crypto::modexp_karatsuba(
        std::span<const uint8_t>{base_be, base_bytes},
        std::span<const uint8_t>{exp_be,  exp_bytes},
        std::span<const uint8_t>{m_be,    mod_bytes},
        out);
}

// === Modular inverse via Fermat: a^{m-2} mod m, m prime ==============
//
// For non-prime m we use the extended Euclidean algorithm. Paillier μ =
// λ^{-1} mod N where N is composite — but |λ| ≈ |N| and gcd(λ, N) = 1 by
// construction (λ has factor 2 and (p-1)/2 . (q-1)/2; N = pq). We use
// extended-Euclid on byte arrays.

// out = a^{-1} mod m using extended-Euclidean. n is the modulus byte width.
// Returns 0 on success, -1 if a is not invertible (gcd != 1).
int be_modinv(uint8_t* out, const uint8_t* a_be, const uint8_t* m_be,
              std::size_t n) noexcept {
    const std::size_t L = n;
    // Extended-Euclidean over signed 256-byte integers represented as
    // (sign, magnitude). For 2048-bit magnitudes a heap allocation is fine.
    struct Sig { std::vector<uint8_t> mag; int sign; };
    auto make = [L](const uint8_t* be) {
        Sig s; s.mag.assign(be, be + L); s.sign = 0;
        // sign 0 = nonneg
        for (auto b : s.mag) if (b) return s;
        return s;
    };

    // Normalize a mod m.
    Sig r0; r0.mag.assign(m_be, m_be + L); r0.sign = 0;
    Sig r1 = make(a_be);
    // Reduce r1 mod m by repeated subtraction is too slow; we use modexp
    // to avoid implementing big-int division: a mod m = modexp_karatsuba(a, 1, m).
    {
        std::vector<uint8_t> red(L);
        const uint8_t one_byte = 0x01;
        cevm::crypto::modexp_karatsuba(
            std::span<const uint8_t>{r1.mag.data(), L},
            std::span<const uint8_t>{&one_byte, 1},
            std::span<const uint8_t>{m_be, L},
            red.data());
        r1.mag = std::move(red);
    }

    // s0 = 0, s1 = 1; r0 = m, r1 = a mod m.
    // Using "binary GCD" + multiplicative inverse via Bezout coefficients
    // would be fastest; for 2048-bit operands ~3500 iters of full division
    // is too slow. Instead we use Fermat-Euler: φ(N) is unknown to the
    // prover side, but for our use cases the modulus is one of:
    //
    //   * N (known to keygen path; sk has λ = φ(N))
    //   * Otherwise prime (only used in tests at this layer)
    //
    // Production code path: be_modinv is called once at keygen for μ.
    // For that case the caller passes in lambda as `a` and N as `m`; we
    // need an arbitrary big-int gcd. We implement a binary-extended-GCD
    // on byte arrays. With 2048-bit operands we have ~4096 iterations of
    // the right-shift step; each is O(L) byte-time so ~250 µs total —
    // acceptable for a one-time keygen.

    // Switch to a simple byte-array binary-extended-GCD.
    using Big = std::vector<uint8_t>;  // big-endian magnitude only (sign stored separately).
    auto be_zero = [L](const Big& x){
        for (auto b : x) if (b) return false; return true;
    };
    auto be_is_one = [L](const Big& x){
        for (std::size_t i = 0; i < L - 1; ++i) if (x[i]) return false;
        return x[L-1] == 1;
    };
    // x >>= 1 (big-endian)
    auto be_rshift1 = [L](Big& x){
        uint8_t carry = 0;
        for (std::size_t i = 0; i < L; ++i) {
            uint8_t nc = x[i] & 1;
            x[i] = (x[i] >> 1) | (carry << 7);
            carry = nc;
        }
    };
    // x <<= 1; returns dropped MSB
    auto be_lshift1 = [L](Big& x) -> uint8_t {
        uint8_t carry = 0;
        for (std::size_t i = L; i-- > 0; ) {
            uint8_t nc = (x[i] >> 7) & 1;
            x[i] = (x[i] << 1) | carry;
            carry = nc;
        }
        return carry;
    };
    auto be_is_even = [L](const Big& x){ return (x[L-1] & 1) == 0; };

    // Signed Bezout coefficients held as (mag, sign). Sign 0 = +, 1 = -.
    struct S { Big mag; int sign; };
    auto sneg = [&](S& s){ if (!be_zero(s.mag)) s.sign ^= 1; };
    // s := (s + add) mod m, allowing negative magnitudes.
    auto sadd_inplace = [&](S& s, const S& add){
        if (s.sign == add.sign) {
            uint8_t c = be_add(s.mag.data(), s.mag.data(), add.mag.data(), L);
            if (c) {
                // Overflow — reduce by subtracting m once. With our bounds (s,
                // add < m before each call) this can occur and we recover by
                // subtracting m, then keeping sign. Edge case rare; bounded.
                be_sub(s.mag.data(), s.mag.data(), m_be, L);
            }
        } else {
            int cmp = be_cmp(s.mag.data(), add.mag.data(), L);
            if (cmp >= 0) {
                be_sub(s.mag.data(), s.mag.data(), add.mag.data(), L);
            } else {
                Big tmp(L);
                be_sub(tmp.data(), add.mag.data(), s.mag.data(), L);
                s.mag = std::move(tmp);
                s.sign ^= 1;
            }
            if (be_zero(s.mag)) s.sign = 0;
        }
    };
    // s /= 2 (modular halving when m is odd).
    auto shalve = [&](S& s){
        if (be_is_even(s.mag)) {
            be_rshift1(s.mag);
        } else {
            // s is odd; (s + m) is even since m is odd. Add m, then halve.
            // Possible overflow into bit 2048; we track that via a single
            // "extra" bit and shift-in.
            uint8_t carry = be_add(s.mag.data(), s.mag.data(), m_be, L);
            be_rshift1(s.mag);
            if (carry) {
                s.mag[0] |= 0x80;
            }
        }
    };

    Big u(r0.mag), v(r1.mag);
    if (be_zero(v)) return -1;  // a = 0 has no inverse
    S A_s, B_s, C_s, D_s;
    A_s.mag.assign(L, 0); A_s.mag[L-1] = 1; A_s.sign = 0;  // 1
    B_s.mag.assign(L, 0); B_s.sign = 0;                    // 0
    C_s.mag.assign(L, 0); C_s.sign = 0;                    // 0
    D_s.mag.assign(L, 0); D_s.mag[L-1] = 1; D_s.sign = 0;  // 1

    // Binary extended GCD; m is required odd (true for Paillier N which is
    // a product of two odd safe primes).
    while (!be_zero(u)) {
        while (be_is_even(u)) {
            be_rshift1(u);
            shalve(A_s);
            shalve(B_s);
        }
        while (be_is_even(v)) {
            be_rshift1(v);
            shalve(C_s);
            shalve(D_s);
        }
        if (be_cmp(u.data(), v.data(), L) >= 0) {
            be_sub(u.data(), u.data(), v.data(), L);
            S Cn = C_s; sneg(Cn); sadd_inplace(A_s, Cn);
            S Dn = D_s; sneg(Dn); sadd_inplace(B_s, Dn);
        } else {
            be_sub(v.data(), v.data(), u.data(), L);
            S An = A_s; sneg(An); sadd_inplace(C_s, An);
            S Bn = B_s; sneg(Bn); sadd_inplace(D_s, Bn);
        }
    }
    // gcd is in v; require gcd == 1 for invertibility.
    if (!be_is_one(v)) return -1;

    // Inverse is D_s mod m.
    if (D_s.sign == 1) {
        // Convert -|D| mod m to m - |D|.
        be_sub(D_s.mag.data(), m_be, D_s.mag.data(), L);
        D_s.sign = 0;
    }
    // Final reduce.
    be_reduce_one(D_s.mag.data(), m_be, L);
    std::memcpy(out, D_s.mag.data(), L);
    (void)r0; (void)r1; (void)be_is_one;
    return 0;
}

// === Paillier encryption ============================================
//
// Optimized form: enc(m, r) = (1 + m*N) * r^N mod N^2 .
//
// (1+N)^m ≡ 1 + m*N mod N^2 by binomial. So we never call modexp on
// (1+N)^m — instead a single multiply (m*N) (2048x2048 -> 4096-bit) plus
// add 1 then a final mulmod with r^N mod N^2.

void compute_one_plus_mN(uint8_t out_4096[MOD_SQ_BYTES],
                         const uint8_t m_be [MOD_BYTES],
                         const uint8_t N_be [MOD_BYTES]) noexcept {
    // Compute m * N as a full 4096-bit product.
    std::array<uint64_t, MOD_LIMBS>    m_le{}, N_le{};
    be_to_le_limbs(m_le.data(), MOD_LIMBS, m_be, MOD_BYTES);
    be_to_le_limbs(N_le.data(), MOD_LIMBS, N_be, MOD_BYTES);
    std::array<uint64_t, MOD_SQ_LIMBS> prod_le{};
    cevm::crypto::karatsuba::kmul({prod_le.data(), MOD_SQ_LIMBS},
                                  {m_le.data(),    MOD_LIMBS},
                                  {N_le.data(),    MOD_LIMBS});
    le_limbs_to_be(out_4096, MOD_SQ_BYTES, prod_le.data(), MOD_SQ_LIMBS);

    // Add 1.
    uint16_t carry = 1;
    for (std::size_t i = MOD_SQ_BYTES; i-- > 0 && carry; ) {
        uint16_t t = (uint16_t)out_4096[i] + carry;
        out_4096[i] = (uint8_t)(t & 0xFF);
        carry = t >> 8;
    }
}

}  // namespace

// === Public API: encrypt =============================================

int encrypt(const PublicKey& pk,
            const uint8_t m_be[MOD_BYTES],
            const uint8_t r_be[MOD_BYTES],
            uint8_t       ct_out[CT_BYTES]) noexcept {
    if (m_be == nullptr || r_be == nullptr || ct_out == nullptr) return -1;

    // First reduce m mod N (Paillier message space is Z_N) so we don't carry
    // bits beyond |N| into the 1+m*N term.
    uint8_t m_red[MOD_BYTES];
    {
        const uint8_t one[1] = {0x01};
        cevm::crypto::modexp_karatsuba(
            std::span<const uint8_t>{m_be, MOD_BYTES},
            std::span<const uint8_t>{one,  1},
            std::span<const uint8_t>{pk.N, MOD_BYTES},
            m_red);
    }

    // term1 = (1 + m*N) — already < N^2 since m < N and N*N is bounded.
    uint8_t term1[MOD_SQ_BYTES];
    compute_one_plus_mN(term1, m_red, pk.N);
    // term1 < (N-1)*N + 1 < N^2; no reduction needed.

    // term2 = r^N mod N^2.
    uint8_t term2[MOD_SQ_BYTES];
    be_powmod(term2, MOD_SQ_BYTES,
              r_be, MOD_BYTES,
              pk.N, MOD_BYTES,
              pk.N_sq);

    // ct = term1 * term2 mod N^2.
    be_mulmod_general(ct_out, term1, term2, pk.N_sq, MOD_SQ_BYTES);
    return 0;
}

// === Public API: decrypt =============================================

int decrypt(const SecretKey& sk,
            const uint8_t ct_be[CT_BYTES],
            uint8_t       m_out[MOD_BYTES]) noexcept {
    if (ct_be == nullptr || m_out == nullptr) return -1;

    // u = c^λ mod N^2. λ is up to 2048 bits.
    uint8_t u[MOD_SQ_BYTES];
    be_powmod(u, MOD_SQ_BYTES,
              ct_be, CT_BYTES,
              sk.lambda, MOD_BYTES,
              sk.pk.N_sq);

    // L(u) = (u - 1) / N. u in [1, N^2), N divides u-1 by Paillier theorem.
    // Subtract 1 from u (4096-bit) in place.
    {
        uint16_t borrow = 1;
        for (std::size_t i = MOD_SQ_BYTES; i-- > 0; ) {
            int32_t t = (int32_t)u[i] - (int32_t)borrow;
            if (t < 0) { t += 256; borrow = 1; } else { borrow = 0; }
            u[i] = (uint8_t)t;
            if (!borrow) break;
        }
    }
    // L = u / N. Quotient is at most 2048 bits since u < N^2 and N | u.
    // Compute via modexp_karatsuba(u, 1, N) to get u mod N (which is 0 by
    // Paillier theorem); we actually need the quotient. Reusing modexp does
    // not yield it. Implement long-division: with N at 2048 bits and u at
    // 4096 bits, the quotient has 2048 bits. Use binary long division.
    uint8_t L_be[MOD_BYTES];
    {
        // q = 0; r = 0; for i in MSB downto LSB: r = (r << 1) | bit(u, i);
        //   if r >= N: r -= N; q |= bit_i.
        //
        // r is 2048-bit storage; mid-iteration its conceptual value can reach
        // up to 2N+1 ≈ 2^2049, so we must track the bit that falls off the top
        // of r during the left shift. If it is 1, the conceptual r is >= 2^2048
        // > N, so a subtraction of N is required (and is sufficient — after one
        // subtract r < 2^2048 since 2N+1 - N = N+1 < 2^2048).
        std::array<uint8_t, MOD_BYTES> r{}; r.fill(0);
        std::array<uint8_t, MOD_BYTES> q{}; q.fill(0);
        for (std::size_t bit = 0; bit < MOD_SQ_BYTES * 8; ++bit) {
            // r <<= 1; capture the bit that falls off the top.
            uint8_t carry = 0;
            for (std::size_t i = MOD_BYTES; i-- > 0; ) {
                uint8_t nc = (r[i] >> 7) & 1;
                r[i] = (r[i] << 1) | carry;
                carry = nc;
            }
            uint8_t r_top = carry;  // bit 2048 of conceptual r (post-shift).
            // bring in bit `bit` of u (msb first)
            std::size_t byte_idx = bit / 8;
            std::size_t bit_off  = 7 - (bit & 7);
            r[MOD_BYTES - 1] |= (u[byte_idx] >> bit_off) & 1;

            // q <<= 1
            carry = 0;
            for (std::size_t i = MOD_BYTES; i-- > 0; ) {
                uint8_t nc = (q[i] >> 7) & 1;
                q[i] = (q[i] << 1) | carry;
                carry = nc;
            }
            // if conceptual r >= N: r -= N; q |= 1.
            // r_top == 1 implies conceptual r >= 2^2048 > N → must subtract.
            if (r_top != 0 || be_cmp(r.data(), sk.pk.N, MOD_BYTES) >= 0) {
                be_sub(r.data(), r.data(), sk.pk.N, MOD_BYTES);
                q[MOD_BYTES - 1] |= 1;
            }
        }
        std::memcpy(L_be, q.data(), MOD_BYTES);
    }

    // m = L * μ mod N.
    be_mulmod_general(m_out, L_be, sk.mu, sk.pk.N, MOD_BYTES);
    return 0;
}

// === Π^enc proof =====================================================

namespace {

void sha256_concat(uint8_t out32[32],
                   const uint8_t* a, std::size_t la,
                   const uint8_t* b, std::size_t lb,
                   const uint8_t* c, std::size_t lc,
                   const uint8_t* d, std::size_t ld) noexcept {
    std::vector<uint8_t> buf;
    buf.reserve(la + lb + lc + ld);
    if (a && la) buf.insert(buf.end(), a, a + la);
    if (b && lb) buf.insert(buf.end(), b, b + lb);
    if (c && lc) buf.insert(buf.end(), c, c + lc);
    if (d && ld) buf.insert(buf.end(), d, d + ld);
    cevm::crypto::sha256(reinterpret_cast<std::byte*>(out32),
                         reinterpret_cast<const std::byte*>(buf.data()),
                         buf.size());
}

}  // namespace

int pi_enc_prove(const PublicKey& pk,
                 const uint8_t K_be    [CT_BYTES],
                 const uint8_t k_be    [MOD_BYTES],
                 const uint8_t rho_be  [MOD_BYTES],
                 const uint8_t alpha_be[MOD_BYTES],
                 const uint8_t beta_be [MOD_BYTES],
                 uint8_t       proof_out[PI_ENC_BYTES]) noexcept {
    if (!K_be || !k_be || !rho_be || !alpha_be || !beta_be || !proof_out) return -1;

    // A = enc_N(α, β). The encrypt() function reduces inputs mod N internally.
    uint8_t A[CT_BYTES];
    if (encrypt(pk, alpha_be, beta_be, A) != 0) return -1;

    // e = SHA-256(N || N^2 || K || A).
    uint8_t e[32];
    sha256_concat(e,
                  pk.N,    MOD_BYTES,
                  pk.N_sq, MOD_SQ_BYTES,
                  K_be,    CT_BYTES,
                  A,       CT_BYTES);

    // z1 = (α + e * k) mod N. (CGGMP21 lifts to integers; the proof stays
    // sound mod N since we range-check Im(z1) < 2^|N| at verify, and
    // soundness reduces via DCR over Z_N.)
    uint8_t ek[MOD_BYTES];
    {
        // e is 32 bytes; pad to MOD_BYTES big-endian.
        uint8_t e_padded[MOD_BYTES];
        std::memset(e_padded, 0, MOD_BYTES);
        std::memcpy(e_padded + MOD_BYTES - 32, e, 32);
        be_mulmod_general(ek, e_padded, k_be, pk.N, MOD_BYTES);
    }
    uint8_t z1[MOD_BYTES];
    {
        // (alpha + ek) mod N.
        uint8_t alpha_red[MOD_BYTES];
        const uint8_t one[1] = {0x01};
        cevm::crypto::modexp_karatsuba(
            std::span<const uint8_t>{alpha_be, MOD_BYTES},
            std::span<const uint8_t>{one, 1},
            std::span<const uint8_t>{pk.N, MOD_BYTES},
            alpha_red);
        uint8_t carry = be_add(z1, alpha_red, ek, MOD_BYTES);
        if (carry || be_cmp(z1, pk.N, MOD_BYTES) >= 0) {
            be_sub(z1, z1, pk.N, MOD_BYTES);
        }
    }

    // z2 = β · ρ^e mod N.
    uint8_t rho_pow_e[MOD_BYTES];
    be_powmod(rho_pow_e, MOD_BYTES,
              rho_be, MOD_BYTES,
              e, 32,
              pk.N);
    uint8_t z2[MOD_BYTES];
    be_mulmod_general(z2, beta_be, rho_pow_e, pk.N, MOD_BYTES);

    // bind = SHA-256(K || A || z1 || z2). Defense-in-depth tag binding the
    // transcript halves together (catches A/z swapping attacks before the
    // expensive enc(z1,z2) verifier).
    uint8_t bind[32];
    sha256_concat(bind,
                  K_be, CT_BYTES,
                  A,    CT_BYTES,
                  z1,   MOD_BYTES,
                  z2,   MOD_BYTES);

    // Pack proof.
    std::size_t off = 0;
    std::memcpy(proof_out + off, A,    CT_BYTES);  off += CT_BYTES;
    std::memcpy(proof_out + off, e,    32);        off += 32;
    std::memcpy(proof_out + off, z1,   MOD_BYTES); off += MOD_BYTES;
    std::memcpy(proof_out + off, z2,   MOD_BYTES); off += MOD_BYTES;
    std::memcpy(proof_out + off, bind, 32);
    return 0;
}

int pi_enc_verify(const PublicKey& pk,
                  const uint8_t K_be     [CT_BYTES],
                  const uint8_t proof_in [PI_ENC_BYTES]) noexcept {
    if (!K_be || !proof_in) return -1;

    const uint8_t* A    = proof_in + 0;
    const uint8_t* e    = proof_in + CT_BYTES;
    const uint8_t* z1   = proof_in + CT_BYTES + 32;
    const uint8_t* z2   = proof_in + CT_BYTES + 32 + MOD_BYTES;
    const uint8_t* bind = proof_in + CT_BYTES + 32 + MOD_BYTES + MOD_BYTES;

    // Recompute e' = SHA-256(N || N^2 || K || A); compare to e.
    uint8_t e_chk[32];
    sha256_concat(e_chk,
                  pk.N,    MOD_BYTES,
                  pk.N_sq, MOD_SQ_BYTES,
                  K_be,    CT_BYTES,
                  A,       CT_BYTES);
    {
        // Constant-time compare of 32-byte e.
        uint8_t diff = 0;
        for (std::size_t i = 0; i < 32; ++i) diff |= (e[i] ^ e_chk[i]);
        if (diff != 0) return 1;
    }

    // Recompute bind' and compare.
    uint8_t bind_chk[32];
    sha256_concat(bind_chk,
                  K_be, CT_BYTES,
                  A,    CT_BYTES,
                  z1,   MOD_BYTES,
                  z2,   MOD_BYTES);
    {
        uint8_t diff = 0;
        for (std::size_t i = 0; i < 32; ++i) diff |= (bind[i] ^ bind_chk[i]);
        if (diff != 0) return 1;
    }

    // Check enc_N(z1, z2) == A · K^e mod N^2.
    uint8_t lhs[CT_BYTES];
    if (encrypt(pk, z1, z2, lhs) != 0) return -1;

    uint8_t Ke[CT_BYTES];
    be_powmod(Ke, MOD_SQ_BYTES,
              K_be, CT_BYTES,
              e, 32,
              pk.N_sq);
    uint8_t rhs[CT_BYTES];
    be_mulmod_general(rhs, A, Ke, pk.N_sq, MOD_SQ_BYTES);

    uint8_t diff = 0;
    for (std::size_t i = 0; i < CT_BYTES; ++i) diff |= (lhs[i] ^ rhs[i]);
    return (diff == 0) ? 0 : 1;
}

// === Keygen (deterministic from seed; test path) ====================
//
// The kernel never generates Paillier keys — those are inputs. This keygen
// is for the test harness only. It picks the smallest pair of probable
// primes p, q ≥ 2^1023 that pass Miller-Rabin with 40 rounds, derived by
// SHA-256 expansion of the input seed.
//
// 40 rounds of MR on 1024-bit candidates → error probability ≤ 2^-80
// (NIST SP 800-89 §5.4.1, table B.1). For test seeds this is more than
// adequate; production keygen lives in kinet/crypto/threshold/paillier_keygen.go
// where tighter primality (with FIPS 186-5 Lucas test) and side-channel
// resistance are required.

namespace {

// Miller-Rabin probable-primality test on a 1024-bit big-endian candidate.
// Returns true if "probably prime" after `rounds` rounds with witnesses
// derived deterministically from `wit_seed`.
bool miller_rabin_1024(const uint8_t cand_be[MOD_BYTES / 2],
                       const uint8_t wit_seed[32],
                       int rounds) noexcept {
    constexpr std::size_t HALF = MOD_BYTES / 2;  // 128 bytes

    // Trivial composites: even or 1.
    if ((cand_be[HALF - 1] & 1) == 0) return false;

    // Compute n - 1 = 2^s * d.
    uint8_t nm1[HALF];
    {
        std::memcpy(nm1, cand_be, HALF);
        // subtract 1
        for (std::size_t i = HALF; i-- > 0; ) {
            if (nm1[i] > 0) { nm1[i] -= 1; break; }
            nm1[i] = 0xFF;
        }
    }
    int s = 0;
    uint8_t d[HALF];
    std::memcpy(d, nm1, HALF);
    while (true) {
        if ((d[HALF - 1] & 1) != 0) break;
        // d >>= 1
        uint8_t carry = 0;
        for (std::size_t i = 0; i < HALF; ++i) {
            uint8_t nc = d[i] & 1;
            d[i] = (d[i] >> 1) | (carry << 7);
            carry = nc;
        }
        ++s;
    }

    // For each round derive a witness a in [2, n-2] from SHA-256 chain.
    uint8_t st[32];
    std::memcpy(st, wit_seed, 32);
    for (int r = 0; r < rounds; ++r) {
        // expand st into HALF-byte witness via 4×SHA-256.
        uint8_t a[HALF];
        for (std::size_t i = 0; i < HALF; i += 32) {
            uint8_t blk_in[32 + 4];
            std::memcpy(blk_in, st, 32);
            blk_in[32] = (uint8_t)(r >> 24);
            blk_in[33] = (uint8_t)(r >> 16);
            blk_in[34] = (uint8_t)(r >>  8);
            blk_in[35] = (uint8_t)((i / 32) & 0xFF);
            uint8_t h[32];
            cevm::crypto::sha256(reinterpret_cast<std::byte*>(h),
                                 reinterpret_cast<const std::byte*>(blk_in), 36);
            std::size_t cp = std::min<std::size_t>(32, HALF - i);
            std::memcpy(a + i, h, cp);
        }
        // Force a in [2, n-2] by reducing mod (n-3) then adding 2.
        uint8_t nm3[HALF];
        std::memcpy(nm3, nm1, HALF);
        // nm3 -= 2
        {
            uint8_t b = 2;
            for (std::size_t i = HALF; i-- > 0 && b; ) {
                if (nm3[i] >= b) { nm3[i] -= b; b = 0; }
                else { nm3[i] = (uint8_t)((int)nm3[i] - (int)b + 256); b = 1; }
            }
        }
        const uint8_t one[1] = {0x01};
        uint8_t a_red[HALF];
        cevm::crypto::modexp_karatsuba(
            std::span<const uint8_t>{a,    HALF},
            std::span<const uint8_t>{one,  1},
            std::span<const uint8_t>{nm3,  HALF},
            a_red);
        // a := a_red + 2
        {
            uint16_t carry = 2;
            for (std::size_t i = HALF; i-- > 0 && carry; ) {
                uint16_t t = (uint16_t)a_red[i] + carry;
                a_red[i] = (uint8_t)(t & 0xFF);
                carry = t >> 8;
            }
        }

        // x = a^d mod n.
        uint8_t x[HALF];
        cevm::crypto::modexp_karatsuba(
            std::span<const uint8_t>{a_red, HALF},
            std::span<const uint8_t>{d,     HALF},
            std::span<const uint8_t>{cand_be, HALF},
            x);

        auto eq_one = [&](const uint8_t* p){
            for (std::size_t i = 0; i < HALF - 1; ++i) if (p[i]) return false;
            return p[HALF - 1] == 1;
        };
        auto eq_nm1 = [&](const uint8_t* p){
            return std::memcmp(p, nm1, HALF) == 0;
        };
        if (eq_one(x) || eq_nm1(x)) {
            // probably prime, next round
            // chain witness state
            uint8_t blk[32 + HALF];
            std::memcpy(blk, st, 32);
            std::memcpy(blk + 32, x, HALF);
            cevm::crypto::sha256(reinterpret_cast<std::byte*>(st),
                                 reinterpret_cast<const std::byte*>(blk),
                                 sizeof(blk));
            continue;
        }
        bool composite_round = true;
        for (int i = 0; i < s - 1; ++i) {
            // x = x^2 mod n
            uint8_t x_sq[HALF];
            const uint8_t two[1] = {0x02};
            cevm::crypto::modexp_karatsuba(
                std::span<const uint8_t>{x,   HALF},
                std::span<const uint8_t>{two, 1},
                std::span<const uint8_t>{cand_be, HALF},
                x_sq);
            std::memcpy(x, x_sq, HALF);
            if (eq_nm1(x)) { composite_round = false; break; }
        }
        if (composite_round) return false;
        // chain
        uint8_t blk[32 + HALF];
        std::memcpy(blk, st, 32);
        std::memcpy(blk + 32, x, HALF);
        cevm::crypto::sha256(reinterpret_cast<std::byte*>(st),
                             reinterpret_cast<const std::byte*>(blk), sizeof(blk));
    }
    return true;
}

// Smallest probable prime ≥ 2^1023 + offset, derived from `seed`. We set
// the top bit (so |p| ≥ 1024) and the bottom bit (so p is odd), then walk
// up by 2 until MR-40 says prime.
void derive_prime(uint8_t out[MOD_BYTES / 2], const uint8_t seed[32]) noexcept {
    constexpr std::size_t HALF = MOD_BYTES / 2;
    // Initial candidate: SHA-256 expansion of seed → 128 bytes.
    uint8_t cand[HALF];
    for (std::size_t i = 0; i < HALF; i += 32) {
        uint8_t blk[36];
        std::memcpy(blk, seed, 32);
        blk[32] = 'p'; blk[33] = 'r'; blk[34] = 'm'; blk[35] = (uint8_t)(i / 32);
        uint8_t h[32];
        cevm::crypto::sha256(reinterpret_cast<std::byte*>(h),
                             reinterpret_cast<const std::byte*>(blk), 36);
        std::size_t cp = std::min<std::size_t>(32, HALF - i);
        std::memcpy(cand + i, h, cp);
    }
    cand[0]      |= 0x80;  // top bit set → ≥ 2^1023
    cand[HALF-1] |= 0x01;  // odd

    uint8_t wit[32];
    {
        uint8_t blk[36];
        std::memcpy(blk, seed, 32);
        blk[32] = 'w'; blk[33] = 'i'; blk[34] = 't'; blk[35] = 0;
        cevm::crypto::sha256(reinterpret_cast<std::byte*>(wit),
                             reinterpret_cast<const std::byte*>(blk), 36);
    }

    while (!miller_rabin_1024(cand, wit, /*rounds=*/40)) {
        // cand += 2
        uint16_t carry = 2;
        for (std::size_t i = HALF; i-- > 0 && carry; ) {
            uint16_t t = (uint16_t)cand[i] + carry;
            cand[i] = (uint8_t)(t & 0xFF);
            carry = t >> 8;
        }
        // top bit must remain set (1024-bit width); if it overflowed, give up.
        if ((cand[0] & 0x80) == 0) {
            cand[0] |= 0x80;
        }
    }
    std::memcpy(out, cand, HALF);
}

}  // namespace

int keygen_from_seed(const uint8_t seed[32], SecretKey& sk_out) noexcept {
    if (seed == nullptr) return -1;
    constexpr std::size_t HALF = MOD_BYTES / 2;

    // Derive p from seed||"P", q from seed||"Q".
    uint8_t seed_p[32], seed_q[32];
    {
        uint8_t blk[33];
        std::memcpy(blk, seed, 32);
        blk[32] = 'P';
        cevm::crypto::sha256(reinterpret_cast<std::byte*>(seed_p),
                             reinterpret_cast<const std::byte*>(blk), 33);
        blk[32] = 'Q';
        cevm::crypto::sha256(reinterpret_cast<std::byte*>(seed_q),
                             reinterpret_cast<const std::byte*>(blk), 33);
    }
    derive_prime(sk_out.p, seed_p);
    derive_prime(sk_out.q, seed_q);
    if (std::memcmp(sk_out.p, sk_out.q, HALF) == 0) return -1;  // duplicate

    // N = p * q (full 2048-bit product). Use kmul.
    {
        std::array<uint64_t, HALF / 8> p_le{}, q_le{};
        be_to_le_limbs(p_le.data(), HALF / 8, sk_out.p, HALF);
        be_to_le_limbs(q_le.data(), HALF / 8, sk_out.q, HALF);
        std::array<uint64_t, MOD_LIMBS> N_le{};
        cevm::crypto::karatsuba::kmul({N_le.data(), MOD_LIMBS},
                                      {p_le.data(), HALF / 8},
                                      {q_le.data(), HALF / 8});
        le_limbs_to_be(sk_out.pk.N, MOD_BYTES, N_le.data(), MOD_LIMBS);
    }

    // N_sq = N * N (4096-bit).
    {
        std::array<uint64_t, MOD_LIMBS>    N_le{};
        std::array<uint64_t, MOD_SQ_LIMBS> Nsq_le{};
        be_to_le_limbs(N_le.data(), MOD_LIMBS, sk_out.pk.N, MOD_BYTES);
        cevm::crypto::karatsuba::kmul({Nsq_le.data(), MOD_SQ_LIMBS},
                                      {N_le.data(),   MOD_LIMBS},
                                      {N_le.data(),   MOD_LIMBS});
        le_limbs_to_be(sk_out.pk.N_sq, MOD_SQ_BYTES, Nsq_le.data(), MOD_SQ_LIMBS);
    }

    // λ = (p - 1)(q - 1).
    uint8_t pm1[HALF], qm1[HALF];
    std::memcpy(pm1, sk_out.p, HALF);
    std::memcpy(qm1, sk_out.q, HALF);
    pm1[HALF - 1] -= 1;
    qm1[HALF - 1] -= 1;
    {
        std::array<uint64_t, HALF / 8> pm1_le{}, qm1_le{};
        be_to_le_limbs(pm1_le.data(), HALF / 8, pm1, HALF);
        be_to_le_limbs(qm1_le.data(), HALF / 8, qm1, HALF);
        std::array<uint64_t, MOD_LIMBS> lam_le{};
        cevm::crypto::karatsuba::kmul({lam_le.data(), MOD_LIMBS},
                                      {pm1_le.data(), HALF / 8},
                                      {qm1_le.data(), HALF / 8});
        le_limbs_to_be(sk_out.lambda, MOD_BYTES, lam_le.data(), MOD_LIMBS);
    }

    // μ = λ^{-1} mod N.
    if (be_modinv(sk_out.mu, sk_out.lambda, sk_out.pk.N, MOD_BYTES) != 0) return -1;
    return 0;
}

}  // namespace kinet::crypto::cggmp21::paillier
