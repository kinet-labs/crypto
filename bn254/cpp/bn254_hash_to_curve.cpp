// First-party RFC 9380 hash-to-curve for BN254 G1 -- implementation.
//
// See bn254_hash_to_curve.hpp for the public surface and design notes.
//
// Constants below match gnark-crypto v0.20.1 ecc/bn254/hash_to_g1.go and were
// derived independently (canonical hex listed inline). All field arithmetic
// uses the first-party Montgomery routines in bn254_fp.hpp.

#include "bn254_hash_to_curve.hpp"

#include <algorithm>
#include <cstring>

namespace kinet::crypto::bn254::h2c {

// ---------------------------------------------------------------------------
// SHA-256 (FIPS 180-4) -- tiny self-contained implementation.
// ---------------------------------------------------------------------------

namespace {

struct Sha256 {
    static constexpr std::size_t BLOCK = 64;
    static constexpr std::size_t DIGEST = 32;

    uint32_t h[8];
    uint64_t total_bits;
    uint8_t  buf[BLOCK];
    std::size_t buf_len;

    Sha256() noexcept { reset(); }

    void reset() noexcept {
        h[0] = 0x6a09e667u; h[1] = 0xbb67ae85u; h[2] = 0x3c6ef372u; h[3] = 0xa54ff53au;
        h[4] = 0x510e527fu; h[5] = 0x9b05688cu; h[6] = 0x1f83d9abu; h[7] = 0x5be0cd19u;
        total_bits = 0;
        buf_len = 0;
    }

    static uint32_t rotr(uint32_t x, unsigned n) noexcept {
        return (x >> n) | (x << (32 - n));
    }

    void compress(const uint8_t* p) noexcept {
        static constexpr uint32_t K[64] = {
            0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
            0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
            0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
            0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
            0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
            0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
            0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
            0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u,
        };
        uint32_t W[64];
        for (int i = 0; i < 16; ++i) {
            W[i] = ((uint32_t)p[4*i+0] << 24) | ((uint32_t)p[4*i+1] << 16)
                 | ((uint32_t)p[4*i+2] <<  8) | ((uint32_t)p[4*i+3]);
        }
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(W[i-15], 7) ^ rotr(W[i-15], 18) ^ (W[i-15] >> 3);
            uint32_t s1 = rotr(W[i-2], 17) ^ rotr(W[i-2],  19) ^ (W[i-2]  >> 10);
            W[i] = W[i-16] + s0 + W[i-7] + s1;
        }
        uint32_t a=h[0], b=h[1], c=h[2], d=h[3], e=h[4], f=h[5], g=h[6], hh=h[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = hh + S1 + ch + K[i] + W[i];
            uint32_t S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
            uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + mj;
            hh = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d;
        h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }

    void update(const uint8_t* data, std::size_t len) noexcept {
        total_bits += (uint64_t)len * 8;
        if (buf_len) {
            std::size_t need = BLOCK - buf_len;
            if (len < need) {
                std::memcpy(buf + buf_len, data, len);
                buf_len += len;
                return;
            }
            std::memcpy(buf + buf_len, data, need);
            compress(buf);
            data += need; len -= need; buf_len = 0;
        }
        while (len >= BLOCK) {
            compress(data);
            data += BLOCK; len -= BLOCK;
        }
        if (len) {
            std::memcpy(buf, data, len);
            buf_len = len;
        }
    }

    void finalize(uint8_t out[DIGEST]) noexcept {
        // Snapshot the message length BEFORE appending pad bytes.
        const uint64_t msg_bits = total_bits;
        uint8_t pad[BLOCK];
        pad[0] = 0x80;
        std::size_t pad_len = (buf_len < 56) ? (56 - buf_len) : (120 - buf_len);
        std::memset(pad + 1, 0, pad_len - 1);
        update(pad, pad_len);
        uint8_t len_be[8];
        uint64_t bits = msg_bits;
        for (int i = 7; i >= 0; --i) {
            len_be[i] = (uint8_t)(bits & 0xff);
            bits >>= 8;
        }
        update(len_be, 8);
        for (int i = 0; i < 8; ++i) {
            out[4*i+0] = (uint8_t)(h[i] >> 24);
            out[4*i+1] = (uint8_t)(h[i] >> 16);
            out[4*i+2] = (uint8_t)(h[i] >>  8);
            out[4*i+3] = (uint8_t)(h[i]);
        }
    }
};

}  // namespace

// ---------------------------------------------------------------------------
// expand_message_xmd with SHA-256 (RFC 9380 §5.4.1).
// ---------------------------------------------------------------------------

std::vector<uint8_t> expand_message_xmd_sha256(
    std::span<const uint8_t> msg,
    std::span<const uint8_t> dst,
    std::size_t len_in_bytes)
{
    constexpr std::size_t b_in_bytes = Sha256::DIGEST; // 32
    constexpr std::size_t r_in_bytes = Sha256::BLOCK;  // 64

    if (dst.size() > 255 || len_in_bytes == 0) return {};
    const std::size_t ell = (len_in_bytes + b_in_bytes - 1) / b_in_bytes;
    if (ell > 255) return {};

    const uint8_t dst_size = (uint8_t)dst.size();

    // b0 = H(Z_pad || msg || I2OSP(len_in_bytes, 2) || I2OSP(0, 1) || DST || I2OSP(len(DST), 1))
    Sha256 h0;
    {
        uint8_t zpad[r_in_bytes] = {0};
        h0.update(zpad, r_in_bytes);
    }
    if (!msg.empty()) h0.update(msg.data(), msg.size());
    {
        const uint8_t lib_be[3] = {
            (uint8_t)((len_in_bytes >> 8) & 0xff),
            (uint8_t)(len_in_bytes & 0xff),
            0x00,
        };
        h0.update(lib_be, 3);
    }
    if (!dst.empty()) h0.update(dst.data(), dst.size());
    h0.update(&dst_size, 1);

    uint8_t b0[Sha256::DIGEST];
    h0.finalize(b0);

    std::vector<uint8_t> out(len_in_bytes);

    // b1 = H(b0 || I2OSP(1, 1) || DST || I2OSP(len(DST), 1))
    uint8_t bi[Sha256::DIGEST];
    {
        Sha256 h;
        h.update(b0, Sha256::DIGEST);
        const uint8_t one = 0x01;
        h.update(&one, 1);
        if (!dst.empty()) h.update(dst.data(), dst.size());
        h.update(&dst_size, 1);
        h.finalize(bi);
    }
    {
        const std::size_t copy_len = std::min<std::size_t>(b_in_bytes, len_in_bytes);
        std::memcpy(out.data(), bi, copy_len);
    }

    for (std::size_t i = 2; i <= ell; ++i) {
        // strxor = b0 XOR b_{i-1}
        uint8_t strxor[Sha256::DIGEST];
        for (std::size_t j = 0; j < Sha256::DIGEST; ++j) strxor[j] = b0[j] ^ bi[j];

        Sha256 h;
        h.update(strxor, Sha256::DIGEST);
        const uint8_t idx = (uint8_t)i;
        h.update(&idx, 1);
        if (!dst.empty()) h.update(dst.data(), dst.size());
        h.update(&dst_size, 1);
        h.finalize(bi);

        const std::size_t off = b_in_bytes * (i - 1);
        const std::size_t copy_len = std::min<std::size_t>(b_in_bytes, len_in_bytes - off);
        std::memcpy(out.data() + off, bi, copy_len);
    }

    return out;
}

// ---------------------------------------------------------------------------
// hash_to_field for BN254 Fp with L = 48, count = 2 (RFC 9380 §5.3).
//
// Each L-byte chunk is interpreted as an unsigned big-endian integer and
// reduced mod p, then converted to Montgomery form for downstream use.
// ---------------------------------------------------------------------------

namespace {

// Reduce a 48-byte big-endian integer mod p. Returns Montgomery form.
U256 reduce_be384_mod_p_to_mont(const uint8_t bytes48[48]) noexcept {
    // Split: hi = top 16 bytes, lo = bottom 32 bytes. Both fit in 256 bits.
    uint8_t hi32[32] = {};
    std::memcpy(hi32 + 16, bytes48, 16);
    uint8_t lo32[32];
    std::memcpy(lo32, bytes48 + 16, 32);

    U256 hi = U256::from_be32(hi32);
    U256 lo = U256::from_be32(lo32);

    // hi < 2^128 << p so already canonical; lo < 2^256 may exceed p once.
    while (U256::cmp(lo, P) >= 0) {
        u64 bw; lo = sub_256(lo, P, bw);
    }

    // value = hi * 2^256 + lo  (mod p).  2^256 mod p = R_FP (the Montgomery R).
    // Compute hi * 2^256 mod p in plain form via Montgomery multiplication:
    //   to_mont(hi) = hi * R mod p
    //   mont_mul(hi*R, R) = hi * R * R / R = hi * R = hi * 2^256 mod p
    U256 hi_mont = to_mont_fp(hi);
    U256 hi_x_R  = mont_mul(hi_mont, R_FP, P, P_INV);
    U256 plain   = mod_add(hi_x_R, lo, P);

    return to_mont_fp(plain);
}

}  // namespace

std::array<U256, 2> hash_to_field_2(
    std::span<const uint8_t> msg,
    std::span<const uint8_t> dst)
{
    constexpr std::size_t L = 48;
    auto buf = expand_message_xmd_sha256(msg, dst, L * 2);
    if (buf.size() != L * 2) return {U256{}, U256{}};
    return {
        reduce_be384_mod_p_to_mont(buf.data() + 0),
        reduce_be384_mod_p_to_mont(buf.data() + L),
    };
}

// ---------------------------------------------------------------------------
// SVDW map_to_curve (RFC 9380 §6.6.1 / gnark MapToCurve1).
//
// Constants (canonical hex; converted to Montgomery on use):
//   Z  = 1
//   c1 = g(Z) = Z^3 + 3 = 4
//   c2 = -Z / 2 = (p - 1) / 2     // hex 0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea3
//   c3 = sqrt(-g(Z) * (3*Z^2))    // sgn0(c3) = 0  (gnark canonical pick)
//                                 // hex 0x16789af3a83522eb353c98fc6b36d713d5d8d1cc5dffffffa
//   c4 = -4*g(Z) / (3*Z^2)        // hex 0x10216f7ba065e00de81ac1e7808072c9dd2b2385cd7b438469602eb24829a9bd
//
// All math below is in Montgomery form on field elements (Fp).
// ---------------------------------------------------------------------------

namespace {

constexpr U256 SVDW_Z_PLAIN{0x0000000000000001ULL, 0, 0, 0};
constexpr U256 SVDW_C1_PLAIN{0x0000000000000004ULL, 0, 0, 0};
constexpr U256 SVDW_C2_PLAIN{0x9E10460B6C3E7EA3ULL, 0xCBC0B548B438E546ULL,
                              0xDC2822DB40C0AC2EULL, 0x183227397098D014ULL};
constexpr U256 SVDW_C3_PLAIN{0x5D8D1CC5DFFFFFFAULL, 0x53C98FC6B36D713DULL,
                              0x6789AF3A83522EB3ULL, 0x0000000000000001ULL};
constexpr U256 SVDW_C4_PLAIN{0x69602EB24829A9BDULL, 0xDD2B2385CD7B4384ULL,
                              0xE81AC1E7808072C9ULL, 0x10216F7BA065E00DULL};

// Sgn0 (RFC 9380 §4.1, m = 1): LSB of canonical (non-Mont) representative.
int fp_sgn0(const U256& a_mont) noexcept {
    U256 plain = from_mont_fp(a_mont);
    return (int)(plain.limbs[0] & 1u);
}

U256 fp_g_x(const U256& x_mont) noexcept {
    U256 x2 = fp_sqr(x_mont);
    U256 x3 = fp_mul(x2, x_mont);
    return fp_add(x3, fp_three()); // y^2 = x^3 + 3
}

}  // namespace

G1Affine map_to_curve_svdw(const U256& u_mont) {
    const U256 ONE = R_FP; // 1 in Montgomery form
    const U256 Z   = to_mont_fp(SVDW_Z_PLAIN);
    const U256 c1  = to_mont_fp(SVDW_C1_PLAIN);
    const U256 c2  = to_mont_fp(SVDW_C2_PLAIN);
    const U256 c3  = to_mont_fp(SVDW_C3_PLAIN);
    const U256 c4  = to_mont_fp(SVDW_C4_PLAIN);

    // Steps numbered per RFC 9380 §6.6.1 / gnark MapToCurve1.
    U256 tv1 = fp_sqr(u_mont);          //  1.  tv1 = u^2
    tv1 = fp_mul(tv1, c1);              //  2.  tv1 = tv1 * c1
    U256 tv2 = fp_add(ONE, tv1);        //  3.  tv2 = 1 + tv1
    tv1 = fp_sub(ONE, tv1);             //  4.  tv1 = 1 - tv1
    U256 tv3 = fp_mul(tv1, tv2);        //  5.  tv3 = tv1 * tv2
    tv3 = fp_inv(tv3);                  //  6.  tv3 = inv0(tv3)
    U256 tv4 = fp_mul(u_mont, tv1);     //  7.  tv4 = u * tv1
    tv4 = fp_mul(tv4, tv3);             //  8.  tv4 = tv4 * tv3
    tv4 = fp_mul(tv4, c3);              //  9.  tv4 = tv4 * c3
    U256 x1 = fp_sub(c2, tv4);          // 10.  x1 = c2 - tv4

    U256 gx1 = fp_g_x(x1);              // 11-14. gx1 = x1^3 + B
    U256 y1{};
    const bool gx1_is_sq = fp_sqrt(gx1, y1); // 15. e1 = is_square(gx1)

    U256 x2 = fp_add(c2, tv4);          // 16. x2 = c2 + tv4
    U256 gx2 = fp_g_x(x2);              // 17-20. gx2 = x2^3 + B
    U256 y2{};
    const bool gx2_is_sq = fp_sqrt(gx2, y2); // 21. e2 = is_square(gx2) AND NOT e1

    U256 x3 = fp_sqr(tv2);              // 22. x3 = tv2^2
    x3 = fp_mul(x3, tv3);               // 23. x3 = x3 * tv3
    x3 = fp_sqr(x3);                    // 24. x3 = x3^2
    x3 = fp_mul(x3, c4);                // 25. x3 = x3 * c4
    x3 = fp_add(x3, Z);                 // 26. x3 = x3 + Z

    // 27. x = e1 ? x1 : x3
    U256 x = gx1_is_sq ? x1 : x3;
    // 28. x = (e2 AND NOT e1) ? x2 : x
    if (gx2_is_sq && !gx1_is_sq) x = x2;

    // 31-32. gx = x^3 + B    33. y = sqrt(gx)
    U256 gx = fp_g_x(x);
    U256 y{};
    (void)fp_sqrt(gx, y); // by construction one of x1/x2/x3 yields a square.

    // 34-35. y = (sgn0(u) == sgn0(y)) ? y : -y
    if (fp_sgn0(u_mont) != fp_sgn0(y)) y = fp_neg(y);

    G1Affine r;
    r.x = x; r.y = y; r.infinity = false;
    return r;
}

// ---------------------------------------------------------------------------
// hash_to_curve_g1 (RFC 9380 §3): full random-oracle map.
// ---------------------------------------------------------------------------

G1Affine hash_to_curve_g1(
    std::span<const uint8_t> msg,
    std::span<const uint8_t> dst)
{
    auto u = hash_to_field_2(msg, dst);
    G1Affine Q0 = map_to_curve_svdw(u[0]);
    G1Affine Q1 = map_to_curve_svdw(u[1]);

    G1Jac J0 = g1_to_jac(Q0);
    G1Jac J1 = g1_to_jac(Q1);
    G1Jac R  = g1_add(J0, J1);
    return g1_to_affine(R);
}

}  // namespace kinet::crypto::bn254::h2c
