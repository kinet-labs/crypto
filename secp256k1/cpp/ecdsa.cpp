// secp256k1 ECDSA sign / verify / sk_to_pk implementation.

#include "ecdsa.hpp"
#include "curve.hpp"
#include "field.hpp"
#include "windowed_g_table.hpp"

#include <cstring>

namespace kinet::crypto::secp256k1 {

namespace {

// ----- BE 32-byte <-> U256 (plain, NOT Montgomery) --------------------------

U256 u256_from_be32(const uint8_t b[32]) noexcept {
    U256 r{};
    for (int i = 0; i < 4; ++i) {
        u64 v = 0;
        const int base = (3 - i) * 8;
        for (int j = 0; j < 8; ++j) v = (v << 8) | (u64)b[base + j];
        r.limbs[i] = v;
    }
    return r;
}

void u256_to_be32(const U256& v, uint8_t out[32]) noexcept {
    for (int i = 0; i < 4; ++i) {
        u64 w = v.limbs[i];
        const int base = (3 - i) * 8;
        for (int j = 7; j >= 0; --j) { out[base + j] = (uint8_t)(w & 0xFF); w >>= 8; }
    }
}

// ----- Reduce a 256-bit integer modulo n (group order) ----------------------

U256 reduce_mod_n(const U256& v) noexcept {
    if (U256::cmp(v, N) >= 0) {
        u64 bw;
        return sub_256(v, N, bw);
    }
    return v;
}

// ----- N_HALF = (n - 1) / 2  -- BIP-62 Low-S boundary -----------------------

constexpr U256 N_HALF{
    0xDFE92F46681B20A0ULL, 0x5D576E7357A4501DULL,
    0xFFFFFFFFFFFFFFFFULL, 0x7FFFFFFFFFFFFFFFULL};

// ----- HMAC-SHA256 used by RFC 6979. We use a tiny private SHA-256 since
// the public sha256 entry is in the c-abi layer above us; embedding a
// 256-line FIPS 180-4 impl here keeps the sign body self-contained.

struct Sha256Ctx {
    uint32_t h[8];
    uint8_t buffer[64];
    uint64_t bitlen;
    size_t buflen;
};

void sha256_init(Sha256Ctx& c) noexcept {
    c.h[0]=0x6a09e667; c.h[1]=0xbb67ae85; c.h[2]=0x3c6ef372; c.h[3]=0xa54ff53a;
    c.h[4]=0x510e527f; c.h[5]=0x9b05688c; c.h[6]=0x1f83d9ab; c.h[7]=0x5be0cd19;
    c.bitlen = 0; c.buflen = 0;
}

void sha256_compress(uint32_t h[8], const uint8_t block[64]) noexcept {
    static constexpr uint32_t K[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = ((uint32_t)block[4*i]<<24) | ((uint32_t)block[4*i+1]<<16) |
               ((uint32_t)block[4*i+2]<<8) | (uint32_t)block[4*i+3];
    }
    auto rotr = [](uint32_t x, int n){ return (x>>n) | (x<<(32-n)); };
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15]>>3);
        uint32_t s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2]>>10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    uint32_t a=h[0],b=h[1],c2=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t T1 = hh + S1 + ch + K[i] + w[i];
        uint32_t S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
        uint32_t mj = (a & b) ^ (a & c2) ^ (b & c2);
        uint32_t T2 = S0 + mj;
        hh = g; g = f; f = e; e = d + T1;
        d = c2; c2 = b; b = a; a = T1 + T2;
    }
    h[0]+=a; h[1]+=b; h[2]+=c2; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
}

void sha256_update(Sha256Ctx& c, const uint8_t* data, size_t n) noexcept {
    c.bitlen += (uint64_t)n * 8;
    while (n > 0) {
        size_t take = 64 - c.buflen;
        if (take > n) take = n;
        std::memcpy(c.buffer + c.buflen, data, take);
        c.buflen += take; data += take; n -= take;
        if (c.buflen == 64) {
            sha256_compress(c.h, c.buffer);
            c.buflen = 0;
        }
    }
}

void sha256_final(Sha256Ctx& c, uint8_t out[32]) noexcept {
    c.buffer[c.buflen++] = 0x80;
    if (c.buflen > 56) {
        std::memset(c.buffer + c.buflen, 0, 64 - c.buflen);
        sha256_compress(c.h, c.buffer);
        c.buflen = 0;
    }
    std::memset(c.buffer + c.buflen, 0, 56 - c.buflen);
    for (int i = 0; i < 8; ++i) {
        c.buffer[56 + i] = (uint8_t)(c.bitlen >> (56 - 8*i));
    }
    sha256_compress(c.h, c.buffer);
    for (int i = 0; i < 8; ++i) {
        out[4*i+0] = (uint8_t)(c.h[i] >> 24);
        out[4*i+1] = (uint8_t)(c.h[i] >> 16);
        out[4*i+2] = (uint8_t)(c.h[i] >> 8);
        out[4*i+3] = (uint8_t)(c.h[i]);
    }
}

void hmac_sha256(const uint8_t* key, size_t key_len,
                 const uint8_t* msg, size_t msg_len, uint8_t out[32]) noexcept {
    uint8_t k[64] = {0};
    if (key_len > 64) {
        Sha256Ctx c; sha256_init(c);
        sha256_update(c, key, key_len); sha256_final(c, k);
    } else {
        std::memcpy(k, key, key_len);
    }
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; ++i) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }

    uint8_t inner[32];
    Sha256Ctx c; sha256_init(c);
    sha256_update(c, ipad, 64);
    sha256_update(c, msg, msg_len);
    sha256_final(c, inner);

    sha256_init(c);
    sha256_update(c, opad, 64);
    sha256_update(c, inner, 32);
    sha256_final(c, out);
}

// RFC 6979: deterministic k for ECDSA over secp256k1.
// k is in [1, n-1].
U256 rfc6979_k(const uint8_t sk[32], const uint8_t z[32]) noexcept {
    uint8_t V[32], K[32];
    std::memset(V, 0x01, 32);
    std::memset(K, 0x00, 32);

    auto step = [&](uint8_t b) {
        uint8_t in[32 + 1 + 32 + 32];
        std::memcpy(in, V, 32);
        in[32] = b;
        std::memcpy(in + 33, sk, 32);
        std::memcpy(in + 65, z, 32);
        hmac_sha256(K, 32, in, sizeof(in), K);
        hmac_sha256(K, 32, V, 32, V);
    };
    step(0x00);
    step(0x01);

    while (true) {
        hmac_sha256(K, 32, V, 32, V);
        const U256 cand = u256_from_be32(V);
        if (!cand.is_zero() && U256::cmp(cand, N) < 0) {
            return cand;
        }
        // Reseed if rejected (vanishingly rare): K = HMAC(K, V || 0x00); V = HMAC(K, V).
        uint8_t tail[33];
        std::memcpy(tail, V, 32);
        tail[32] = 0x00;
        hmac_sha256(K, 32, tail, 33, K);
        hmac_sha256(K, 32, V, 32, V);
    }
}

}  // namespace

// ----- secret_to_public ----------------------------------------------------

EcdsaStatus secret_to_public(const uint8_t sk[32], uint8_t pk[64]) noexcept {
    const U256 d = u256_from_be32(sk);
    if (d.is_zero() || U256::cmp(d, N) >= 0) return EcdsaStatus::InvalidSecret;

    const auto& tbl = windowed_g_table();
    JacobianPoint Q = scalar_mul_g_windowed(tbl, d);
    AffinePoint A = jacobian_to_affine(Q);
    if (A.infinity) return EcdsaStatus::InvalidSecret;

    const U256 x_norm = from_mont(A.x, P, P_INV);
    const U256 y_norm = from_mont(A.y, P, P_INV);
    u256_to_be32(x_norm, pk);
    u256_to_be32(y_norm, pk + 32);
    return EcdsaStatus::OK;
}

// ----- sign ----------------------------------------------------------------

EcdsaStatus sign(const uint8_t sk[32], const uint8_t msg32[32],
                 uint8_t sig[64], uint8_t* recid) noexcept {
    const U256 d = u256_from_be32(sk);
    if (d.is_zero() || U256::cmp(d, N) >= 0) return EcdsaStatus::InvalidSecret;

    // z = msg reduced mod n.
    const U256 z = reduce_mod_n(u256_from_be32(msg32));

    // Try k once (RFC 6979). For secp256k1 the prob of needing a retry for r==0
    // or s==0 is ~2^{-256}; the loop covers the remote case by re-deriving k
    // via RFC 6979 step 3.2.k re-entry. We keep it simple: one-shot.
    U256 k = rfc6979_k(sk, msg32);

    const auto& tbl = windowed_g_table();
    AffinePoint R = jacobian_to_affine(scalar_mul_g_windowed(tbl, k));
    if (R.infinity) return EcdsaStatus::InvalidSignature;

    const U256 Rx_norm = from_mont(R.x, P, P_INV);  // x of k*G as a normal int
    U256 r = reduce_mod_n(Rx_norm);
    if (r.is_zero()) return EcdsaStatus::InvalidSignature;

    // s = k^{-1} * (z + r*d) mod n; arithmetic in Montgomery wrt n.
    const U256 d_n   = to_mont_n(d);
    const U256 r_n   = to_mont_n(r);
    const U256 z_n   = to_mont_n(z);
    const U256 k_n   = to_mont_n(k);
    const U256 rd    = fn_mul(r_n, d_n);
    const U256 zrd   = mod_add(z_n, rd, N);
    const U256 k_inv = fn_inv(k_n);
    const U256 s_mont = fn_mul(k_inv, zrd);
    U256 s = from_mont_n(s_mont);
    if (s.is_zero()) return EcdsaStatus::InvalidSignature;

    // recid: low bit = parity(R.y); high bit = (Rx_norm >= n).
    const U256 Ry_norm = from_mont(R.y, P, P_INV);
    uint8_t v = 0;
    if (Ry_norm.limbs[0] & 1ULL) v |= 0x01;
    if (U256::cmp(Rx_norm, N) >= 0) v |= 0x02;

    // BIP-62 Low-S: if s > n/2, use s' = n - s and flip the y-parity bit.
    if (U256::cmp(s, N_HALF) > 0) {
        u64 bw;
        s = sub_256(N, s, bw);
        v ^= 0x01;
    }

    u256_to_be32(r, sig);
    u256_to_be32(s, sig + 32);
    if (recid != nullptr) *recid = v;
    return EcdsaStatus::OK;
}

// ----- verify --------------------------------------------------------------

EcdsaStatus verify(const uint8_t pk[64], const uint8_t msg32[32],
                   const uint8_t sig[64]) noexcept {
    const U256 r = u256_from_be32(sig);
    const U256 s = u256_from_be32(sig + 32);
    if (r.is_zero() || U256::cmp(r, N) >= 0) return EcdsaStatus::InvalidSignature;
    if (s.is_zero() || U256::cmp(s, N) >= 0) return EcdsaStatus::InvalidSignature;

    // Decode pubkey: 64 bytes = X || Y, plain BE.
    const U256 qx_norm = u256_from_be32(pk);
    const U256 qy_norm = u256_from_be32(pk + 32);
    if (U256::cmp(qx_norm, P) >= 0 || U256::cmp(qy_norm, P) >= 0) return EcdsaStatus::InvalidPubkey;

    AffinePoint Q;
    Q.x = to_mont(qx_norm, R2_P, P, P_INV);
    Q.y = to_mont(qy_norm, R2_P, P, P_INV);
    Q.infinity = false;
    // y^2 == x^3 + 7
    const U256 SEVEN_MONT = to_mont(U256{7,0,0,0}, R2_P, P, P_INV);
    const U256 y2  = fp_sqr(Q.y);
    const U256 x3  = fp_mul(fp_sqr(Q.x), Q.x);
    const U256 rhs = fp_add(x3, SEVEN_MONT);
    if (!(y2 == rhs)) return EcdsaStatus::InvalidPubkey;

    const U256 z = reduce_mod_n(u256_from_be32(msg32));

    const U256 s_n = to_mont_n(s);
    const U256 w   = from_mont_n(fn_inv(s_n));   // s^{-1} mod n, normal form
    const U256 u1  = from_mont_n(fn_mul(to_mont_n(z), to_mont_n(w)));
    const U256 u2  = from_mont_n(fn_mul(to_mont_n(r), to_mont_n(w)));

    AffinePoint G;
    G.x = to_mont(GX, R2_P, P, P_INV);
    G.y = to_mont(GY, R2_P, P, P_INV);
    G.infinity = false;

    const JacobianPoint R_jac = jac_msm2(u1, G, u2, Q);
    if (R_jac.infinity) return EcdsaStatus::VerifyFailed;
    const AffinePoint R_aff = jacobian_to_affine(R_jac);
    const U256 Rx_norm = from_mont(R_aff.x, P, P_INV);
    const U256 Rx_modn = reduce_mod_n(Rx_norm);
    return (Rx_modn == r) ? EcdsaStatus::OK : EcdsaStatus::VerifyFailed;
}

}  // namespace kinet::crypto::secp256k1
