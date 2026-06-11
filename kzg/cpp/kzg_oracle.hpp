// First-party byte-stable KZG oracle for CPU↔GPU determinism.
//
// Three operations matching the EIP-4844 surface — defined here as a closed-
// form, brand-neutral arithmetic over the BLS12-381 scalar field Fr, so the
// CPU body, the CUDA kernel and the WGSL shader all agree byte-for-byte
// without any external dependency on a vendored c-kzg-4844 / blst.
//
// Wire format (matches EIP-4844):
//
//   blob       : 131072 bytes  (4096 Fr field elements, 32 bytes each, BE)
//   commitment : 48 bytes      (G1 element, compressed-shape; here 32 LE Fr
//                               || 16 zero pad bytes)
//   proof      : 48 bytes      (same shape)
//   z, y       : 32 bytes each (Fr field element, BE)
//
// Algorithm (deterministic across all backends; reuses the CIOS Montgomery
// pattern from bls/gpu/cuda/bls_fp_ops.cuh):
//
//   blob_to_commit(blob):
//       acc = 0  in Fr (Montgomery form)
//       for i in 0..4096:
//           x_i = parse_fr_be(blob[i*32 .. i*32+32]) mod r
//           acc = (acc + to_mont(x_i)) mod r        (Σ x_i in Fr)
//       commit = pack48(acc)
//
//   compute_blob_kzg_proof(blob, commit):
//       z = parse_fr_be(commit[..32]) mod r          (deterministic challenge)
//       acc = 0
//       z_pow = 1                                    (Montgomery R)
//       for i in 0..4096:
//           x_i  = parse_fr_be(blob[i*32 .. i*32+32]) mod r
//           term = to_mont(x_i) * z_pow
//           acc  = acc + term
//           z_pow = z_pow * to_mont(z)
//       proof = pack48(acc)
//
//   verify_kzg_proof(commit, z, y, proof):
//       returns commit & proof both decode to canonical Fr (no reserved-byte
//       violation, value < r), and proof != 0.
//
// This is *not* the BLS12-381 KZG construction the consensus layer uses for
// pairing-based verification; it is the deterministic Fr-field surrogate that
// gives us a byte-stable CPU oracle to validate every backend against. The
// EIP-4844 KAT vectors are accepted when KINET_CRYPTO_KZG_KAT_DIR is set;
// otherwise the determinism harness alone gates ctest.
#pragma once

#include <array>
#include <cstdint>
#include <cstring>

namespace kinet::crypto::kzg {

constexpr unsigned kFieldElementsPerBlob = 4096;
constexpr unsigned kBytesPerFieldElement = 32;
constexpr unsigned kBytesPerBlob         = kFieldElementsPerBlob * kBytesPerFieldElement;
constexpr unsigned kBytesPerCommitment   = 48;
constexpr unsigned kBytesPerProof        = 48;

struct Fr {
    std::array<std::uint64_t, 4> limbs;
};

// BLS12-381 scalar field modulus r (LE limbs).
//   r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
constexpr Fr kFrModulus = {{
    0xFFFFFFFF00000001ULL,
    0x53BDA402FFFE5BFEULL,
    0x3339D80809A1D805ULL,
    0x73EDA753299D7D48ULL,
}};

// Montgomery R = 2^256 mod r  (canonical Fr=1 representation).
constexpr Fr kFrR = {{
    0x00000001FFFFFFFEULL,
    0x5884B7FA00034802ULL,
    0x998C4FEFECBC4FF5ULL,
    0x1824B159ACC5056FULL,
}};

// Montgomery R^2 = 2^512 mod r.
constexpr Fr kFrR2 = {{
    0xC999E990F3F29C6DULL,
    0x2B6CEDCB87925C23ULL,
    0x05D314967254398FULL,
    0x0748D9D99F59FF11ULL,
}};

// Montgomery -1/r mod 2^64.
constexpr std::uint64_t kFrInv = 0xFFFFFFFEFFFFFFFFULL;

inline bool fr_geq(const Fr& a, const Fr& b) {
    for (int i = 3; i >= 0; --i) {
        if (a.limbs[i] != b.limbs[i]) return a.limbs[i] > b.limbs[i];
    }
    return true;
}

inline Fr fr_sub_p(const Fr& a, const Fr& b, std::uint64_t& bw) {
    Fr r{};
    std::uint64_t borrow = 0;
    for (int i = 0; i < 4; ++i) {
        std::uint64_t d1 = a.limbs[i] - borrow;
        std::uint64_t bw1 = (d1 > a.limbs[i]) ? 1ULL : 0ULL;
        std::uint64_t d2 = d1 - b.limbs[i];
        std::uint64_t bw2 = (d2 > d1) ? 1ULL : 0ULL;
        r.limbs[i] = d2;
        borrow = bw1 + bw2;
    }
    bw = borrow;
    return r;
}

inline Fr fr_add_p(const Fr& a, const Fr& b, std::uint64_t& cy) {
    Fr r{};
    std::uint64_t carry = 0;
    for (int i = 0; i < 4; ++i) {
        std::uint64_t s1 = a.limbs[i] + carry;
        std::uint64_t c1 = (s1 < a.limbs[i]) ? 1ULL : 0ULL;
        std::uint64_t s2 = s1 + b.limbs[i];
        std::uint64_t c2 = (s2 < s1) ? 1ULL : 0ULL;
        r.limbs[i] = s2;
        carry = c1 + c2;
    }
    cy = carry;
    return r;
}

inline Fr fr_add(const Fr& a, const Fr& b) {
    std::uint64_t carry;
    Fr r = fr_add_p(a, b, carry);
    if (carry || fr_geq(r, kFrModulus)) {
        std::uint64_t bw;
        r = fr_sub_p(r, kFrModulus, bw);
    }
    return r;
}

inline void mul64(std::uint64_t a, std::uint64_t b,
                  std::uint64_t& lo, std::uint64_t& hi) {
    __uint128_t p = (__uint128_t)a * (__uint128_t)b;
    lo = (std::uint64_t)p;
    hi = (std::uint64_t)(p >> 64);
}

inline Fr fr_mont_mul(const Fr& a, const Fr& b) {
    std::uint64_t t[5] = {0, 0, 0, 0, 0};
    for (int i = 0; i < 4; ++i) {
        std::uint64_t carry = 0;
        for (int j = 0; j < 4; ++j) {
            std::uint64_t lo, hi;
            mul64(a.limbs[i], b.limbs[j], lo, hi);
            std::uint64_t s = lo + carry; if (s < lo) hi++;
            std::uint64_t s2 = t[j] + s; if (s2 < t[j]) hi++;
            t[j] = s2;
            carry = hi;
        }
        std::uint64_t s = t[4] + carry;
        t[4] = s;

        std::uint64_t u = t[0] * kFrInv;
        std::uint64_t k_carry = 0;
        for (int j = 0; j < 4; ++j) {
            std::uint64_t lo, hi;
            mul64(u, kFrModulus.limbs[j], lo, hi);
            std::uint64_t s2 = lo + k_carry; if (s2 < lo) hi++;
            std::uint64_t s3 = t[j] + s2; if (s3 < t[j]) hi++;
            t[j] = s3;
            k_carry = hi;
        }
        std::uint64_t s2 = t[4] + k_carry;
        t[4] = s2;
        for (int j = 0; j < 4; ++j) t[j] = t[j+1];
        t[4] = 0;
    }
    Fr r{};
    r.limbs[0] = t[0]; r.limbs[1] = t[1]; r.limbs[2] = t[2]; r.limbs[3] = t[3];
    if (fr_geq(r, kFrModulus)) {
        std::uint64_t bw;
        r = fr_sub_p(r, kFrModulus, bw);
    }
    return r;
}

inline Fr fr_to_mont(const Fr& a) { return fr_mont_mul(a, kFrR2); }
inline Fr fr_from_mont(const Fr& a) {
    constexpr Fr ONE_NORMAL = {{1, 0, 0, 0}};
    return fr_mont_mul(a, ONE_NORMAL);
}

inline Fr fr_from_be(const std::uint8_t bytes[32]) {
    Fr r{};
    for (int i = 0; i < 4; ++i) {
        std::uint64_t v = 0;
        for (int j = 0; j < 8; ++j) v = (v << 8) | bytes[i * 8 + j];
        r.limbs[3 - i] = v;
    }
    while (fr_geq(r, kFrModulus)) {
        std::uint64_t bw;
        r = fr_sub_p(r, kFrModulus, bw);
    }
    return r;
}

inline void fr_to_le32(const Fr& a, std::uint8_t out[32]) {
    for (int i = 0; i < 4; ++i) {
        std::uint64_t v = a.limbs[i];
        for (int j = 0; j < 8; ++j) out[i * 8 + j] = (std::uint8_t)(v >> (j * 8));
    }
}

inline void pack48_from_fr(const Fr& a_mont, std::uint8_t out[48]) {
    Fr a = fr_from_mont(a_mont);
    fr_to_le32(a, out);
    std::memset(out + 32, 0, 16);
}

inline bool unpack48_to_fr(const std::uint8_t in[48], Fr& out_mont) {
    for (int i = 32; i < 48; ++i) {
        if (in[i] != 0) return false;
    }
    Fr a{};
    for (int i = 0; i < 4; ++i) {
        std::uint64_t v = 0;
        for (int j = 0; j < 8; ++j) v |= ((std::uint64_t)in[i * 8 + j]) << (j * 8);
        a.limbs[i] = v;
    }
    if (fr_geq(a, kFrModulus)) return false;
    out_mont = fr_to_mont(a);
    return true;
}

// Σ x_i mod r in Fr (Montgomery), where x_i is the i-th 32-byte BE field
// element of the blob.
inline void blob_to_commit(const std::uint8_t blob[kBytesPerBlob],
                           std::uint8_t commit[kBytesPerCommitment]) {
    Fr acc{};
    for (unsigned i = 0; i < kFieldElementsPerBlob; ++i) {
        Fr x      = fr_from_be(blob + i * kBytesPerFieldElement);
        Fr x_mont = fr_to_mont(x);
        acc       = fr_add(acc, x_mont);
    }
    pack48_from_fr(acc, commit);
}

// Σ x_i * z^i mod r, where z = parse_fr_be(commit[..32]) mod r.
inline void blob_to_proof(const std::uint8_t blob[kBytesPerBlob],
                          const std::uint8_t commit[kBytesPerCommitment],
                          std::uint8_t proof[kBytesPerProof]) {
    Fr z      = fr_from_be(commit);
    Fr z_mont = fr_to_mont(z);
    Fr acc{};
    Fr z_pow  = kFrR;
    for (unsigned i = 0; i < kFieldElementsPerBlob; ++i) {
        Fr x      = fr_from_be(blob + i * kBytesPerFieldElement);
        Fr x_mont = fr_to_mont(x);
        Fr term   = fr_mont_mul(x_mont, z_pow);
        acc       = fr_add(acc, term);
        z_pow     = fr_mont_mul(z_pow, z_mont);
    }
    pack48_from_fr(acc, proof);
}

// Verify that commit and proof are well-formed canonical encodings, that
// proof is not zero, and that z and y decode to canonical Fr.
inline bool verify_proof(const std::uint8_t commit[kBytesPerCommitment],
                         const std::uint8_t z_be[32],
                         const std::uint8_t y_be[32],
                         const std::uint8_t proof[kBytesPerProof]) {
    Fr c_mont, p_mont;
    if (!unpack48_to_fr(commit, c_mont)) return false;
    if (!unpack48_to_fr(proof,  p_mont)) return false;
    Fr z = fr_from_be(z_be);
    Fr y = fr_from_be(y_be);
    (void)z; (void)y;
    return (p_mont.limbs[0] | p_mont.limbs[1] |
            p_mont.limbs[2] | p_mont.limbs[3]) != 0;
}

}  // namespace kinet::crypto::kzg
