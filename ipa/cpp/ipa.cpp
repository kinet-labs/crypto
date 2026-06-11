// SPDX-License-Identifier: Apache-2.0
//
// ipa/ipa.cpp -- IPA prover and verifier over Banderwagon.
// First-party. No vendoring. See ipa.hpp for the contract.

#include "ipa.hpp"
#include "../../banderwagon/cpp/multiexp.hpp"

#include <cstring>
#include <vector>

namespace kinet::crypto::ipa {

namespace {

constexpr std::uint32_t kSha256K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
    0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
    0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
    0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

inline std::uint32_t rotr32(std::uint32_t x, std::uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

void sha256_compress(std::uint32_t H[8], const std::uint8_t block[64]) {
    std::uint32_t W[64];
    for (int i = 0; i < 16; ++i) {
        W[i] = (static_cast<std::uint32_t>(block[4 * i + 0]) << 24)
             | (static_cast<std::uint32_t>(block[4 * i + 1]) << 16)
             | (static_cast<std::uint32_t>(block[4 * i + 2]) << 8)
             | (static_cast<std::uint32_t>(block[4 * i + 3]));
    }
    for (int i = 16; i < 64; ++i) {
        std::uint32_t s0 = rotr32(W[i - 15], 7) ^ rotr32(W[i - 15], 18) ^ (W[i - 15] >> 3);
        std::uint32_t s1 = rotr32(W[i - 2], 17) ^ rotr32(W[i - 2], 19) ^ (W[i - 2] >> 10);
        W[i] = W[i - 16] + s0 + W[i - 7] + s1;
    }
    std::uint32_t a = H[0], b = H[1], c = H[2], d = H[3];
    std::uint32_t e = H[4], f = H[5], g = H[6], h = H[7];
    for (int i = 0; i < 64; ++i) {
        std::uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        std::uint32_t ch = (e & f) ^ ((~e) & g);
        std::uint32_t T1 = h + S1 + ch + kSha256K[i] + W[i];
        std::uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        std::uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        std::uint32_t T2 = S0 + mj;
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }
    H[0] += a; H[1] += b; H[2] += c; H[3] += d;
    H[4] += e; H[5] += f; H[6] += g; H[7] += h;
}

}  // namespace

void Transcript::sha_init_() {
    digest_state_[0] = 0x6a09e667u; digest_state_[1] = 0xbb67ae85u;
    digest_state_[2] = 0x3c6ef372u; digest_state_[3] = 0xa54ff53au;
    digest_state_[4] = 0x510e527fu; digest_state_[5] = 0x9b05688cu;
    digest_state_[6] = 0x1f83d9abu; digest_state_[7] = 0x5be0cd19u;
    digest_block_len_ = 0;
    digest_total_bits_ = 0;
}

void Transcript::sha_update_(const std::uint8_t* data, std::size_t len) {
    digest_total_bits_ += static_cast<std::uint64_t>(len) * 8u;
    while (len > 0) {
        std::size_t want = 64 - digest_block_len_;
        std::size_t take = (len < want) ? len : want;
        std::memcpy(digest_block_.data() + digest_block_len_, data, take);
        digest_block_len_ += take;
        data += take;
        len  -= take;
        if (digest_block_len_ == 64) {
            sha256_compress(digest_state_.data(), digest_block_.data());
            digest_block_len_ = 0;
        }
    }
}

void Transcript::sha_final_(std::uint8_t out32[32]) {
    std::uint64_t total_bits = digest_total_bits_;
    digest_block_[digest_block_len_++] = 0x80;
    if (digest_block_len_ > 56) {
        while (digest_block_len_ < 64) digest_block_[digest_block_len_++] = 0;
        sha256_compress(digest_state_.data(), digest_block_.data());
        digest_block_len_ = 0;
    }
    while (digest_block_len_ < 56) digest_block_[digest_block_len_++] = 0;
    for (int i = 7; i >= 0; --i) {
        digest_block_[digest_block_len_++] = static_cast<std::uint8_t>(total_bits >> (8 * i));
    }
    sha256_compress(digest_state_.data(), digest_block_.data());
    for (int i = 0; i < 8; ++i) {
        out32[4 * i + 0] = static_cast<std::uint8_t>(digest_state_[i] >> 24);
        out32[4 * i + 1] = static_cast<std::uint8_t>(digest_state_[i] >> 16);
        out32[4 * i + 2] = static_cast<std::uint8_t>(digest_state_[i] >> 8);
        out32[4 * i + 3] = static_cast<std::uint8_t>(digest_state_[i]);
    }
}

Transcript::Transcript(const char* label) {
    sha_init_();
    if (label) {
        const std::size_t len = std::strlen(label);
        sha_update_(reinterpret_cast<const std::uint8_t*>(label), len);
    }
    buff_.reserve(1024);
}

void Transcript::domain_sep(const std::uint8_t* label, std::size_t label_len) {
    buff_.insert(buff_.end(), label, label + label_len);
}

void Transcript::append_message(const std::uint8_t* msg, std::size_t msg_len,
                                const std::uint8_t* label, std::size_t label_len) {
    buff_.insert(buff_.end(), label, label + label_len);
    buff_.insert(buff_.end(), msg, msg + msg_len);
}

void Transcript::append_scalar(const Fr& scalar,
                               const std::uint8_t* label, std::size_t label_len) {
    std::uint8_t le[32];
    scalar.to_bytes_le(le);
    append_message(le, 32, label, label_len);
}

void Transcript::append_point(const Element& point,
                              const std::uint8_t* label, std::size_t label_len) {
    std::uint8_t be[32];
    point.serialize_compressed(be);
    append_message(be, 32, label, label_len);
}

Fr Transcript::challenge_scalar(const std::uint8_t* label, std::size_t label_len) {
    domain_sep(label, label_len);
    sha_update_(buff_.data(), buff_.size());
    buff_.clear();
    std::uint8_t hash_be[32];
    sha_final_(hash_be);
    // Match Go's `SetBytesLE(sha_sum)`: treat the raw SHA output as a
    // little-endian canonical integer (no in-place byte reverse).
    // (Go's SetBytesLE reverses-then-SetBytes-BE, which is the same big-int
    // value as reading the original bytes directly as little-endian.)

    Fr challenge = Fr::zero();
    {
        std::uint64_t raw[4] = {0, 0, 0, 0};
        for (int i = 0; i < 4; ++i) {
            for (int b = 0; b < 8; ++b) {
                raw[i] |= static_cast<std::uint64_t>(hash_be[8 * i + b]) << (8 * b);
            }
        }
        constexpr std::uint64_t r0 = 0x74fd06b52876e7e1ULL;
        constexpr std::uint64_t r1 = 0xff8f870074190471ULL;
        constexpr std::uint64_t r2 = 0x0cce760202687600ULL;
        constexpr std::uint64_t r3 = 0x1cfb69d4ca675f52ULL;
        auto cmp_ge_r = [&](const std::uint64_t v[4]) -> bool {
            if (v[3] != r3) return v[3] > r3;
            if (v[2] != r2) return v[2] > r2;
            if (v[1] != r1) return v[1] > r1;
            return v[0] >= r0;
        };
        auto sub_r = [&](std::uint64_t v[4]) {
            __uint128_t b = 0, t;
            t = (__uint128_t)v[0] - r0 - b; v[0] = (std::uint64_t)t; b = (t >> 127) & 1;
            t = (__uint128_t)v[1] - r1 - b; v[1] = (std::uint64_t)t; b = (t >> 127) & 1;
            t = (__uint128_t)v[2] - r2 - b; v[2] = (std::uint64_t)t; b = (t >> 127) & 1;
            t = (__uint128_t)v[3] - r3 - b; v[3] = (std::uint64_t)t;
        };
        while (cmp_ge_r(raw)) sub_r(raw);
        std::uint8_t canon_le[32];
        for (int i = 0; i < 4; ++i) {
            for (int b = 0; b < 8; ++b) {
                canon_le[8 * i + b] = static_cast<std::uint8_t>(raw[i] >> (8 * b));
            }
        }
        (void)Fr::from_bytes_le(canon_le, challenge);
    }

    sha_init_();
    append_scalar(challenge, label, label_len);
    return challenge;
}

namespace {

Fr fr_from_u64(std::uint64_t v) {
    std::uint8_t le[32] = {0};
    for (int i = 0; i < 8; ++i) le[i] = static_cast<std::uint8_t>(v >> (8 * i));
    Fr out;
    Fr::from_bytes_le(le, out);
    return out;
}

bool fr_canonical_lt_u64(const Fr& a, std::uint64_t bound) {
    std::uint8_t le[32];
    a.to_bytes_le(le);
    for (int i = 8; i < 32; ++i) {
        if (le[i] != 0) return false;
    }
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= static_cast<std::uint64_t>(le[i]) << (8 * i);
    return v < bound;
}

std::uint64_t fr_canonical_to_u64(const Fr& a) {
    std::uint8_t le[32];
    a.to_bytes_le(le);
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= static_cast<std::uint64_t>(le[i]) << (8 * i);
    return v;
}

void fr_batch_invert(Fr* xs, std::size_t n) {
    if (n == 0) return;
    std::vector<Fr> partial(n);
    Fr acc = Fr::one();
    for (std::size_t i = 0; i < n; ++i) {
        partial[i] = acc;
        if (!xs[i].is_zero()) acc = Fr::mul(acc, xs[i]);
    }
    Fr inv_acc = Fr::inv(acc);
    for (std::size_t i = n; i-- > 0;) {
        if (xs[i].is_zero()) continue;
        Fr orig = xs[i];
        xs[i] = Fr::mul(partial[i], inv_acc);
        inv_acc = Fr::mul(inv_acc, orig);
    }
}

void generate_srs(std::array<Element, kVectorLength>& srs) {
    static constexpr char kSeed[] = "eth_verkle_oct_2021";
    constexpr std::size_t kSeedLen = sizeof(kSeed) - 1;

    std::size_t found = 0;
    std::uint64_t counter = 0;
    while (found < kVectorLength) {
        std::uint32_t H[8] = {
            0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
            0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
        };
        std::uint8_t buf[64] = {0};
        std::memcpy(buf, kSeed, kSeedLen);
        for (int i = 0; i < 8; ++i) {
            buf[kSeedLen + i] = static_cast<std::uint8_t>(counter >> (8 * (7 - i)));
        }
        std::size_t payload_len = kSeedLen + 8;
        buf[payload_len] = 0x80;
        std::uint64_t bits = static_cast<std::uint64_t>(payload_len) * 8;
        for (int i = 7; i >= 0; --i) {
            buf[64 - 8 + (7 - i)] = static_cast<std::uint8_t>(bits >> (8 * i));
        }
        sha256_compress(H, buf);
        std::uint8_t hash[32];
        for (int i = 0; i < 8; ++i) {
            hash[4 * i + 0] = static_cast<std::uint8_t>(H[i] >> 24);
            hash[4 * i + 1] = static_cast<std::uint8_t>(H[i] >> 16);
            hash[4 * i + 2] = static_cast<std::uint8_t>(H[i] >> 8);
            hash[4 * i + 3] = static_cast<std::uint8_t>(H[i]);
        }
        ++counter;

        ::kinet::banderwagon::Fp x_fp;
        std::uint64_t raw[4] = {0, 0, 0, 0};
        for (int i = 0; i < 4; ++i) {
            for (int b = 0; b < 8; ++b) {
                raw[i] |= static_cast<std::uint64_t>(hash[31 - 8 * i - b]) << (8 * b);
            }
        }
        constexpr std::uint64_t q0 = 0xffffffff00000001ULL;
        constexpr std::uint64_t q1 = 0x53bda402fffe5bfeULL;
        constexpr std::uint64_t q2 = 0x3339d80809a1d805ULL;
        constexpr std::uint64_t q3 = 0x73eda753299d7d48ULL;
        auto cmp_ge_q = [&](const std::uint64_t v[4]) -> bool {
            if (v[3] != q3) return v[3] > q3;
            if (v[2] != q2) return v[2] > q2;
            if (v[1] != q1) return v[1] > q1;
            return v[0] >= q0;
        };
        auto sub_q = [&](std::uint64_t v[4]) {
            __uint128_t b = 0, t;
            t = (__uint128_t)v[0] - q0 - b; v[0] = (std::uint64_t)t; b = (t >> 127) & 1;
            t = (__uint128_t)v[1] - q1 - b; v[1] = (std::uint64_t)t; b = (t >> 127) & 1;
            t = (__uint128_t)v[2] - q2 - b; v[2] = (std::uint64_t)t; b = (t >> 127) & 1;
            t = (__uint128_t)v[3] - q3 - b; v[3] = (std::uint64_t)t;
        };
        while (cmp_ge_q(raw)) sub_q(raw);
        std::uint8_t canon_be[32];
        for (int i = 0; i < 4; ++i) {
            for (int b = 0; b < 8; ++b) {
                canon_be[31 - 8 * i - b] = static_cast<std::uint8_t>(raw[i] >> (8 * b));
            }
        }
        ::kinet::banderwagon::Fp::from_bytes_be(canon_be, x_fp);
        std::uint8_t x_be[32];
        x_fp.to_bytes_be(x_be);
        Element P;
        if (!Element::deserialize_compressed(x_be, P)) continue;
        srs[found] = P;
        ++found;
    }
}

const std::uint8_t kLabelDomainSep[]   = {'i', 'p', 'a'};
const std::uint8_t kLabelC[]           = {'C'};
const std::uint8_t kLabelInputPoint[]  = {'i', 'n', 'p', 'u', 't', ' ', 'p', 'o', 'i', 'n', 't'};
const std::uint8_t kLabelOutputPoint[] = {'o', 'u', 't', 'p', 'u', 't', ' ', 'p', 'o', 'i', 'n', 't'};
const std::uint8_t kLabelW[]           = {'w'};
const std::uint8_t kLabelL[]           = {'L'};
const std::uint8_t kLabelR[]           = {'R'};
const std::uint8_t kLabelX[]           = {'x'};

}  // namespace

bool Config::init() {
    generate_srs(srs);
    q = Element::generator();

    for (std::uint64_t i = 0; i < kVectorLength; ++i) {
        Fr i_fr = fr_from_u64(i);
        Fr w = Fr::one();
        for (std::uint64_t j = 0; j < kVectorLength; ++j) {
            if (j == i) continue;
            Fr j_fr = fr_from_u64(j);
            w = Fr::mul(w, Fr::sub(i_fr, j_fr));
        }
        bary_weights[i] = w;
    }
    Fr tmp[kVectorLength];
    for (std::size_t i = 0; i < kVectorLength; ++i) tmp[i] = bary_weights[i];
    fr_batch_invert(tmp, kVectorLength);
    for (std::size_t i = 0; i < kVectorLength; ++i) {
        bary_weights[i + kVectorLength] = tmp[i];
    }

    Fr d_tmp[kVectorLength - 1];
    for (std::uint64_t i = 1; i < kVectorLength; ++i) {
        d_tmp[i - 1] = fr_from_u64(i);
    }
    fr_batch_invert(d_tmp, kVectorLength - 1);
    for (std::uint64_t i = 1; i < kVectorLength; ++i) {
        inv_domain[i - 1] = d_tmp[i - 1];
        inv_domain[(i - 1) + (kVectorLength - 1)] = Fr::neg(d_tmp[i - 1]);
    }
    return true;
}

void IPAProof::serialize(std::uint8_t out[kSerializedSize]) const {
    for (std::size_t i = 0; i < kNumRounds; ++i) {
        L[i].serialize_compressed(out + i * 32);
    }
    for (std::size_t i = 0; i < kNumRounds; ++i) {
        R[i].serialize_compressed(out + (kNumRounds + i) * 32);
    }
    a_final.to_bytes_le(out + 2 * kNumRounds * 32);
}

bool IPAProof::deserialize(const std::uint8_t in[kSerializedSize], IPAProof& out) {
    for (std::size_t i = 0; i < kNumRounds; ++i) {
        if (!Element::deserialize_compressed(in + i * 32, out.L[i])) return false;
    }
    for (std::size_t i = 0; i < kNumRounds; ++i) {
        if (!Element::deserialize_compressed(in + (kNumRounds + i) * 32, out.R[i])) return false;
    }
    return Fr::from_bytes_le(in + 2 * kNumRounds * 32, out.a_final);
}

Fr inner_product(const Fr* a, const Fr* b, std::size_t n) {
    Fr acc = Fr::zero();
    for (std::size_t i = 0; i < n; ++i) {
        acc = Fr::add(acc, Fr::mul(a[i], b[i]));
    }
    return acc;
}

Element commit(const ProverConfig& cfg, const Fr polynomial[kVectorLength]) {
    return ::kinet::banderwagon::multi_scalar_mul(cfg.srs.data(), polynomial, kVectorLength);
}

namespace {

void compute_b_vector(const Config& cfg, const Fr& eval_point,
                      Fr b_out[kVectorLength]) {
    if (fr_canonical_lt_u64(eval_point, kVectorLength)) {
        std::uint64_t idx = fr_canonical_to_u64(eval_point);
        for (std::size_t i = 0; i < kVectorLength; ++i) b_out[i] = Fr::zero();
        b_out[idx] = Fr::one();
        return;
    }
    Fr lag[kVectorLength];
    for (std::uint64_t i = 0; i < kVectorLength; ++i) {
        Fr i_fr = fr_from_u64(i);
        Fr diff = Fr::sub(eval_point, i_fr);
        lag[i] = Fr::mul(diff, cfg.bary_weights[i]);
    }
    Fr total = Fr::one();
    for (std::uint64_t i = 0; i < kVectorLength; ++i) {
        Fr i_fr = fr_from_u64(i);
        total = Fr::mul(total, Fr::sub(eval_point, i_fr));
    }
    fr_batch_invert(lag, kVectorLength);
    for (std::size_t i = 0; i < kVectorLength; ++i) {
        b_out[i] = Fr::mul(lag[i], total);
    }
}

}  // namespace

int create_proof(const ProverConfig& cfg,
                 Transcript& transcript,
                 const Element& commitment,
                 const Fr a_in[kVectorLength],
                 const Fr& eval_point,
                 IPAProof& out_proof,
                 Fr& out_y) {
    transcript.domain_sep(kLabelDomainSep, sizeof(kLabelDomainSep));

    std::vector<Fr> a(a_in, a_in + kVectorLength);
    std::vector<Fr> b(kVectorLength);
    compute_b_vector(cfg, eval_point, b.data());

    Fr inner = inner_product(a.data(), b.data(), kVectorLength);
    out_y = inner;

    transcript.append_point(commitment, kLabelC, sizeof(kLabelC));
    transcript.append_scalar(eval_point, kLabelInputPoint, sizeof(kLabelInputPoint));
    transcript.append_scalar(inner, kLabelOutputPoint, sizeof(kLabelOutputPoint));
    Fr w = transcript.challenge_scalar(kLabelW, sizeof(kLabelW));

    Element q = Element::scalar_mul(cfg.q, w);

    std::vector<Element> basis(cfg.srs.begin(), cfg.srs.end());

    std::size_t n = kVectorLength;
    for (std::size_t round = 0; round < kNumRounds; ++round) {
        std::size_t half = n / 2;
        const Fr*       a_L = a.data();
        const Fr*       a_R = a.data() + half;
        const Fr*       b_L = b.data();
        const Fr*       b_R = b.data() + half;
        const Element*  G_L = basis.data();
        const Element*  G_R = basis.data() + half;

        Fr z_L = inner_product(a_R, b_L, half);
        Fr z_R = inner_product(a_L, b_R, half);

        Element C_L1 = ::kinet::banderwagon::multi_scalar_mul(G_L, a_R, half);
        Element C_L  = Element::add(C_L1, Element::scalar_mul(q, z_L));

        Element C_R1 = ::kinet::banderwagon::multi_scalar_mul(G_R, a_L, half);
        Element C_R  = Element::add(C_R1, Element::scalar_mul(q, z_R));

        out_proof.L[round] = C_L;
        out_proof.R[round] = C_R;

        transcript.append_point(C_L, kLabelL, sizeof(kLabelL));
        transcript.append_point(C_R, kLabelR, sizeof(kLabelR));
        Fr x    = transcript.challenge_scalar(kLabelX, sizeof(kLabelX));
        Fr xInv = Fr::inv(x);

        std::vector<Fr> a_new(half);
        std::vector<Fr> b_new(half);
        std::vector<Element> g_new(half);
        for (std::size_t i = 0; i < half; ++i) {
            a_new[i] = Fr::add(a_L[i], Fr::mul(x,    a_R[i]));
            b_new[i] = Fr::add(b_L[i], Fr::mul(xInv, b_R[i]));
            g_new[i] = Element::add(G_L[i],
                                    Element::scalar_mul(G_R[i], xInv));
        }
        a = std::move(a_new);
        b = std::move(b_new);
        basis = std::move(g_new);
        n = half;
    }

    if (a.size() != 1) return -2;
    out_proof.a_final = a[0];
    return 0;
}

int check_proof(const VerifierConfig& cfg,
                Transcript& transcript,
                const Element& commitment_in,
                const IPAProof& proof,
                const Fr& eval_point,
                const Fr& claimed_y) {
    transcript.domain_sep(kLabelDomainSep, sizeof(kLabelDomainSep));

    std::vector<Fr> b(kVectorLength);
    compute_b_vector(cfg, eval_point, b.data());

    transcript.append_point(commitment_in, kLabelC, sizeof(kLabelC));
    transcript.append_scalar(eval_point, kLabelInputPoint, sizeof(kLabelInputPoint));
    transcript.append_scalar(claimed_y, kLabelOutputPoint, sizeof(kLabelOutputPoint));
    Fr w = transcript.challenge_scalar(kLabelW, sizeof(kLabelW));

    Element q  = Element::scalar_mul(cfg.q, w);
    Element qy = Element::scalar_mul(q, claimed_y);
    Element commitment = Element::add(commitment_in, qy);

    std::array<Fr, kNumRounds> challenges;
    std::array<Fr, kNumRounds> challenges_inv;
    for (std::size_t i = 0; i < kNumRounds; ++i) {
        transcript.append_point(proof.L[i], kLabelL, sizeof(kLabelL));
        transcript.append_point(proof.R[i], kLabelR, sizeof(kLabelR));
        challenges[i] = transcript.challenge_scalar(kLabelX, sizeof(kLabelX));
    }
    {
        Fr tmp[kNumRounds];
        for (std::size_t i = 0; i < kNumRounds; ++i) tmp[i] = challenges[i];
        fr_batch_invert(tmp, kNumRounds);
        for (std::size_t i = 0; i < kNumRounds; ++i) challenges_inv[i] = tmp[i];
    }

    for (std::size_t i = 0; i < kNumRounds; ++i) {
        commitment = Element::add(
            commitment,
            Element::add(
                Element::scalar_mul(proof.L[i], challenges[i]),
                Element::scalar_mul(proof.R[i], challenges_inv[i])));
    }

    std::array<Fr, kVectorLength> folding;
    for (std::size_t i = 0; i < kVectorLength; ++i) {
        Fr s = Fr::one();
        for (std::size_t c = 0; c < kNumRounds; ++c) {
            if (i & (std::size_t{1} << (kNumRounds - 1 - c))) {
                s = Fr::mul(s, challenges_inv[c]);
            }
        }
        folding[i] = s;
    }
    Element g0 = ::kinet::banderwagon::multi_scalar_mul(
        cfg.srs.data(), folding.data(), kVectorLength);
    Fr b0 = inner_product(b.data(), folding.data(), kVectorLength);

    Element got = Element::add(
        Element::scalar_mul(g0, proof.a_final),
        Element::scalar_mul(q, Fr::mul(b0, proof.a_final)));

    return Element::equal(got, commitment) ? 0 : -2;
}

}  // namespace kinet::crypto::ipa
