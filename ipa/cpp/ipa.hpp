// SPDX-License-Identifier: Apache-2.0
//
// ipa/ipa.hpp -- Bulletproofs-style Inner Product Argument over Banderwagon.
//
// Reference: github.com/kinet-labs/crypto/ipa (Go), Verkle-tree Bulletproofs IPA.
// Domain size and round count fixed (VectorLength = 256, numRounds = 8).
//
// Surface:
//   Config holds the SRS = 256 deterministically-derived Banderwagon
//   generators and Q = Banderwagon generator.
//
//   Transcript is the Fiat-Shamir transcript matching common.Transcript in
//   Go (SHA-256 backed, byte-equal).
//
//   IPAProof is { L[8], R[8], a_final }. Serializes to 544 bytes.
//
// Verifier is variable-time (public scalars). Prover handles only public
// poly evaluations -- variable-time is acceptable. First-party. No vendoring.

#pragma once

#include "../../banderwagon/cpp/element.hpp"
#include "../../banderwagon/cpp/fr.hpp"

#include <array>
#include <cstdint>
#include <cstddef>
#include <vector>

namespace kinet::crypto::ipa {

inline constexpr std::size_t kVectorLength = 256;
inline constexpr std::size_t kNumRounds = 8;

using ::kinet::banderwagon::Element;
using ::kinet::banderwagon::Fr;

class Transcript {
public:
    explicit Transcript(const char* label);

    void domain_sep(const std::uint8_t* label, std::size_t label_len);
    void append_message(const std::uint8_t* msg, std::size_t msg_len,
                        const std::uint8_t* label, std::size_t label_len);
    void append_scalar(const Fr& scalar,
                       const std::uint8_t* label, std::size_t label_len);
    void append_point(const Element& point,
                      const std::uint8_t* label, std::size_t label_len);

    Fr challenge_scalar(const std::uint8_t* label, std::size_t label_len);

private:
    std::array<std::uint32_t, 8> digest_state_;
    std::array<std::uint8_t, 64> digest_block_;
    std::size_t digest_block_len_;
    std::uint64_t digest_total_bits_;

    std::vector<std::uint8_t> buff_;

    void sha_init_();
    void sha_update_(const std::uint8_t* data, std::size_t len);
    void sha_final_(std::uint8_t out32[32]);
};

struct Config {
    std::array<Element, kVectorLength>      srs;
    Element                                  q;
    std::array<Fr, 2 * kVectorLength>       bary_weights;
    std::array<Fr, 2 * (kVectorLength - 1)> inv_domain;

    bool init();
};

using ProverConfig   = Config;
using VerifierConfig = Config;

struct IPAProof {
    std::array<Element, kNumRounds> L;
    std::array<Element, kNumRounds> R;
    Fr                              a_final;

    static constexpr std::size_t kSerializedSize = (kNumRounds + kNumRounds) * 32 + 32;

    void serialize(std::uint8_t out[kSerializedSize]) const;
    static bool deserialize(const std::uint8_t in[kSerializedSize], IPAProof& out);
};

int create_proof(const ProverConfig& cfg,
                 Transcript& transcript,
                 const Element& commitment,
                 const Fr a[kVectorLength],
                 const Fr& eval_point,
                 IPAProof& out_proof,
                 Fr& out_y);

int check_proof(const VerifierConfig& cfg,
                Transcript& transcript,
                const Element& commitment,
                const IPAProof& proof,
                const Fr& eval_point,
                const Fr& claimed_y);

Element commit(const ProverConfig& cfg, const Fr polynomial[kVectorLength]);
Fr inner_product(const Fr* a, const Fr* b, std::size_t n);

}  // namespace kinet::crypto::ipa
