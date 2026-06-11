// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// ipa/c-abi/c_ipa.cpp -- C ABI for the Banderwagon IPA prover/verifier.

#include "kinet_crypto.h"
#include "../cpp/ipa.hpp"

#include <cstring>
#include <new>

extern "C" {

int ipa_commit(const uint8_t* /*coeffs*/, size_t /*n*/, uint8_t /*commit*/[48]) {
    return CRYPTO_ERR_NOTIMPL;
}
int ipa_verify(const uint8_t /*commit*/[48], const uint8_t* /*proof*/, size_t /*proof_len*/) {
    return CRYPTO_ERR_NOTIMPL;
}

static kinet::crypto::ipa::Config* g_cfg = nullptr;

static kinet::crypto::ipa::Config* get_cfg() {
    if (g_cfg == nullptr) {
        auto* cfg = new (std::nothrow) kinet::crypto::ipa::Config();
        if (cfg == nullptr) return nullptr;
        if (!cfg->init()) { delete cfg; return nullptr; }
        g_cfg = cfg;
    }
    return g_cfg;
}

int ipa_config_init(void) {
    return (get_cfg() != nullptr) ? CRYPTO_OK : CRYPTO_ERR_INTERNAL;
}

int ipa_create_proof(const uint8_t* coeffs_le,
                     const uint8_t   eval_le[32],
                     uint8_t         commitment_be[32],
                     uint8_t         proof_out[kinet::crypto::ipa::IPAProof::kSerializedSize],
                     uint8_t         y_le[32]) {
    using namespace kinet::crypto::ipa;
    if (coeffs_le == nullptr || eval_le == nullptr || commitment_be == nullptr ||
        proof_out == nullptr || y_le == nullptr) {
        return CRYPTO_ERR_INPUT;
    }
    auto* cfg = get_cfg();
    if (cfg == nullptr) return CRYPTO_ERR_INTERNAL;

    Fr a[kVectorLength];
    for (size_t i = 0; i < kVectorLength; ++i) {
        if (!Fr::from_bytes_le(coeffs_le + i * 32, a[i])) return CRYPTO_ERR_INPUT;
    }
    Fr eval;
    if (!Fr::from_bytes_le(eval_le, eval)) return CRYPTO_ERR_INPUT;

    Element commitment = commit(*cfg, a);
    commitment.serialize_compressed(commitment_be);

    Transcript transcript("ipa");
    IPAProof   proof;
    Fr         y;
    int rc = create_proof(*cfg, transcript, commitment, a, eval, proof, y);
    if (rc != 0) return CRYPTO_ERR_INTERNAL;

    proof.serialize(proof_out);
    y.to_bytes_le(y_le);
    return CRYPTO_OK;
}

int ipa_check_proof(const uint8_t commitment_be[32],
                    const uint8_t eval_le[32],
                    const uint8_t y_le[32],
                    const uint8_t proof_in[kinet::crypto::ipa::IPAProof::kSerializedSize]) {
    using namespace kinet::crypto::ipa;
    if (commitment_be == nullptr || eval_le == nullptr ||
        y_le == nullptr || proof_in == nullptr) {
        return CRYPTO_ERR_INPUT;
    }
    auto* cfg = get_cfg();
    if (cfg == nullptr) return CRYPTO_ERR_INTERNAL;

    Element commitment;
    if (!Element::deserialize_compressed(commitment_be, commitment)) {
        return CRYPTO_ERR_INPUT;
    }
    Fr eval;
    if (!Fr::from_bytes_le(eval_le, eval))     return CRYPTO_ERR_INPUT;
    Fr y;
    if (!Fr::from_bytes_le(y_le, y))           return CRYPTO_ERR_INPUT;
    IPAProof proof;
    if (!IPAProof::deserialize(proof_in, proof)) return CRYPTO_ERR_INPUT;

    Transcript transcript("ipa");
    int rc = check_proof(*cfg, transcript, commitment, proof, eval, y);
    return (rc == 0) ? CRYPTO_OK : CRYPTO_ERR_VERIFY;
}

struct ipa_transcript { kinet::crypto::ipa::Transcript* impl; };

ipa_transcript* ipa_transcript_new(const char* label) {
    auto* t = new (std::nothrow) ipa_transcript();
    if (t == nullptr) return nullptr;
    t->impl = new (std::nothrow) kinet::crypto::ipa::Transcript(label != nullptr ? label : "");
    if (t->impl == nullptr) { delete t; return nullptr; }
    return t;
}

void ipa_transcript_free(ipa_transcript* t) {
    if (t == nullptr) return;
    delete t->impl;
    delete t;
}

int ipa_transcript_append_message(ipa_transcript* t,
                                  const uint8_t* msg, size_t msg_len,
                                  const uint8_t* label, size_t label_len) {
    if (t == nullptr || t->impl == nullptr) return CRYPTO_ERR_INPUT;
    t->impl->append_message(msg, msg_len, label, label_len);
    return CRYPTO_OK;
}

int ipa_transcript_append_scalar(ipa_transcript* t,
                                 const uint8_t scalar_le[32],
                                 const uint8_t* label, size_t label_len) {
    if (t == nullptr || t->impl == nullptr || scalar_le == nullptr) return CRYPTO_ERR_INPUT;
    kinet::banderwagon::Fr s;
    if (!kinet::banderwagon::Fr::from_bytes_le(scalar_le, s)) return CRYPTO_ERR_INPUT;
    t->impl->append_scalar(s, label, label_len);
    return CRYPTO_OK;
}

int ipa_transcript_append_point(ipa_transcript* t,
                                const uint8_t point_be[32],
                                const uint8_t* label, size_t label_len) {
    if (t == nullptr || t->impl == nullptr || point_be == nullptr) return CRYPTO_ERR_INPUT;
    kinet::banderwagon::Element p;
    if (!kinet::banderwagon::Element::deserialize_compressed(point_be, p)) return CRYPTO_ERR_INPUT;
    t->impl->append_point(p, label, label_len);
    return CRYPTO_OK;
}

int ipa_transcript_challenge_scalar(ipa_transcript* t,
                                    const uint8_t* label, size_t label_len,
                                    uint8_t out_le[32]) {
    if (t == nullptr || t->impl == nullptr || out_le == nullptr) return CRYPTO_ERR_INPUT;
    kinet::banderwagon::Fr c = t->impl->challenge_scalar(label, label_len);
    c.to_bytes_le(out_le);
    return CRYPTO_OK;
}

}  // extern "C"
