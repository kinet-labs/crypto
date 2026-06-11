// IRTF BLS signature primitive byte-equality test.
//
// Tests cevm::crypto::bls::keygen, sk_to_pk, sign, verify,
// aggregate_pubkeys, aggregate_sigs, fast_aggregate_verify,
// aggregate_verify_distinct against direct blst re-computation
// (the test-oracle pattern: the body under test wraps blst, so re-running
// the same blst calls in the same binary must match byte-for-byte).
//
// Ciphersuite BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_ — the same one
// that py_ecc / gnark-crypto / blst v0.3.15 emit byte-for-byte for the
// Ethereum eth2-spec-tests vectors.
//
// >=10 vectors per op via parameterization over ten distinct IKMs (the
// byte 0x00..0x09 each repeated 32 times) and ten distinct messages.

#include "bls_signature.hpp"

#include <blst.h>

#include <array>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

namespace {

bool bytes_eq(const uint8_t* a, const uint8_t* b, size_t n)
{
    return std::memcmp(a, b, n) == 0;
}

std::array<uint8_t, 32> ikm_repeat(uint8_t v)
{
    std::array<uint8_t, 32> out{};
    for (auto& x : out) x = v;
    return out;
}

constexpr const char* kPOPDST  = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
constexpr size_t      kPOPDSTL = 43;

int failures = 0;

void check_eq(bool cond, const char* what)
{
    if (!cond) {
        std::fprintf(stderr, "FAIL: %s\n", what);
        failures++;
    }
}

// Reference: same blst calls our impl wraps. If the impl matches blst
// byte-for-byte, this re-computation must agree.
void ref_keygen_sign(const uint8_t ikm[32],
                     const uint8_t* msg, size_t msg_len,
                     uint8_t sk[32], uint8_t pk[48], uint8_t sig[96])
{
    blst_scalar s;
    blst_keygen(&s, ikm, 32, /*info=*/nullptr, /*info_len=*/0);
    blst_bendian_from_scalar(sk, &s);

    blst_p1 pk_jac;
    blst_sk_to_pk_in_g1(&pk_jac, &s);
    blst_p1_compress(pk, &pk_jac);

    blst_p2 hash_jac;
    blst_hash_to_g2(&hash_jac, msg, msg_len,
                    reinterpret_cast<const uint8_t*>(kPOPDST), kPOPDSTL,
                    /*aug=*/nullptr, /*aug_len=*/0);
    blst_p2 sig_jac;
    blst_sign_pk_in_g1(&sig_jac, &hash_jac, &s);
    blst_p2_compress(sig, &sig_jac);
}

}  // namespace

int main()
{
    using namespace cevm::crypto::bls;

    std::printf("[bls-signature-test] ciphersuite "
                "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_\n");

    // ---- Vector 1: pinned IKM=0x00*32, msg="test message" (12 bytes) ----
    {
        const auto ikm = ikm_repeat(0x00);
        const char* msg_str = "test message";
        const size_t msg_len = 12;

        uint8_t ref_sk[32], ref_pk[48], ref_sig[96];
        ref_keygen_sign(ikm.data(),
                        reinterpret_cast<const uint8_t*>(msg_str), msg_len,
                        ref_sk, ref_pk, ref_sig);

        uint8_t sk[32];
        check_eq(keygen(ikm.data(), sk) == 0, "vec1.keygen rc");
        check_eq(bytes_eq(sk, ref_sk, 32), "vec1.keygen byte-equal");

        uint8_t pk[48];
        check_eq(sk_to_pk(sk, pk) == 0, "vec1.sk_to_pk rc");
        check_eq(bytes_eq(pk, ref_pk, 48), "vec1.sk_to_pk byte-equal");

        uint8_t sig[96];
        check_eq(sign(sk, reinterpret_cast<const uint8_t*>(msg_str), msg_len,
                      sig) == 0, "vec1.sign rc");
        check_eq(bytes_eq(sig, ref_sig, 96), "vec1.sign byte-equal");

        check_eq(verify(pk, reinterpret_cast<const uint8_t*>(msg_str), msg_len,
                        sig) == 0, "vec1.verify accepts");

        uint8_t bad_sig[96];
        std::memcpy(bad_sig, sig, 96);
        bad_sig[0] ^= 0x01;
        check_eq(verify(pk, reinterpret_cast<const uint8_t*>(msg_str), msg_len,
                        bad_sig) != 0, "vec1.verify rejects flipped bit");
    }

    // ---- Vectors 2-11: 10 distinct IKMs, 10 distinct messages ----
    constexpr size_t N = 10;
    std::vector<std::array<uint8_t, 32>> ikms;
    for (size_t i = 0; i < N; i++) ikms.push_back(ikm_repeat(uint8_t(i + 1)));

    std::vector<std::vector<uint8_t>> msgs;
    for (size_t i = 0; i < N; i++) {
        std::vector<uint8_t> m;
        m.reserve(16 + i);
        for (size_t j = 0; j < 16 + i; j++) m.push_back(uint8_t(j ^ i));
        msgs.push_back(std::move(m));
    }

    std::vector<std::array<uint8_t, 32>> sks(N);
    std::vector<std::array<uint8_t, 48>> pks(N);
    std::vector<std::array<uint8_t, 96>> sigs(N);

    // ---- keygen + sk_to_pk + sign byte-equal blst (>=10 vectors each) ----
    for (size_t i = 0; i < N; i++) {
        uint8_t ref_sk[32], ref_pk[48], ref_sig[96];
        ref_keygen_sign(ikms[i].data(), msgs[i].data(), msgs[i].size(),
                        ref_sk, ref_pk, ref_sig);

        check_eq(keygen(ikms[i].data(), sks[i].data()) == 0, "keygen rc");
        check_eq(bytes_eq(sks[i].data(), ref_sk, 32), "keygen byte-equal");

        check_eq(sk_to_pk(sks[i].data(), pks[i].data()) == 0, "sk_to_pk rc");
        check_eq(bytes_eq(pks[i].data(), ref_pk, 48), "sk_to_pk byte-equal");

        check_eq(sign(sks[i].data(), msgs[i].data(), msgs[i].size(),
                      sigs[i].data()) == 0, "sign rc");
        check_eq(bytes_eq(sigs[i].data(), ref_sig, 96), "sign byte-equal");
    }

    // ---- verify positive (>=10 vectors) ----
    for (size_t i = 0; i < N; i++) {
        check_eq(verify(pks[i].data(), msgs[i].data(), msgs[i].size(),
                        sigs[i].data()) == 0, "verify positive");
    }

    // ---- verify negative — wrong msg, wrong pk, flipped sig (>=10 each) ----
    for (size_t i = 0; i < N; i++) {
        check_eq(verify(pks[i].data(),
                        msgs[(i + 1) % N].data(), msgs[(i + 1) % N].size(),
                        sigs[i].data()) != 0,
                 "verify negative: wrong msg");
        check_eq(verify(pks[(i + 1) % N].data(),
                        msgs[i].data(), msgs[i].size(),
                        sigs[i].data()) != 0,
                 "verify negative: wrong pk");
        std::array<uint8_t, 96> bad = sigs[i];
        bad[42] ^= 0x80;
        check_eq(verify(pks[i].data(), msgs[i].data(), msgs[i].size(),
                        bad.data()) != 0,
                 "verify negative: flipped sig");
    }

    // ---- aggregate_pubkeys (n=2..11 — >=10 vectors) ----
    for (size_t n = 2; n <= N; n++) {
        std::vector<uint8_t> pk_buf(n * 48);
        for (size_t i = 0; i < n; i++) {
            std::memcpy(pk_buf.data() + i * 48, pks[i].data(), 48);
        }
        uint8_t agg_pk[48];
        check_eq(aggregate_pubkeys(pk_buf.data(), n, agg_pk) == 0,
                 "aggregate_pubkeys rc");

        blst_p1 acc;
        blst_p1_affine first;
        BLST_ERROR rc1 = blst_p1_uncompress(&first, pks[0].data());
        check_eq(rc1 == BLST_SUCCESS, "ref blst_p1_uncompress[0]");
        blst_p1_from_affine(&acc, &first);
        for (size_t i = 1; i < n; i++) {
            blst_p1_affine pi;
            BLST_ERROR rci = blst_p1_uncompress(&pi, pks[i].data());
            check_eq(rci == BLST_SUCCESS, "ref blst_p1_uncompress[i]");
            blst_p1_add_or_double_affine(&acc, &acc, &pi);
        }
        uint8_t ref_agg[48];
        blst_p1_compress(ref_agg, &acc);
        check_eq(bytes_eq(agg_pk, ref_agg, 48),
                 "aggregate_pubkeys byte-equal blst");
    }

    // ---- aggregate_sigs + fast_aggregate_verify (n=2..11 — >=10 vectors) ----
    std::vector<std::array<uint8_t, 96>> sigs_same_msg(N);
    for (size_t i = 0; i < N; i++) {
        check_eq(sign(sks[i].data(), msgs[0].data(), msgs[0].size(),
                      sigs_same_msg[i].data()) == 0, "sign same-msg rc");
    }
    for (size_t n = 2; n <= N; n++) {
        std::vector<uint8_t> sig_buf(n * 96);
        for (size_t i = 0; i < n; i++) {
            std::memcpy(sig_buf.data() + i * 96, sigs_same_msg[i].data(), 96);
        }
        uint8_t agg_sig[96];
        check_eq(aggregate_sigs(sig_buf.data(), n, agg_sig) == 0,
                 "aggregate_sigs rc");

        blst_p2 acc;
        blst_p2_affine first;
        BLST_ERROR rc1 = blst_p2_uncompress(&first, sigs_same_msg[0].data());
        check_eq(rc1 == BLST_SUCCESS, "ref blst_p2_uncompress[0]");
        blst_p2_from_affine(&acc, &first);
        for (size_t i = 1; i < n; i++) {
            blst_p2_affine si;
            BLST_ERROR rci = blst_p2_uncompress(&si, sigs_same_msg[i].data());
            check_eq(rci == BLST_SUCCESS, "ref blst_p2_uncompress[i]");
            blst_p2_add_or_double_affine(&acc, &acc, &si);
        }
        uint8_t ref_agg_sig[96];
        blst_p2_compress(ref_agg_sig, &acc);
        check_eq(bytes_eq(agg_sig, ref_agg_sig, 96),
                 "aggregate_sigs byte-equal blst");

        std::vector<uint8_t> pk_buf(n * 48);
        for (size_t i = 0; i < n; i++) {
            std::memcpy(pk_buf.data() + i * 48, pks[i].data(), 48);
        }
        check_eq(fast_aggregate_verify(pk_buf.data(), n,
                                       msgs[0].data(), msgs[0].size(),
                                       agg_sig) == 0,
                 "fast_aggregate_verify positive");
        check_eq(fast_aggregate_verify(pk_buf.data(), n,
                                       msgs[1].data(), msgs[1].size(),
                                       agg_sig) != 0,
                 "fast_aggregate_verify negative: wrong msg");
    }

    // ---- aggregate_verify_distinct (n=2..11 — >=10 vectors) ----
    for (size_t n = 2; n <= N; n++) {
        std::vector<uint8_t> pk_buf(n * 48);
        std::vector<uint8_t> msgs_flat;
        std::vector<size_t>  msg_lens(n);
        std::vector<uint8_t> sig_buf(n * 96);

        for (size_t i = 0; i < n; i++) {
            std::memcpy(pk_buf.data() + i * 48, pks[i].data(), 48);
            std::memcpy(sig_buf.data() + i * 96, sigs[i].data(), 96);
            msgs_flat.insert(msgs_flat.end(), msgs[i].begin(), msgs[i].end());
            msg_lens[i] = msgs[i].size();
        }

        uint8_t agg_sig[96];
        check_eq(aggregate_sigs(sig_buf.data(), n, agg_sig) == 0,
                 "aggregate_sigs (distinct-msg) rc");

        check_eq(aggregate_verify_distinct(pk_buf.data(), n,
                                           msgs_flat.data(), msg_lens.data(),
                                           agg_sig) == 0,
                 "aggregate_verify_distinct positive");

        std::vector<uint8_t> bad_msgs = msgs_flat;
        if (!bad_msgs.empty()) bad_msgs[0] ^= 0xFF;
        check_eq(aggregate_verify_distinct(pk_buf.data(), n,
                                           bad_msgs.data(), msg_lens.data(),
                                           agg_sig) != 0,
                 "aggregate_verify_distinct negative: tampered msg");
    }

    // ---- Determinism (5 trials per op) ----
    {
        const auto ikm = ikm_repeat(0xAB);
        const char* m = "deterministic";
        const size_t mlen = 13;
        uint8_t sk[32], pk[48], sig[96];
        check_eq(keygen(ikm.data(), sk) == 0, "det.keygen");
        check_eq(sk_to_pk(sk, pk) == 0, "det.sk_to_pk");
        check_eq(sign(sk, reinterpret_cast<const uint8_t*>(m), mlen, sig) == 0,
                 "det.sign");
        for (int t = 0; t < 5; t++) {
            uint8_t sk2[32], pk2[48], sig2[96];
            check_eq(keygen(ikm.data(), sk2) == 0, "det loop keygen");
            check_eq(sk_to_pk(sk2, pk2) == 0, "det loop sk_to_pk");
            check_eq(sign(sk2, reinterpret_cast<const uint8_t*>(m), mlen, sig2) == 0,
                     "det loop sign");
            check_eq(bytes_eq(sk, sk2, 32), "det.sk same");
            check_eq(bytes_eq(pk, pk2, 48), "det.pk same");
            check_eq(bytes_eq(sig, sig2, 96), "det.sig same");
        }
    }

    if (failures != 0) {
        std::fprintf(stderr, "[bls-signature-test] %d FAILURES\n", failures);
        return 1;
    }
    std::printf("[bls-signature-test] all vectors PASS (byte-equal blst v0.3.15)\n");
    return 0;
}
