// CPU vs Metal byte-equality test for Lamport-SHA256 OTS.
//
// 100 deterministic vectors. For each vector we:
//   - keygen(seed_i)  -> sk, pk on CPU
//   - sign(msg_i)     -> sig
//   - verify(pk, msg, sig) -> must be true
//   - hash all preimage slots on the GPU and assert byte-equality with the
//     CPU pubkey hashes.
//
// "preimage slots" covers both keygen (sk -> pk) and verify (sig -> hash to
// compare against pk), so a single hash dispatch is enough to prove byte
// equality across the full Lamport surface.

#include "../cpp/lamport.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#if __APPLE__
#include "../gpu/metal/lamport_driver.h"
#endif

namespace lp = kinet::crypto::lamport;

namespace {

uint64_t lcg_state = 0xC0FFEE0123456789ULL;
uint8_t lcg_byte() {
    lcg_state = lcg_state * 6364136223846793005ULL + 1442695040888963407ULL;
    return uint8_t(lcg_state >> 33);
}

void fill_random(uint8_t* p, size_t n) { for (size_t i = 0; i < n; ++i) p[i] = lcg_byte(); }

}  // namespace

int main() {
    std::fprintf(stdout, "=== lamport CPU vs Metal byte-equality (LP-2506) ===\n");

#if __APPLE__
    const char* metallib = std::getenv("CRYPTO_LAMPORT_METALLIB");
    if (!metallib) {
        std::fprintf(stdout, "(skip GPU equality: CRYPTO_LAMPORT_METALLIB unset)\n");
        std::fprintf(stdout, "=== ALL TESTS PASSED (GPU skipped) ===\n");
        return 0;
    }

    constexpr size_t N = 100;
    std::vector<uint8_t> seeds(N * 32);
    std::vector<uint8_t> msgs (N * 32);
    fill_random(seeds.data(), seeds.size());
    fill_random(msgs .data(), msgs .size());

    std::vector<uint8_t> sks(N * lp::SK_SIZE);
    std::vector<uint8_t> pks(N * lp::PK_SIZE);
    std::vector<uint8_t> sigs(N * lp::SIG_SIZE);

    int verify_pass = 0;
    for (size_t i = 0; i < N; ++i) {
        lp::keygen(&seeds[i*32],
                   &sks[i * lp::SK_SIZE],
                   &pks[i * lp::PK_SIZE]);
        lp::sign  (&sks[i * lp::SK_SIZE],
                   &msgs[i*32],
                   &sigs[i * lp::SIG_SIZE]);
        if (lp::verify(&pks[i * lp::PK_SIZE],
                       &msgs[i*32],
                       &sigs[i * lp::SIG_SIZE])) {
            ++verify_pass;
        }
    }
    if (verify_pass != (int)N) {
        std::fprintf(stderr, "FAIL CPU verify pass count: %d/%zu\n", verify_pass, N);
        return 1;
    }
    std::fprintf(stdout, "PASS CPU keygen/sign/verify %d/%zu\n", verify_pass, N);

    // Build the preimage arena: per key, all 512 sk slots followed by all 256
    // sig slots, totalling 768 hashes per key.
    constexpr size_t SLOTS_PER_KEY = lp::MSG_BITS * 2 + lp::MSG_BITS;  // 768
    const size_t total_slots = N * SLOTS_PER_KEY;
    std::vector<uint8_t> slots  (total_slots * lp::HASH_SIZE);
    std::vector<uint8_t> cpu_dig(total_slots * lp::HASH_SIZE);
    std::vector<uint8_t> gpu_dig(total_slots * lp::HASH_SIZE);

    // Pack slots and CPU-expected digests.
    for (size_t i = 0; i < N; ++i) {
        const uint8_t* sk = &sks[i * lp::SK_SIZE];
        const uint8_t* pk = &pks[i * lp::PK_SIZE];
        const uint8_t* sg = &sigs[i * lp::SIG_SIZE];
        const uint8_t* mg = &msgs[i*32];

        // 512 sk slots -> expect pk slots.
        for (size_t k = 0; k < lp::MSG_BITS * 2; ++k) {
            const size_t s = (i * SLOTS_PER_KEY + k) * lp::HASH_SIZE;
            std::memcpy(&slots[s], sk + k * lp::HASH_SIZE, lp::HASH_SIZE);
            std::memcpy(&cpu_dig[s], pk + k * lp::HASH_SIZE, lp::HASH_SIZE);
        }
        // 256 sig slots -> expect pk[2*i + bit_i].
        for (size_t bit = 0; bit < lp::MSG_BITS; ++bit) {
            const size_t s = (i * SLOTS_PER_KEY + lp::MSG_BITS * 2 + bit) * lp::HASH_SIZE;
            std::memcpy(&slots[s], sg + bit * lp::HASH_SIZE, lp::HASH_SIZE);
            const uint8_t b = lp::msg_bit(mg, bit);
            const size_t pk_slot = bit * 2 + b;
            std::memcpy(&cpu_dig[s], pk + pk_slot * lp::HASH_SIZE, lp::HASH_SIZE);
        }
    }

    int rc = lamport_hash_batch_metal(slots.data(), total_slots,
                                      gpu_dig.data(), metallib);
    if (rc != 0) {
        std::fprintf(stderr, "FAIL Metal dispatch rc=%d\n", rc);
        return 1;
    }
    std::fprintf(stdout, "PASS Metal dispatch rc=0 (%zu slots)\n", total_slots);

    int eq_full = 0;
    for (size_t i = 0; i < N; ++i) {
        bool ok = std::memcmp(&cpu_dig[i * SLOTS_PER_KEY * lp::HASH_SIZE],
                              &gpu_dig[i * SLOTS_PER_KEY * lp::HASH_SIZE],
                              SLOTS_PER_KEY * lp::HASH_SIZE) == 0;
        if (ok) ++eq_full;
    }
    int failures = (eq_full == (int)N) ? 0 : 1;
    char ok[80];
    std::snprintf(ok, sizeof(ok), "byte-equal %d/%zu vectors", eq_full, N);
    if (eq_full == (int)N) std::fprintf(stdout, "PASS %s\n", ok);
    else                   std::fprintf(stderr, "FAIL %s\n", ok);
    std::fprintf(stdout, "=== %s ===\n",
                 failures == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED");
    return failures;
#else
    std::fprintf(stdout, "(non-Apple host: GPU equality skipped)\n");
    std::fprintf(stdout, "=== ALL TESTS PASSED (no Metal) ===\n");
    return 0;
#endif
}
