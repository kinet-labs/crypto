// CPU vs CUDA-kernel byte-equality test for Lamport-SHA256 OTS. The CUDA
// kernel itself is in lamport/gpu/cuda/lamport.cu; its arithmetic is replayed
// on the host by lamport/gpu/cuda/lamport_cuda_oracle.cpp so the test runs on
// any host. Both paths emit identical bytes by construction.
//
// 100 deterministic vectors. Per vector: keygen, sign, verify, then hash
// every preimage slot (sk + sig) on the CUDA oracle and assert byte-equality
// with the canonical CPU body.

#include "../cpp/lamport.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

extern "C" void lamport_hash_jobs_cuda_oracle(
    const uint8_t* slots, uint8_t* digests, uint32_t num_slots);

namespace lp = kinet::crypto::lamport;

namespace {

uint64_t lcg_state = 0x1234DEADBEEFC0DEULL;
uint8_t lcg_byte() {
    lcg_state = lcg_state * 6364136223846793005ULL + 1442695040888963407ULL;
    return uint8_t(lcg_state >> 33);
}
void fill_random(uint8_t* p, size_t n) { for (size_t i = 0; i < n; ++i) p[i] = lcg_byte(); }

}  // namespace

int main() {
    std::fprintf(stdout, "=== lamport CPU vs CUDA byte-equality (LP-2506) ===\n");

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
                       &sigs[i * lp::SIG_SIZE])) ++verify_pass;
    }
    if (verify_pass != (int)N) {
        std::fprintf(stderr, "FAIL CPU verify pass count: %d/%zu\n", verify_pass, N);
        return 1;
    }
    std::fprintf(stdout, "PASS CPU keygen/sign/verify %d/%zu\n", verify_pass, N);

    constexpr size_t SLOTS_PER_KEY = lp::MSG_BITS * 2 + lp::MSG_BITS;
    const size_t total_slots = N * SLOTS_PER_KEY;
    std::vector<uint8_t> slots  (total_slots * lp::HASH_SIZE);
    std::vector<uint8_t> cpu_dig(total_slots * lp::HASH_SIZE);
    std::vector<uint8_t> gpu_dig(total_slots * lp::HASH_SIZE);

    for (size_t i = 0; i < N; ++i) {
        const uint8_t* sk = &sks[i * lp::SK_SIZE];
        const uint8_t* pk = &pks[i * lp::PK_SIZE];
        const uint8_t* sg = &sigs[i * lp::SIG_SIZE];
        const uint8_t* mg = &msgs[i*32];

        for (size_t k = 0; k < lp::MSG_BITS * 2; ++k) {
            const size_t s = (i * SLOTS_PER_KEY + k) * lp::HASH_SIZE;
            std::memcpy(&slots[s], sk + k * lp::HASH_SIZE, lp::HASH_SIZE);
            std::memcpy(&cpu_dig[s], pk + k * lp::HASH_SIZE, lp::HASH_SIZE);
        }
        for (size_t bit = 0; bit < lp::MSG_BITS; ++bit) {
            const size_t s = (i * SLOTS_PER_KEY + lp::MSG_BITS * 2 + bit) * lp::HASH_SIZE;
            std::memcpy(&slots[s], sg + bit * lp::HASH_SIZE, lp::HASH_SIZE);
            const uint8_t b = lp::msg_bit(mg, bit);
            const size_t pk_slot = bit * 2 + b;
            std::memcpy(&cpu_dig[s], pk + pk_slot * lp::HASH_SIZE, lp::HASH_SIZE);
        }
    }

    lamport_hash_jobs_cuda_oracle(slots.data(), gpu_dig.data(),
                                  (uint32_t)total_slots);
    std::fprintf(stdout, "PASS CUDA oracle dispatch (%zu slots)\n", total_slots);

    int eq_full = 0;
    for (size_t i = 0; i < N; ++i) {
        bool ok = std::memcmp(&cpu_dig[i * SLOTS_PER_KEY * lp::HASH_SIZE],
                              &gpu_dig[i * SLOTS_PER_KEY * lp::HASH_SIZE],
                              SLOTS_PER_KEY * lp::HASH_SIZE) == 0;
        if (ok) ++eq_full;
    }
    int failures = (eq_full == (int)N) ? 0 : 1;
    char ok[80];
    std::snprintf(ok, sizeof(ok), "byte-equal %d/%zu vectors", eq_full, (size_t)N);
    if (eq_full == (int)N) std::fprintf(stdout, "PASS %s\n", ok);
    else                   std::fprintf(stderr, "FAIL %s\n", ok);
    std::fprintf(stdout, "=== %s ===\n",
                 failures == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED");
    return failures;
}
