// Copyright (c) 2024-2026 Kinet Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Tests for the Keccak service (KeccakJobKind dedup + round cache).
//
// 1. 100 random jobs of mixed kinds -> outputs byte-equal to keccak256()
//    called directly per job.
// 2. Same input fed twice in one batch -> second slot is a copy of the first
//    (no extra hashing).
// 3. All 9 KeccakJobKind values exercised at least once.
// 4. Synthetic mapping-slot workload: hit rate ≥ 50% on round-cache.

#include "../cpp/keccak_service.hpp"

#include <cassert>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <unordered_map>

namespace lk = kinet::crypto::keccak;

static int g_failures = 0;

#define ASSERT_TRUE(name, cond) do { \
    if (!(cond)) { std::fprintf(stderr, "FAIL %s\n", name); ++g_failures; } \
    else        { std::fprintf(stdout, "PASS %s\n", name); } \
} while (0)

static uint64_t lcg(uint64_t& s) {
    s = s * 6364136223846793005ULL + 1442695040888963407ULL;
    return s;
}

// Generate `n` jobs of randomly assorted kinds and inputs (lengths 1..200).
static void build_random_workload(size_t n, uint64_t seed,
                                  std::vector<lk::KeccakJob>& jobs,
                                  std::vector<uint8_t>& inputs,
                                  std::vector<uint8_t>& outputs) {
    jobs.clear();
    inputs.clear();
    outputs.clear();

    uint64_t s = seed;
    uint32_t out_off = 0;
    for (size_t i = 0; i < n; ++i) {
        size_t len = (size_t)((lcg(s) % 199ULL) + 1ULL);
        uint32_t in_off = (uint32_t)inputs.size();
        for (size_t b = 0; b < len; ++b)
            inputs.push_back((uint8_t)(lcg(s) & 0xFF));

        lk::KeccakJob j;
        j.kind = (lk::KeccakJobKind)((uint16_t)(lcg(s) % lk::KECCAK_JOB_KIND_COUNT));
        j.input_offset_class = 0;
        j.input_offset = in_off;
        j.input_len = (uint32_t)len;
        j.output_offset = out_off;
        jobs.push_back(j);

        out_off += 32;
    }
    outputs.resize(out_off);
}

static void test_random_byte_equal() {
    std::vector<lk::KeccakJob> jobs;
    std::vector<uint8_t> inputs;
    std::vector<uint8_t> outputs;
    build_random_workload(100, 0xC001CAFEFEEDFEEDULL, jobs, inputs, outputs);

    size_t computed = lk::keccak_service_run(jobs.size(), jobs.data(),
                                             inputs.data(), outputs.data(),
                                             nullptr);
    (void)computed;

    int eq = 0;
    for (size_t i = 0; i < jobs.size(); ++i) {
        uint8_t want[32];
        keccak256(inputs.data() + jobs[i].input_offset,
                  jobs[i].input_len, want);
        if (std::memcmp(outputs.data() + jobs[i].output_offset, want, 32) == 0)
            ++eq;
    }
    char buf[80];
    std::snprintf(buf, sizeof(buf), "random workload byte-equal (%d/%zu)",
                  eq, jobs.size());
    ASSERT_TRUE(buf, eq == (int)jobs.size());
}

static void test_in_batch_dedup() {
    // Build a batch with the SAME input bytes appearing 3 times.
    const uint8_t input_bytes[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33};
    std::vector<lk::KeccakJob> jobs(3);
    std::vector<uint8_t> inputs(input_bytes, input_bytes + sizeof(input_bytes));
    std::vector<uint8_t> outputs(3 * 32, 0);

    for (int i = 0; i < 3; ++i) {
        jobs[i].kind = lk::KeccakJobKind::TxHash;
        jobs[i].input_offset_class = 0;
        jobs[i].input_offset = 0;
        jobs[i].input_len = (uint32_t)sizeof(input_bytes);
        jobs[i].output_offset = (uint32_t)(i * 32);
    }

    size_t computed = lk::keccak_service_run(3, jobs.data(), inputs.data(),
                                             outputs.data(), nullptr);
    char buf[64];
    std::snprintf(buf, sizeof(buf), "in-batch dedup: only 1 keccak (got %zu)", computed);
    ASSERT_TRUE(buf, computed == 1);

    bool eq01 = std::memcmp(outputs.data(), outputs.data() + 32, 32) == 0;
    bool eq12 = std::memcmp(outputs.data() + 32, outputs.data() + 64, 32) == 0;
    ASSERT_TRUE("in-batch dedup: outputs[0..1] equal", eq01);
    ASSERT_TRUE("in-batch dedup: outputs[1..2] equal", eq12);

    uint8_t ref[32];
    keccak256(input_bytes, sizeof(input_bytes), ref);
    ASSERT_TRUE("in-batch dedup: matches keccak256",
                std::memcmp(outputs.data(), ref, 32) == 0);
}

static void test_all_kinds_exercised() {
    // Build one job of each kind.
    std::vector<lk::KeccakJob> jobs(lk::KECCAK_JOB_KIND_COUNT);
    std::vector<uint8_t> inputs;
    std::vector<uint8_t> outputs(32 * lk::KECCAK_JOB_KIND_COUNT);

    for (size_t i = 0; i < lk::KECCAK_JOB_KIND_COUNT; ++i) {
        // Distinct input per kind so dedup doesn't fire.
        for (uint8_t b = 0; b < 16; ++b) inputs.push_back((uint8_t)((i * 17 + b) & 0xFF));
        jobs[i].kind = (lk::KeccakJobKind)i;
        jobs[i].input_offset_class = 0;
        jobs[i].input_offset = (uint32_t)(i * 16);
        jobs[i].input_len = 16;
        jobs[i].output_offset = (uint32_t)(i * 32);
    }
    size_t computed = lk::keccak_service_run(jobs.size(), jobs.data(),
                                             inputs.data(), outputs.data(),
                                             nullptr);
    char buf[64];
    std::snprintf(buf, sizeof(buf), "all kinds exercised: %zu/9 hashed", computed);
    ASSERT_TRUE(buf, computed == lk::KECCAK_JOB_KIND_COUNT);

    int eq = 0;
    for (size_t i = 0; i < jobs.size(); ++i) {
        uint8_t want[32];
        keccak256(inputs.data() + jobs[i].input_offset,
                  jobs[i].input_len, want);
        if (std::memcmp(outputs.data() + jobs[i].output_offset, want, 32) == 0) ++eq;
    }
    std::snprintf(buf, sizeof(buf), "all kinds byte-equal (%d/%zu)", eq, jobs.size());
    ASSERT_TRUE(buf, eq == (int)jobs.size());
}

// 100 mapping-slot keccak requests across 3 simulated calls. ~half of them
// should hit the round cache on calls 2 and 3.
static void test_mapping_slot_cache_hit_rate() {
    lk::KeccakDedupTable cache;
    cache.reset();

    // 50 unique mapping slots, each repeated up to 4 times across 3 calls.
    const int UNIQUE = 50;
    std::vector<std::vector<uint8_t>> unique_inputs(UNIQUE);
    uint64_t s = 0xBA0BAB0BA0BAB0BAULL;
    for (int i = 0; i < UNIQUE; ++i) {
        size_t len = 32 + (size_t)((lcg(s) % 32ULL));
        unique_inputs[i].resize(len);
        for (size_t b = 0; b < len; ++b)
            unique_inputs[i][b] = (uint8_t)(lcg(s) & 0xFF);
    }

    auto run_call = [&](int call_idx, int jobs_per_call) {
        std::vector<lk::KeccakJob> jobs(jobs_per_call);
        std::vector<uint8_t> inputs;
        uint32_t in_off = 0;
        for (int j = 0; j < jobs_per_call; ++j) {
            int u = (int)((lcg(s) % UNIQUE));
            jobs[j].kind = lk::KeccakJobKind::MappingSlot;
            jobs[j].input_offset_class = 0;
            jobs[j].input_offset = in_off;
            jobs[j].input_len = (uint32_t)unique_inputs[u].size();
            jobs[j].output_offset = (uint32_t)(j * 32);
            inputs.insert(inputs.end(),
                          unique_inputs[u].begin(),
                          unique_inputs[u].end());
            in_off += jobs[j].input_len;
        }
        std::vector<uint8_t> outputs(jobs_per_call * 32);
        size_t computed = lk::keccak_service_run(jobs.size(), jobs.data(),
                                                 inputs.data(), outputs.data(),
                                                 &cache);
        return computed;
    };

    run_call(1, 100);  // populate
    run_call(2, 100);  // many hits expected
    size_t c3 = run_call(3, 100);
    (void)c3;

    double total = (double)(cache.hits + cache.misses);
    double rate = total > 0 ? (double)cache.hits / total : 0.0;
    char buf[128];
    std::snprintf(buf, sizeof(buf),
                  "mapping-slot dedup hit-rate %.2f (hits=%llu misses=%llu)",
                  rate, (unsigned long long)cache.hits,
                  (unsigned long long)cache.misses);
    ASSERT_TRUE(buf, rate >= 0.50);
}

int main() {
    std::fprintf(stdout, "=== kinet_crypto keccak_service test suite ===\n");
    test_random_byte_equal();
    test_in_batch_dedup();
    test_all_kinds_exercised();
    test_mapping_slot_cache_hit_rate();
    std::fprintf(stdout, "=== %s (%d failure%s) ===\n",
                 g_failures == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED",
                 g_failures, g_failures == 1 ? "" : "s");
    return g_failures == 0 ? 0 : 1;
}
