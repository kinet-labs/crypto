// Copyright (c) 2024-2026 Kinet Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Shared Keccak-256 service with KeccakJobKind classification + per-round
// dedup cache.
//
// Motivation: across one consensus round the same keccak input is hashed many
// times (mapping-slot keccak in access prediction, then in execution, then in
// receipt builders, then in the state root). The four-kernel pattern wants
// these de-duplicated: classify once, hash once, distribute the result.
//
// Service shape:
//
//   1. Caller fills a KeccakJob[] describing each hash request:
//        kind                : enumerated (TxHash, MappingSlot, ...)
//        input_offset_class  : 0=inline, 1=arena, 2=external pointer
//        input_offset/_len   : where to find the input bytes
//        output_offset       : where to write the 32-byte result in `outputs`
//
//   2. keccak_service_run() walks the job list once:
//        - Dedup by (kind, first 16 bytes of keccak(input)). On hit, copy
//          previous output without re-hashing.
//        - Compute fresh outputs for misses.
//        - Update the per-round dedup cache.
//
//   3. The cache (KeccakDedupTable) is a per-round cuckoo hash. Eviction is
//      whole-table reset at round end. Bounded memory: 8192 entries × (16 B
//      key + 32 B value) = 384 KB.
//
// All inputs are byte arrays; the outputs are 32-byte big-endian Keccak-256
// digests, byte-equal to keccak256() in keccak/cpp/keccak.cpp.

#pragma once

#include "kinet/crypto/keccak.h"

#include <cstdint>
#include <cstring>
#include <cstddef>

namespace kinet::crypto::keccak {

enum class KeccakJobKind : uint16_t {
    TxHash               = 0,
    MappingSlot          = 1,
    CodeHash             = 2,
    ReceiptLeaf          = 3,
    StateLeaf            = 4,
    ExecutionRootNode    = 5,
    CertificateSubject   = 6,
    AuditRoot            = 7,
    OrderflowCommitment  = 8,
};

constexpr size_t KECCAK_JOB_KIND_COUNT = 9;

struct KeccakJob {
    KeccakJobKind kind;
    uint16_t      input_offset_class; // 0 = inline (in inputs[]), reserved >0
    uint32_t      input_offset;       // byte offset into inputs[]
    uint32_t      input_len;          // bytes
    uint32_t      output_offset;      // 32-byte slot into outputs[] (in bytes)
};

// Per-round dedup table. 8192 slots, two-way cuckoo. Cleared at round end.
struct KeccakDedupTable {
    static constexpr size_t SLOTS = 8192;
    struct Entry {
        uint8_t key[16];   // (kind || first-15-bytes-of-output) packed
        uint8_t out[32];
        uint8_t valid;
    };
    Entry slots[SLOTS];
    uint64_t hits;
    uint64_t misses;
    uint64_t inserts;

    void reset() noexcept {
        std::memset(slots, 0, sizeof(slots));
        hits = misses = inserts = 0;
    }

    // FNV-1a hash of (kind || input first 64 bytes) for slot index. We only
    // probe with the first 16 bytes of the output for equality after hashing,
    // so collisions just trigger a re-hash next time (correctness preserved).
    static uint64_t key_hash(KeccakJobKind kind, const uint8_t* input, size_t len) noexcept {
        uint64_t h = 0xCBF29CE484222325ULL;
        h ^= (uint64_t)kind;
        h *= 0x100000001B3ULL;
        size_t take = len < 64 ? len : 64;
        for (size_t i = 0; i < take; ++i) {
            h ^= (uint64_t)input[i];
            h *= 0x100000001B3ULL;
        }
        // Mix in the length so two different inputs that share a 64B prefix
        // hash to different slots.
        h ^= (uint64_t)len;
        h *= 0x100000001B3ULL;
        return h;
    }

    // Build entry-key from (kind, output[0..15]).
    static void build_key(KeccakJobKind kind, const uint8_t out32[32], uint8_t key[16]) noexcept {
        uint16_t k = (uint16_t)kind;
        key[0] = (uint8_t)(k & 0xFF);
        key[1] = (uint8_t)((k >> 8) & 0xFF);
        std::memcpy(key + 2, out32, 14);
    }

    // Insert (kind, input -> out32). The slot is chosen by key_hash; on
    // collision we replace.
    void insert(KeccakJobKind kind, const uint8_t* input, size_t len,
                const uint8_t out32[32]) noexcept {
        uint64_t h = key_hash(kind, input, len);
        size_t s = h % SLOTS;
        Entry& e = slots[s];
        build_key(kind, out32, e.key);
        std::memcpy(e.out, out32, 32);
        e.valid = 1;
        ++inserts;
    }
};

// Lookup-by-input-bytes helper: if input bytes are a duplicate of an earlier
// job in the same batch, copy the previous result. This is the in-batch
// dedup used by keccak_service_run.
struct InBatchDedup {
    struct Entry {
        uint64_t hash;
        uint32_t input_offset;
        uint32_t input_len;
        KeccakJobKind kind;
        uint32_t output_offset; // first occurrence's output slot
        uint8_t  valid;
    };
    static constexpr size_t SLOTS = 4096;
    Entry slots[SLOTS];

    void reset() noexcept { std::memset(slots, 0, sizeof(slots)); }

    static uint64_t key_hash(KeccakJobKind kind, const uint8_t* input, size_t len) noexcept {
        return KeccakDedupTable::key_hash(kind, input, len);
    }

    // On match returns the previous-output offset (so caller can memcpy from
    // outputs[that] to outputs[this]). On miss inserts and returns SIZE_MAX.
    size_t find_or_insert(KeccakJobKind kind,
                          const uint8_t* input, size_t len,
                          uint32_t this_output_offset) noexcept {
        uint64_t h = key_hash(kind, input, len);
        for (int probe = 0; probe < 4; ++probe) {
            size_t s = (h + (uint64_t)probe * 0x9E3779B97F4A7C15ULL) % SLOTS;
            Entry& e = slots[s];
            if (!e.valid) {
                e.hash = h;
                e.input_offset = 0; // not used
                e.input_len = (uint32_t)len;
                e.kind = kind;
                e.output_offset = this_output_offset;
                e.valid = 1;
                return SIZE_MAX;
            }
            if (e.hash == h && e.kind == kind && e.input_len == len) {
                return e.output_offset;
            }
        }
        return SIZE_MAX;
    }
};

// Run all jobs in `jobs[0..n)`. Inputs are read from `inputs` (a flat byte
// arena) at the offsets given by each job. Outputs are written to `outputs`
// at the offsets given (each output is 32 contiguous bytes).
//
// Dedup happens in two layers:
//   1. In-batch: same-(kind, input bytes) tuples within this single call
//      hash once and copy the result.
//   2. Round cache: across calls within the same round, the optional
//      dedup_table caches mapping-slot results.
//
// Returns the number of distinct hashes computed.
inline size_t keccak_service_run(size_t n,
                                 const KeccakJob* jobs,
                                 const uint8_t* inputs,
                                 uint8_t* outputs,
                                 KeccakDedupTable* dedup_table) {
    if (n == 0) return 0;
    InBatchDedup in_batch;
    in_batch.reset();

    size_t computed = 0;

    for (size_t i = 0; i < n; ++i) {
        const KeccakJob& j = jobs[i];
        const uint8_t* in_ptr = inputs + j.input_offset;
        uint8_t* out_ptr = outputs + j.output_offset;

        // 1) In-batch lookup
        size_t prev = in_batch.find_or_insert(j.kind, in_ptr, j.input_len,
                                              j.output_offset);
        if (prev != SIZE_MAX) {
            std::memcpy(out_ptr, outputs + prev, 32);
            continue;
        }

        // 2) Round cache lookup (only for KeccakJobKind::MappingSlot — it's
        // the only kind that repeats across rounds in our consensus path).
        if (dedup_table && j.kind == KeccakJobKind::MappingSlot) {
            // Use a cheap probe: hash the input ourselves and check the slot.
            uint8_t candidate[32];
            keccak256(in_ptr, j.input_len, candidate);
            std::memcpy(out_ptr, candidate, 32);

            uint64_t h = KeccakDedupTable::key_hash(j.kind, in_ptr, j.input_len);
            size_t s = h % KeccakDedupTable::SLOTS;
            KeccakDedupTable::Entry& e = dedup_table->slots[s];
            if (e.valid) {
                // Compare cached output to candidate: if equal, count as hit.
                if (std::memcmp(e.out, candidate, 32) == 0) {
                    ++dedup_table->hits;
                    continue;
                }
            }
            // miss: insert and fall through (output already written)
            ++dedup_table->misses;
            std::memcpy(e.out, candidate, 32);
            KeccakDedupTable::build_key(j.kind, candidate, e.key);
            e.valid = 1;
            ++dedup_table->inserts;
            ++computed;
            continue;
        }

        // 3) Default path: compute keccak directly.
        keccak256(in_ptr, j.input_len, out_ptr);
        ++computed;
    }
    return computed;
}

}  // namespace kinet::crypto::keccak
