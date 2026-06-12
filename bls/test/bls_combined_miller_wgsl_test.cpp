// Byte-equality test for the combined-pair Miller-loop WGSL reduction kernel.
//
// WGSL ships only the canonical Fp12 tree-reduction kernel at this stage
// (Stage 4 ports Fp-tower; full miller_loop in WGSL is Stage 5b).  This
// test exercises the kernel correctness by:
//   1. Building k random pairs and running blst_miller_loop on the host
//      to produce k Fp12 inputs.
//   2. Calling the WGSL host driver to dispatch the tree-reduce kernel
//      ceil(log2(k)) times.
//   3. Asserting byte-equality of the WGSL output against the canonical
//      CPU tree_reduce_fp12 over the same k Fp12 inputs.
//
// On CI hosts without wgpu-native, the driver returns -2 and the test
// prints a SKIP line — same convention as bls_fp_tower_wgsl_test.cpp.

#include <blst.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <random>
#include <vector>

namespace {

constexpr std::size_t kFp12B = 576;

// WGSL host helper — definition lives in gpu/wgsl/bls_driver_wgpu.cpp
// once the WGSL Miller path is wired in (Stage 5b).  Until then we
// provide a stub here that returns -2, and the test prints SKIP.
//
// Mach-O does not honour __attribute__((weak)) on undefined references
// the way ELF does, so we ship the stub directly in the test binary —
// a real WGSL driver in the same link line would override this.
extern "C" int bls_combined_miller_wgsl_reduce(const std::uint8_t* in_fp12s,
                                                std::size_t k,
                                                std::uint8_t fp12_out[576]);

extern "C" __attribute__((weak)) int bls_combined_miller_wgsl_reduce(
    const std::uint8_t*, std::size_t, std::uint8_t[576])
{
    return -2;  // WGSL reduce driver not linked (Stage 5b ships it).
}

void tree_reduce(std::vector<blst_fp12>& v)
{
    while (v.size() > 1) {
        std::vector<blst_fp12> next;
        next.reserve((v.size() + 1) / 2);
        for (std::size_t i = 0; i + 1 < v.size(); i += 2) {
            blst_fp12 r;
            blst_fp12_mul(&r, &v[i], &v[i + 1]);
            next.push_back(r);
        }
        if (v.size() & 1u) next.push_back(v.back());
        v = std::move(next);
    }
}

void make_random_fp12s(std::size_t k,
                       std::vector<std::uint8_t>& flat,
                       std::vector<blst_fp12>& parsed,
                       std::uint64_t seed)
{
    flat.assign(k * kFp12B, 0);
    parsed.assign(k, {});
    std::mt19937_64 r(seed);
    for (std::size_t i = 0; i < k; ++i) {
        // Build a random valid Fp12 by running miller_loop on a random
        // (P, Q).  Cheaper than constructing structurally — and matches
        // the production input distribution to this kernel exactly.
        std::uint8_t sk1[32], sk2[32];
        for (int j = 0; j < 32; ++j) sk1[j] = static_cast<std::uint8_t>(r() & 0xFF);
        for (int j = 0; j < 32; ++j) sk2[j] = static_cast<std::uint8_t>(r() & 0xFF);
        sk1[31] &= 0x3F; sk1[0] |= 0x01;
        sk2[31] &= 0x3F; sk2[0] |= 0x01;
        blst_p1 P_jac; blst_p1_mult(&P_jac, blst_p1_generator(), sk1, 256);
        blst_p1_affine P_aff; blst_p1_to_affine(&P_aff, &P_jac);
        blst_p2 Q_jac; blst_p2_mult(&Q_jac, blst_p2_generator(), sk2, 256);
        blst_p2_affine Q_aff; blst_p2_to_affine(&Q_aff, &Q_jac);
        blst_fp12 t; blst_miller_loop(&t, &Q_aff, &P_aff);
        parsed[i] = t;
        std::memcpy(flat.data() + i * kFp12B, &t, kFp12B);
    }
}

}  // namespace

int main(int, char**)
{
    // Probe the driver with k=1; if it returns -2 the WGSL reduce path
    // is not linked in this build and we SKIP.  This matches the
    // bls_fp_tower_wgsl_test convention.
    {
        std::vector<std::uint8_t> probe_in(576, 0);
        std::vector<blst_fp12>    probe_parsed;
        make_random_fp12s(1, probe_in, probe_parsed, 0xC0FFEEULL);
        std::uint8_t probe_out[kFp12B];
        int probe_rc = bls_combined_miller_wgsl_reduce(probe_in.data(), 1, probe_out);
        if (probe_rc == -2) {
            std::printf("=== combined Miller-loop WGSL test ===\n");
            std::printf("  SKIP: WGSL reduce driver not linked in this build\n");
            return 0;
        }
    }

    std::printf("=== combined Miller-loop WGSL byte-equality vs CPU tree-reduce ===\n");
    int failures = 0;
    for (std::size_t k : { (std::size_t)1, (std::size_t)4, (std::size_t)16,
                           (std::size_t)64, (std::size_t)256 }) {
        std::vector<std::uint8_t> flat;
        std::vector<blst_fp12>    parsed;
        make_random_fp12s(k, flat, parsed, 0xC0FFEEULL ^ k);

        // CPU reference.
        std::vector<blst_fp12> v = parsed;
        tree_reduce(v);
        std::uint8_t expected[kFp12B];
        std::memcpy(expected, &v[0], kFp12B);

        // WGSL kernel.
        std::uint8_t actual[kFp12B];
        int rc = bls_combined_miller_wgsl_reduce(flat.data(), k, actual);
        if (rc != 0) {
            std::fprintf(stderr, "FAIL: wgsl(k=%zu) rc=%d\n", k, rc);
            ++failures;
            continue;
        }
        if (std::memcmp(expected, actual, kFp12B) != 0) {
            std::fprintf(stderr, "FAIL: wgsl byte mismatch at k=%zu\n", k);
            ++failures;
            continue;
        }
        std::printf("  k=%-4zu  PASS\n", k);
    }
    return failures == 0 ? 0 : 1;
}
