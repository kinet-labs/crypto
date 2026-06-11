// Stage 4 subgroup test. Verifies the host-side predicate blst_p*_in_g* used
// by the production short-circuit (the GPU pipelines short-circuit identity
// inputs and rely on the host predicate for subgroup membership). The same
// predicate is consulted on every backend, so the decision array byte-equals
// across Metal / CUDA / WGSL deployments.

#include <blst.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "vectors_subgroup.h"

namespace {
constexpr size_t kP1Aff  = 96;
constexpr size_t kP2Aff  = 192;
constexpr size_t kP1Comp = 48;
constexpr size_t kP2Comp = 96;

bool g1_in(const uint8_t* aff_bytes) {
    blst_p1_affine pa;
    std::memcpy(&pa, aff_bytes, kP1Aff);
    if (!blst_p1_affine_on_curve(&pa)) return false;
    return blst_p1_affine_in_g1(&pa);
}
bool g2_in(const uint8_t* aff_bytes) {
    blst_p2_affine pa;
    std::memcpy(&pa, aff_bytes, kP2Aff);
    if (!blst_p2_affine_on_curve(&pa)) return false;
    return blst_p2_affine_in_g2(&pa);
}
bool g1_decompress_ok(const uint8_t* compressed) {
    blst_p1_affine pa;
    return blst_p1_uncompress(&pa, compressed) == BLST_SUCCESS;
}
bool g2_decompress_ok(const uint8_t* compressed) {
    blst_p2_affine pa;
    return blst_p2_uncompress(&pa, compressed) == BLST_SUCCESS;
}
} // namespace

int main(int /*argc*/, char** /*argv*/) {
    size_t pass = 0, fail = 0;

    auto check_g1_acc = [&](const uint8_t* pts, const uint8_t* dec, size_t n) {
        for (size_t i = 0; i < n; ++i) {
            const bool got = g1_in(pts + i * kP1Aff);
            if (got == (dec[i] != 0)) pass++; else fail++;
        }
    };
    auto check_g2_acc = [&](const uint8_t* pts, const uint8_t* dec, size_t n) {
        for (size_t i = 0; i < n; ++i) {
            const bool got = g2_in(pts + i * kP2Aff);
            if (got == (dec[i] != 0)) pass++; else fail++;
        }
    };
    auto check_g1_dec = [&](const uint8_t* pts, const uint8_t* dec, size_t n) {
        for (size_t i = 0; i < n; ++i) {
            const bool got = g1_decompress_ok(pts + i * kP1Comp);
            if (got == (dec[i] != 0)) pass++; else fail++;
        }
    };
    auto check_g2_dec = [&](const uint8_t* pts, const uint8_t* dec, size_t n) {
        for (size_t i = 0; i < n; ++i) {
            const bool got = g2_decompress_ok(pts + i * kP2Comp);
            if (got == (dec[i] != 0)) pass++; else fail++;
        }
    };

    check_g1_acc(kSubg_AccG1_pts, kSubg_AccG1_dec, kSubg_AccG1);
    check_g2_acc(kSubg_AccG2_pts, kSubg_AccG2_dec, kSubg_AccG2);
    check_g1_acc(kSubg_RejG1_pts, kSubg_RejG1_dec, kSubg_RejG1);
    check_g2_acc(kSubg_RejG2_pts, kSubg_RejG2_dec, kSubg_RejG2);
    check_g1_dec(kSubg_InfG1, kSubg_InfG1_dec, kSubg_Inf);
    check_g2_dec(kSubg_InfG2, kSubg_InfG2_dec, kSubg_Inf);
    check_g1_dec(kSubg_MalG1, kSubg_MalG1_dec, kSubg_Mal);
    check_g2_dec(kSubg_MalG2, kSubg_MalG2_dec, kSubg_Mal);

    std::printf("=== BLS subgroup predicate (Stage 4) ===\n");
    std::printf("  pass=%zu  fail=%zu  (over %zu vectors)\n", pass, fail, pass + fail);
    return fail == 0 ? 0 : 1;
}
