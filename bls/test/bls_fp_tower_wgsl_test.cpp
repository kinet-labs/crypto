// WGSL parity for Stage 1 (Fp tower). Loads the same vectors_fp_tower.h that
// Metal uses and verifies WGSL kernels produce identical bytes for every op.

#include "vectors_fp_tower.h"
#include "bls_driver_wgpu.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {
struct Result { std::string name; size_t pass; size_t fail; size_t elem; };

Result cmp(const char* name, size_t elem, const void* a, const void* b, size_t n) {
    Result r{name, 0, 0, elem};
    const uint8_t* x = static_cast<const uint8_t*>(a);
    const uint8_t* y = static_cast<const uint8_t*>(b);
    for (size_t i = 0; i < n; ++i) {
        if (std::memcmp(x + i * elem, y + i * elem, elem) == 0) r.pass++;
        else r.fail++;
    }
    return r;
}
void hexdump(const char* label, const uint8_t* d, size_t n) {
    std::printf("  %s: ", label);
    for (size_t i = 0; i < n; ++i) {
        std::printf("%02x", d[i]);
        if ((i + 1) % 32 == 0 && i + 1 < n) std::printf("\n            ");
        else if (i + 1 < n) std::printf(" ");
    }
    std::printf("\n");
}
}

int main(int /*argc*/, char** /*argv*/) {
    if (!bls_wgpu_available()) {
        std::printf("[bls-fp-tower-wgsl] wgpu unavailable on this host — skipped\n");
        return 0;
    }

    std::vector<Result> results;
    std::vector<uint8_t> buf;

    auto bin = [&](const char* op, const char* metric, size_t elem,
                    const uint8_t* A, const uint8_t* B, const uint8_t* O) {
        buf.assign(kNVectors * elem, 0);
        if (bls_wgpu_run_binary(op, A, B, buf.data(), elem, kNVectors) != 0) {
            std::fprintf(stderr, "FATAL: dispatch %s failed\n", op);
            std::exit(2);
        }
        results.push_back(cmp(metric, elem, buf.data(), O, kNVectors));
    };
    auto un = [&](const char* op, const char* metric, size_t elem,
                   const uint8_t* A, const uint8_t* O) {
        buf.assign(kNVectors * elem, 0);
        if (bls_wgpu_run_unary(op, A, buf.data(), elem, kNVectors) != 0) {
            std::fprintf(stderr, "FATAL: dispatch %s failed\n", op);
            std::exit(2);
        }
        results.push_back(cmp(metric, elem, buf.data(), O, kNVectors));
    };

    un("k_fp_inv_diag", "fp_inv (diag)", kFp2Bytes, kFpInvIn_bytes, kFpInvOut_bytes);

    bin("k_fp2_add", "fp2_add", kFp2Bytes, kFp2A_bytes, kFp2B_bytes, kFp2Add_bytes);
    bin("k_fp2_sub", "fp2_sub", kFp2Bytes, kFp2A_bytes, kFp2B_bytes, kFp2Sub_bytes);
    bin("k_fp2_mul", "fp2_mul", kFp2Bytes, kFp2A_bytes, kFp2B_bytes, kFp2Mul_bytes);
    un("k_fp2_sqr",   "fp2_sqr",  kFp2Bytes, kFp2A_bytes, kFp2Sqr_bytes);
    un("k_fp2_inv",   "fp2_inv",  kFp2Bytes, kFp2A_bytes, kFp2Inv_bytes);
    un("k_fp2_conj",  "fp2_conj", kFp2Bytes, kFp2A_bytes, kFp2Conj_bytes);

    bin("k_fp6_add", "fp6_add", kFp6Bytes, kFp6A_bytes, kFp6B_bytes, kFp6Add_bytes);
    bin("k_fp6_sub", "fp6_sub", kFp6Bytes, kFp6A_bytes, kFp6B_bytes, kFp6Sub_bytes);
    bin("k_fp6_mul", "fp6_mul", kFp6Bytes, kFp6A_bytes, kFp6B_bytes, kFp6Mul_bytes);
    un("k_fp6_sqr",   "fp6_sqr", kFp6Bytes, kFp6A_bytes, kFp6Sqr_bytes);
    un("k_fp6_inv",   "fp6_inv", kFp6Bytes, kFp6A_bytes, kFp6Inv_bytes);

    bin("k_fp12_add", "fp12_add", kFp12Bytes, kFp12A_bytes, kFp12B_bytes, kFp12Add_bytes);
    bin("k_fp12_sub", "fp12_sub", kFp12Bytes, kFp12A_bytes, kFp12B_bytes, kFp12Sub_bytes);
    bin("k_fp12_mul", "fp12_mul", kFp12Bytes, kFp12A_bytes, kFp12B_bytes, kFp12Mul_bytes);
    un("k_fp12_sqr",       "fp12_sqr",       kFp12Bytes, kFp12A_bytes, kFp12Sqr_bytes);
    un("k_fp12_inv",       "fp12_inv",       kFp12Bytes, kFp12A_bytes, kFp12Inv_bytes);
    un("k_fp12_conj",      "fp12_conj",      kFp12Bytes, kFp12A_bytes, kFp12Conj_bytes);
    un("k_fp12_cyclo_sqr", "fp12_cyclo_sqr", kFp12Bytes, kFp12CycloIn_bytes, kFp12CycloOut_bytes);

    size_t total_pass = 0, total_fail = 0;
    std::printf("=== BLS Fp tower vs blst (WGSL via wgpu-native) ===\n");
    for (auto& r : results) {
        std::printf("  %-22s  pass=%4zu  fail=%4zu  (%zu B/elem)\n",
                    r.name.c_str(), r.pass, r.fail, r.elem);
        total_pass += r.pass; total_fail += r.fail;
    }
    std::printf("---------------------------------------------------\n");
    std::printf("  TOTAL: %zu pass, %zu fail (over %zu vectors)\n",
                total_pass, total_fail, total_pass + total_fail);

    // Byte dump for fp2_mul vector 42 (Fp2 fits comfortably in the WGSL stack).
    if (total_pass > 0) {
        std::vector<uint8_t> mbuf(kNVectors * kFp2Bytes);
        bls_wgpu_run_binary("k_fp2_mul", kFp2A_bytes, kFp2B_bytes,
                                 mbuf.data(), kFp2Bytes, kNVectors);
        const size_t IDX = 42;
        const uint8_t* mptr = mbuf.data() + IDX * kFp2Bytes;
        const uint8_t* optr = kFp2Mul_bytes + IDX * kFp2Bytes;
        const bool eq = std::memcmp(mptr, optr, kFp2Bytes) == 0;
        std::printf("\nVector fp2_mul[%zu]:  %s\n", IDX, eq ? "EQUAL" : "DIFFER");
        hexdump("blst  ", optr, kFp2Bytes);
        hexdump("wgsl  ", mptr, kFp2Bytes);
    }

    return total_fail == 0 ? 0 : 1;
}
