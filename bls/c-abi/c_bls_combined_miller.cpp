// C-ABI entry point for the combined-pair Miller-loop pipeline.
//
//   bls12_381_combined_miller(g1s, g2s, k, fp12_out)
//
// Computes the pre-final-exponentiation Fp12 product
//
//     prod_i miller_loop(Q_i, P_i)  for i in 0..k
//
// byte-equal the canonical CPU reference (per-pair blst_miller_loop +
// canonical pairwise Fp12 tree reduction).  Caller applies final_exp()
// once after this routine to obtain a pairing verdict.
//
// Backend selection:
//   1. Try Metal driver (Apple builds with metallib available).
//   2. Try CUDA driver  (Linux+CUDA CI runner).
//   3. Fall back to CPU oracle (blst_miller_loop + tree_reduce_fp12).
//
// All three paths emit the SAME bytes — the determinism contract is the
// canonical Fp12 tree reduction (round k+1 multiplies adjacent outputs
// of round k; odd counts carry the last element forward unchanged).

#include <blst.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#if defined(__APPLE__) && defined(BLS_HAVE_METAL)
#include "../gpu/metal/bls_combined_miller_driver.h"
#endif

#if defined(BLS_HAVE_CUDA)
#include "../gpu/cuda/bls_combined_miller_driver.h"
#endif

namespace {

bool is_zero(const uint8_t* b, std::size_t n) noexcept
{
    for (std::size_t i = 0; i < n; ++i) {
        if (b[i] != 0) return false;
    }
    return true;
}

const std::uint64_t kBLS_R_LE[6] = {
    0x760900000002FFFDULL, 0xEBF4000BC40C0002ULL, 0x5F48985753C758BAULL,
    0x77CE585370525745ULL, 0x5C071A97A256EC6DULL, 0x15F65EC3FA80E493ULL
};

void make_fp12_one(blst_fp12& f) noexcept
{
    std::memset(&f, 0, sizeof(f));
    std::memcpy(&f, kBLS_R_LE, sizeof(kBLS_R_LE));
}

// Canonical pairwise Fp12 tree reduction.  Round k+1 multiplies adjacent
// outputs of round k; odd counts carry the last element forward.  Same
// shape as tree_reduce_fp12 in cpp/bls_pairing.cpp and the Metal/CUDA/WGSL
// reduction kernels.
void tree_reduce(std::vector<blst_fp12>& v) noexcept
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

int cpu_combined_miller(const uint8_t* g1s,
                        const uint8_t* g2s,
                        std::size_t    k,
                        uint8_t        fp12_out[576]) noexcept
{
    std::vector<blst_fp12> ml;
    ml.reserve(k);
    for (std::size_t i = 0; i < k; ++i) {
        const uint8_t* P = g1s + i * 96;
        const uint8_t* Q = g2s + i * 192;
        blst_fp12 t;
        if (is_zero(P, 96) || is_zero(Q, 192)) {
            // Identity short-circuit: pairing of identity is Fp12::one().
            make_fp12_one(t);
        } else {
            blst_p1_affine P_aff;
            blst_p2_affine Q_aff;
            std::memcpy(&P_aff, P, sizeof(P_aff));
            std::memcpy(&Q_aff, Q, sizeof(Q_aff));
            blst_miller_loop(&t, &Q_aff, &P_aff);
        }
        ml.push_back(t);
    }
    tree_reduce(ml);
    std::memcpy(fp12_out, &ml[0], sizeof(blst_fp12));
    return 0;
}

}  // namespace

extern "C" int bls12_381_combined_miller(const uint8_t* g1s,
                                          const uint8_t* g2s,
                                          std::size_t    k,
                                          uint8_t        fp12_out[576])
{
    if (fp12_out == nullptr) return -1;
    if (k == 0) return -1;
    if (g1s == nullptr || g2s == nullptr) return -1;

#if defined(__APPLE__) && defined(BLS_HAVE_METAL)
    {
        int rc = bls_combined_miller_metal(g1s, g2s, k, fp12_out);
        if (rc == 0) return 0;
        // rc == -2: Metal unavailable / kernel load failed -> fall through.
    }
#endif

#if defined(BLS_HAVE_CUDA)
    if (bls_combined_miller_cuda_available()) {
        int rc = bls_combined_miller_cuda(g1s, g2s, k, fp12_out);
        if (rc == 0) return 0;
    }
#endif

    return cpu_combined_miller(g1s, g2s, k, fp12_out);
}
