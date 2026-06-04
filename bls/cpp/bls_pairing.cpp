// Copyright (c) 2024-2026 Kinet Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// CPU reference implementation of the BLS12-381 pairing public API.
//
// This file links blst at build time and is included only in the TEST
// target — the production library compiles the GPU-dispatch implementation
// (cevm/lib/consensus/quasar/gpu/quasar_bls_verifier.cpp at Stage 5).
//
// The reference is here so unit tests can validate the C++ + C-ABI surface
// against blst directly, without depending on Metal/CUDA/WGSL backends in
// CI containers that lack a GPU.

#include "bls_pairing.hpp"

#include <blst.h>
#include <cstring>

namespace cevm::crypto::bls
{
namespace
{
// Fp12::one() in Montgomery form (matches blst layout byte-for-byte).
const uint64_t kBLS_R_LE[6] = {
    0x760900000002FFFDULL, 0xEBF4000BC40C0002ULL, 0x5F48985753C758BAULL,
    0x77CE585370525745ULL, 0x5C071A97A256EC6DULL, 0x15F65EC3FA80E493ULL
};

bool is_zero(const uint8_t* b, size_t n)
{
    for (size_t i = 0; i < n; i++) if (b[i] != 0) return false;
    return true;
}

void write_fp12_one(uint8_t out[576])
{
    std::memset(out, 0, 576);
    std::memcpy(out, kBLS_R_LE, sizeof(kBLS_R_LE));
}

}  // namespace

int pairing(const uint8_t P_aff[96],
            const uint8_t Q_aff[192],
            uint8_t       fp12_out[576]) noexcept
{
    // Identity short-circuit: e(0, Q) = e(P, 0) = 1.
    if (is_zero(P_aff, 96) || is_zero(Q_aff, 192)) {
        write_fp12_one(fp12_out);
        return 0;
    }

    blst_p1_affine P;
    blst_p2_affine Q;
    std::memcpy(&P, P_aff, sizeof(P));
    std::memcpy(&Q, Q_aff, sizeof(Q));

    blst_fp12 ml;
    blst_miller_loop(&ml, &Q, &P);
    blst_fp12 res;
    blst_final_exp(&res, &ml);
    std::memcpy(fp12_out, &res, sizeof(res));
    return 0;
}

int aggregate_verify(const uint8_t* pks,
                     const uint8_t* sigs,
                     size_t         n) noexcept
{
    if (n == 0) return -1;

    blst_fp12 acc;
    {
        blst_fp12 one;
        std::memset(&one, 0, sizeof(one));
        std::memcpy(&one, kBLS_R_LE, sizeof(kBLS_R_LE));
        acc = one;
    }

    for (size_t i = 0; i < n; i++) {
        blst_p1_affine P;
        blst_p2_affine Q;
        std::memcpy(&P, pks  + i * 96,  sizeof(P));
        std::memcpy(&Q, sigs + i * 192, sizeof(Q));

        blst_fp12 ml;
        blst_miller_loop(&ml, &Q, &P);
        blst_fp12_mul(&acc, &acc, &ml);
    }

    blst_fp12 final_;
    blst_final_exp(&final_, &acc);

    blst_fp12 one;
    std::memset(&one, 0, sizeof(one));
    std::memcpy(&one, kBLS_R_LE, sizeof(kBLS_R_LE));

    return std::memcmp(&final_, &one, sizeof(one)) == 0 ? 0 : 1;
}

}  // namespace cevm::crypto::bls
