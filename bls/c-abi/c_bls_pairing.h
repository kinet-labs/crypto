// Copyright (c) 2024-2026 Kinet Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Brand-neutral C ABI for BLS12-381 pairing operations.

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Compute e(P, Q) where:
//   p1   = uncompressed G1 point  (96 bytes,  x || y)
//   p2   = uncompressed G2 point  (192 bytes, x || y, each 96 bytes Fp2)
//   fp12 = output Fp12 element    (576 bytes, native blst layout)
// Returns 0 on success, non-zero on error.
int bls_pairing(const uint8_t p1[96],
                const uint8_t p2[192],
                uint8_t       fp12[576]);

// Aggregate verify: given N pairs (P_i in G1, Q_i in G2), compute
//   prod_i e(P_i, Q_i)
// and check whether the product equals Fp12::one().
//   pks  = packed N * 96 bytes
//   sigs = packed N * 192 bytes
//   n    = number of pairs
// Returns:
//    0 if the aggregate equals one (verification succeeds)
//    1 if it does not (verification fails)
//   <0 on input error
int bls_aggregate_verify(const uint8_t* pks,
                         const uint8_t* sigs,
                         size_t         n);

#ifdef __cplusplus
}  // extern "C"
#endif
