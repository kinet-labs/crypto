// Copyright (c) 2024-2026 Kinet Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// C ABI -> C++ surface adapter for BLS12-381 pairing.

#include "c_bls_pairing.h"
#include "../cpp/bls_pairing.hpp"

extern "C" int bls_pairing(const uint8_t p1[96],
                           const uint8_t p2[192],
                           uint8_t       fp12[576])
{
    return cevm::crypto::bls::pairing(p1, p2, fp12);
}

extern "C" int bls_aggregate_verify(const uint8_t* pks,
                                    const uint8_t* sigs,
                                    size_t         n)
{
    return cevm::crypto::bls::aggregate_verify(pks, sigs, n);
}
