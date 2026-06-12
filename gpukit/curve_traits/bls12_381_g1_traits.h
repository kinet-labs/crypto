// BLS12-381 G1 curve traits for the multi_pippenger CPU reference.
//
//   p = 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787
//   y^2 = x^3 + 4
//
// The first-party CPU body for BLS12-381 G1 MSM lives in
//   bls/cpp/bls.cpp      (cevm::crypto::bls::g1_msm)
//
// That body validates points (Fp range + on-curve + subgroup), filters the
// point at infinity, and runs Pippenger over the validated set. It is the
// same body that ships behind the EIP-2537 G1MSM precompile.
//
// Wire format adaptation:
//
//   gpukit ABI : 96-byte affine point  (48-byte BE x || 48-byte BE y)
//                32-byte LE scalar
//   bls body   : per entry (64 BE x || 64 BE y || 32 BE scalar)
//                  -- BLS body uses 64-byte fields with 16 leading zero bytes
//                     per EIP-2537, and 32-byte BE scalars.
//
// This header provides the byte-level adapter and dispatches into the bls
// body. No separate point-trait struct is needed because the bls body is
// MSM-direct (it does not expose Jacobian add/double on the public surface);
// dispatch is at the MSM level, mirroring how multi_pippenger.cpp dispatches
// banderwagon to kinet::banderwagon::multi_scalar_mul.

#pragma once

#include "../../bls/cpp/bls.hpp"
#include "kinet/gpukit/gpukit.h"

#include <cstdint>
#include <cstring>
#include <vector>

namespace kinet::gpukit::mp {

// Pack one entry into the bls body's expected layout:
//   64 BE x || 64 BE y || 32 BE scalar
//
//   gpukit point bytes : 96 bytes (48 BE x || 48 BE y).
//   gpukit scalar bytes: 32 bytes LE.
inline void pack_bls12_381_g1_entry(const std::uint8_t* point_96,
                                    const std::uint8_t* scalar_le_32,
                                    std::uint8_t out_160[160]) noexcept {
    // x coordinate: 64-byte BE, 16 leading zero bytes + 48 BE bytes.
    std::memset(out_160, 0, 16);
    std::memcpy(out_160 + 16, point_96, 48);
    // y coordinate: 64-byte BE, 16 leading zero bytes + 48 BE bytes.
    std::memset(out_160 + 64, 0, 16);
    std::memcpy(out_160 + 64 + 16, point_96 + 48, 48);
    // scalar: 32 BE. gpukit ABI is LE, bls body is BE. Reverse byte order.
    for (int i = 0; i < 32; ++i) {
        out_160[128 + i] = scalar_le_32[31 - i];
    }
}

// Drop the 16 leading zero bytes from each 64-byte BE field element to
// emit gpukit's 96-byte affine layout.
inline void unpack_bls12_381_g1_result(const std::uint8_t rx_64[64],
                                       const std::uint8_t ry_64[64],
                                       std::uint8_t out_96[96]) noexcept {
    std::memcpy(out_96,      rx_64 + 16, 48);
    std::memcpy(out_96 + 48, ry_64 + 16, 48);
}

// Multi-scalar multiplication on BLS12-381 G1.
//   scalars : n * 32-byte LE.
//   points  : n * 96 bytes affine (48 BE x || 48 BE y); all-zero = identity.
//   n       : pair count.
//   result  : 96 bytes affine output.
//
// Returns GPUKIT_OK on success or GPUKIT_ERR_BAD_SIZE if the bls body
// rejects a point (off-curve, off-field, or out-of-subgroup).
inline int multi_pippenger_bls12_381_g1(const std::uint8_t* scalars,
                                        const std::uint8_t* points,
                                        std::size_t n,
                                        std::uint8_t* result) noexcept {
    constexpr std::size_t kEntry = 64 * 2 + 32;  // 160 bytes per (point, scalar).

    if (n == 0) {
        std::memset(result, 0, 96);
        return GPUKIT_OK;
    }

    // Filter all-zero points up front: they are wire-encoded identities and
    // contribute nothing to the MSM, but the bls body's validate_p1 path
    // would reject them as off-curve. (cevm::crypto::bls::g1_msm internally
    // skips blst's point-at-infinity, but that detection happens after the
    // on-curve check, so an all-zero affine never reaches it.)
    std::vector<std::uint8_t> packed;
    packed.reserve(n * kEntry);
    std::uint8_t entry[kEntry];
    bool any_nonidentity = false;
    for (std::size_t i = 0; i < n; ++i) {
        const std::uint8_t* p = points + 96 * i;
        bool any = false;
        for (int j = 0; j < 96; ++j) any |= (p[j] != 0);
        if (!any) continue;  // identity contributes nothing
        any_nonidentity = true;
        pack_bls12_381_g1_entry(p, scalars + 32 * i, entry);
        packed.insert(packed.end(), entry, entry + kEntry);
    }

    if (!any_nonidentity) {
        std::memset(result, 0, 96);
        return GPUKIT_OK;
    }

    std::uint8_t rx[64], ry[64];
    if (!cevm::crypto::bls::g1_msm(rx, ry, packed.data(), packed.size())) {
        return GPUKIT_ERR_BAD_SIZE;
    }
    unpack_bls12_381_g1_result(rx, ry, result);
    return GPUKIT_OK;
}

}  // namespace kinet::gpukit::mp
