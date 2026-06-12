// First-party BLS12-381 G1 curve trait for the multi_pippenger CPU reference.
//
//   p = 4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787
//   y^2 = x^3 + 4
//
// This trait satisfies the same interface that Secp256k1Trait and BN254G1Trait
// expose to multi_pippenger.cpp's template body, so the BLS12-381 G1 case is
// dispatched through the *same* signed-digit Bos-Coster Pippenger skeleton as
// every other curve on the kernel -- one MSM body, one auto-tune, one bucket
// sweep.  This is the LP-137 "blst test-only" line: the production kernel
// links zero blst code, only first-party Fp384 + Jacobian formulas.
//
// Wire format adaptation:
//
//   gpukit ABI : 96-byte affine point  (48-byte BE x || 48-byte BE y)
//                32-byte LE scalar
//   trait      : G1Jac with U384 fields in Montgomery form
//
// Identity (point-at-infinity) is wire-encoded as all-zero point bytes,
// matching the convention used by the secp256k1 / bn254 traits.

#pragma once

#include "../../bls/cpp/bls12_381_fp.hpp"
#include "../../bls/cpp/bls12_381_g1.hpp"
#include "kinet/gpukit/gpukit.h"

#include <cstdint>
#include <cstring>

namespace kinet::gpukit::mp {

struct BLS12381G1FirstPartyTrait {
    using Field  = kinet::crypto::bls12_381::U384;
    using Point  = kinet::crypto::bls12_381::G1Jac;
    using Affine = kinet::crypto::bls12_381::G1Affine;

    static Point identity() {
        return kinet::crypto::bls12_381::g1_jac_zero();
    }

    static Point neg(const Point& p) {
        if (p.infinity) return p;
        Point r = p;
        r.Y = kinet::crypto::bls12_381::fp_neg(p.Y);
        return r;
    }

    static Point add(const Point& a, const Point& b) {
        return kinet::crypto::bls12_381::g1_add(a, b);
    }

    static Point double_self(const Point& a) {
        return kinet::crypto::bls12_381::g1_double(a);
    }

    // Read a 96-byte affine point: 48 BE x || 48 BE y.  All-zero = identity.
    static Point read_affine(const std::uint8_t* xy) {
        bool any = false;
        for (int i = 0; i < 96; ++i) any |= (xy[i] != 0);
        if (!any) return kinet::crypto::bls12_381::g1_jac_zero();
        Affine a;
        a.x = kinet::crypto::bls12_381::U384::from_be48(xy);
        a.y = kinet::crypto::bls12_381::U384::from_be48(xy + 48);
        a.x = kinet::crypto::bls12_381::to_mont_fp(a.x);
        a.y = kinet::crypto::bls12_381::to_mont_fp(a.y);
        a.infinity = false;
        return kinet::crypto::bls12_381::g1_to_jac(a);
    }

    static void write_affine(const Point& p, std::uint8_t* xy) {
        Affine a = kinet::crypto::bls12_381::g1_to_affine(p);
        if (a.infinity) {
            std::memset(xy, 0, 96);
            return;
        }
        kinet::crypto::bls12_381::U384 x_canon =
            kinet::crypto::bls12_381::from_mont_fp(a.x);
        kinet::crypto::bls12_381::U384 y_canon =
            kinet::crypto::bls12_381::from_mont_fp(a.y);
        x_canon.to_be48(xy);
        y_canon.to_be48(xy + 48);
    }
};

}  // namespace kinet::gpukit::mp
