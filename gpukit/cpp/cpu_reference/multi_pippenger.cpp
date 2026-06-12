// Multi-curve Pippenger MSM kernel -- CPU reference.
//
// Single bucket-sort skeleton, parameterised by a curve trait struct that
// supplies field arithmetic + group operations. The four supported curves
// each route through their own first-party CPU library:
//
//   secp256k1     -> kinet::crypto::secp256k1::{AffinePoint, JacobianPoint}
//   bn254 g1      -> kinet::crypto::bn254::{G1Affine, G1Jac}
//   bls12-381 g1  -> kinet::crypto::bls12_381::{G1Affine, G1Jac}  (first-party
//                    Fp384 + Jacobian Bernstein-Lange formulas in
//                    bls/cpp/bls12_381_{fp,g1}.hpp -- header-only, stdlib-only,
//                    zero blst).  Dispatched via the trait struct in
//                    gpukit/curve_traits/bls12_381_g1_first_party_traits.h.
//   banderwagon   -> kinet::banderwagon::Element  (delegates to the existing
//                    multiexp.cpp body to avoid duplicating its proven
//                    signed-digit Pippenger -- the multi-curve kernel is the
//                    *dispatch* point, not a re-implementation).
//
// Algorithm: signed-digit Bos-Coster Pippenger. Cost-tuned window size
// c in [4, 16]; per c-bit window, partition each scalar into a digit
// d in (-2^{c-1}, +2^{c-1}], borrowing 2^c into the next window when the
// raw digit exceeds 2^{c-1}. M = 2^{c-1} buckets, running-sum reduction.
//
// All four curves share this skeleton; only the field/group ops differ.

#include "kinet/gpukit/multi_pippenger.h"
#include "kinet/gpukit/gpukit.h"

#include <cstdint>
#include <cstring>
#include <limits>
#include <vector>

// secp256k1 + bn254 G1 are header-only Jacobian arithmetic.
#include "../../../secp256k1/cpp/curve.hpp"
#include "../../../secp256k1/cpp/field.hpp"
#include "../../../bn254/cpp/bn254_g1.hpp"
#include "../../../bn254/cpp/bn254_fp.hpp"
// Banderwagon group element + the proven signed-digit MSM body.
#include "../../../banderwagon/cpp/element.hpp"
#include "../../../banderwagon/cpp/fr.hpp"
#include "../../../banderwagon/cpp/multiexp.hpp"
// BLS12-381 G1: first-party Fp384 + Jacobian arithmetic dispatched through
// the same signed-digit Pippenger template as the other curves.  Linking
// this trait pulls in zero blst code -- the field and group ops live in
// crypto/bls/cpp/bls12_381_{fp,g1}.hpp and depend only on the C++ stdlib.
#include "../../curve_traits/bls12_381_g1_first_party_traits.h"

namespace kinet::gpukit::mp {
namespace {

// =============================================================================
// Common signed-digit Pippenger over a generic point-trait.
// =============================================================================
//
// The trait T must provide:
//   using Point;                     point type returned by add/double/...
//   static Point identity();
//   static Point neg(const Point&);
//   static Point add(const Point&, const Point&);
//   static Point double_self(const Point&);
//   static Point read_affine(const uint8_t* xy);   // 64 bytes, LE x||LE y
//   static void  write_affine(const Point&, uint8_t* xy);  // 64 bytes
//
// scalars: n * 32 bytes, LE canonical.

constexpr int kBits = 256;

inline std::uint64_t cost_model(std::uint64_t c, std::size_t n) {
    // (256/c) * (n + 2^c) -- minimised over c.
    const std::uint64_t windows = (kBits + c - 1) / c;
    const std::uint64_t pow2c = (std::uint64_t)1 << c;
    return windows * ((std::uint64_t)n + pow2c);
}

inline std::uint64_t best_c(std::size_t n) {
    static const std::uint64_t cs[] = {4, 5, 6, 7, 8, 9, 10, 11, 12};
    std::uint64_t best = 4;
    std::uint64_t best_cost = std::numeric_limits<std::uint64_t>::max();
    for (std::uint64_t c : cs) {
        std::uint64_t cost = cost_model(c, n);
        if (cost < best_cost) {
            best_cost = cost;
            best = c;
        }
    }
    return best;
}

inline std::uint32_t window_digit(const std::uint8_t* s_le,
                                  std::size_t bit_offset,
                                  std::uint64_t c) {
    const std::size_t byte_idx = bit_offset >> 3;
    const std::size_t bit_in_byte = bit_offset & 7;
    std::uint32_t word = 0;
    for (int i = 0; i < 4; ++i) {
        const std::size_t bi = byte_idx + i;
        if (bi < 32) word |= (std::uint32_t)s_le[bi] << (8 * i);
    }
    word >>= bit_in_byte;
    return word & ((1u << c) - 1u);
}

template <class Trait>
typename Trait::Point process_window(const typename Trait::Point* points,
                                     const std::uint8_t* scalars_le,
                                     std::size_t n,
                                     std::size_t bit_offset,
                                     std::uint64_t c,
                                     std::vector<typename Trait::Point>& buckets,
                                     std::vector<int>& carries) {
    using P = typename Trait::Point;
    const std::int32_t max_pos = (std::int32_t)1 << (c - 1);
    const std::size_t M = (std::size_t)1 << (c - 1);

    for (std::size_t k = 0; k < M; ++k) buckets[k] = Trait::identity();

    for (std::size_t i = 0; i < n; ++i) {
        std::uint32_t bits = window_digit(scalars_le + 32 * i, bit_offset, c);
        std::int32_t digit = (std::int32_t)bits + carries[i];
        carries[i] = 0;
        if (digit > max_pos) {
            digit -= (std::int32_t)1 << c;
            carries[i] = 1;
        }
        if (digit == 0) continue;  // skip after borrow normalisation
        if (digit > 0) {
            const std::size_t k = (std::size_t)digit - 1;
            buckets[k] = Trait::add(buckets[k], points[i]);
        } else {
            const std::size_t k = (std::size_t)(-digit) - 1;
            buckets[k] = Trait::add(buckets[k], Trait::neg(points[i]));
        }
    }

    P running = Trait::identity();
    P total   = Trait::identity();
    for (std::size_t k_inv = 0; k_inv < M; ++k_inv) {
        const std::size_t k = M - 1 - k_inv;
        running = Trait::add(running, buckets[k]);
        total   = Trait::add(total, running);
    }
    return total;
}

template <class Trait>
typename Trait::Point pippenger(const typename Trait::Point* points,
                                const std::uint8_t* scalars_le,
                                std::size_t n) {
    using P = typename Trait::Point;
    if (n == 0) return Trait::identity();

    const std::uint64_t c = best_c(n);
    const std::size_t M = (std::size_t)1 << (c - 1);
    const std::size_t nbChunks = (kBits + c - 1) / c;

    std::vector<P> buckets(M);
    std::vector<int> carries(n, 0);
    std::vector<P> window_sums(nbChunks);

    for (std::size_t w = 0; w < nbChunks; ++w) {
        const std::size_t bit_offset = w * (std::size_t)c;
        window_sums[w] = process_window<Trait>(
            points, scalars_le, n, bit_offset, c, buckets, carries);
    }

    P result = window_sums[nbChunks - 1];
    bool dbg2 = (std::getenv("MP_DEBUG2") != nullptr);
    for (std::size_t w_inv = 1; w_inv < nbChunks; ++w_inv) {
        for (std::uint64_t b = 0; b < c; ++b) {
            result = Trait::double_self(result);
        }
        const std::size_t w = nbChunks - 1 - w_inv;
        result = Trait::add(result, window_sums[w]);
        if (dbg2) {
            // Generic placeholder; only prints first 4 limbs of result if Point has X with limbs[].
            std::fprintf(stderr, "combine w_inv=%zu w=%zu\n", w_inv, w);
        }
    }
    return result;
}

// =============================================================================
// secp256k1 trait.
// =============================================================================

struct Secp256k1Trait {
    using Field = kinet::crypto::secp256k1::U256;
    using Point = kinet::crypto::secp256k1::JacobianPoint;
    using Affine = kinet::crypto::secp256k1::AffinePoint;

    static Point identity() { return kinet::crypto::secp256k1::jac_zero(); }

    static Point neg(const Point& p) {
        if (p.infinity) return p;
        Point r = p;
        // -P in Jacobian = (X, -Y, Z).
        r.Y = kinet::crypto::secp256k1::fp_sub(
            kinet::crypto::secp256k1::U256{}, p.Y);
        return r;
    }

    static Point add(const Point& a, const Point& b) {
        return kinet::crypto::secp256k1::jac_add(a, b);
    }

    static Point double_self(const Point& a) {
        return kinet::crypto::secp256k1::jac_double(a);
    }

    // 32-byte BE x || 32-byte BE y. All-zero = identity.
    static Point read_affine(const std::uint8_t* xy) {
        bool any = false;
        for (int i = 0; i < 64; ++i) any |= (xy[i] != 0);
        if (!any) return kinet::crypto::secp256k1::jac_zero();
        Affine a;
        a.x = kinet::crypto::secp256k1::U256::from_be32(xy);
        a.y = kinet::crypto::secp256k1::U256::from_be32(xy + 32);
        // Canonical -> Montgomery.
        a.x = kinet::crypto::secp256k1::to_mont_p(a.x);
        a.y = kinet::crypto::secp256k1::to_mont_p(a.y);
        a.infinity = false;
        return kinet::crypto::secp256k1::affine_to_jacobian(a);
    }

    static void write_affine(const Point& p, std::uint8_t* xy) {
        Affine a = kinet::crypto::secp256k1::jacobian_to_affine(p);
        if (a.infinity) {
            std::memset(xy, 0, 64);
            return;
        }
        kinet::crypto::secp256k1::U256 x_canon =
            kinet::crypto::secp256k1::from_mont_p(a.x);
        kinet::crypto::secp256k1::U256 y_canon =
            kinet::crypto::secp256k1::from_mont_p(a.y);
        x_canon.to_be32(xy);
        y_canon.to_be32(xy + 32);
    }
};

// =============================================================================
// BN254 G1 trait.
// =============================================================================

struct BN254G1Trait {
    using Field = kinet::crypto::bn254::U256;
    using Point = kinet::crypto::bn254::G1Jac;
    using Affine = kinet::crypto::bn254::G1Affine;

    static Point identity() { return kinet::crypto::bn254::g1_jac_zero(); }

    static Point neg(const Point& p) {
        if (p.infinity) return p;
        Point r = p;
        r.Y = kinet::crypto::bn254::fp_neg(p.Y);
        return r;
    }

    static Point add(const Point& a, const Point& b) {
        return kinet::crypto::bn254::g1_add(a, b);
    }

    static Point double_self(const Point& a) {
        return kinet::crypto::bn254::g1_double(a);
    }

    static Point read_affine(const std::uint8_t* xy) {
        bool any = false;
        for (int i = 0; i < 64; ++i) any |= (xy[i] != 0);
        if (!any) return kinet::crypto::bn254::g1_jac_zero();
        Affine a;
        a.x = kinet::crypto::bn254::U256::from_be32(xy);
        a.y = kinet::crypto::bn254::U256::from_be32(xy + 32);
        a.x = kinet::crypto::bn254::to_mont_fp(a.x);
        a.y = kinet::crypto::bn254::to_mont_fp(a.y);
        a.infinity = false;
        return kinet::crypto::bn254::g1_to_jac(a);
    }

    static void write_affine(const Point& p, std::uint8_t* xy) {
        Affine a = kinet::crypto::bn254::g1_to_affine(p);
        if (a.infinity) {
            std::memset(xy, 0, 64);
            return;
        }
        kinet::crypto::bn254::U256 x_canon = kinet::crypto::bn254::from_mont_fp(a.x);
        kinet::crypto::bn254::U256 y_canon = kinet::crypto::bn254::from_mont_fp(a.y);
        x_canon.to_be32(xy);
        y_canon.to_be32(xy + 32);
    }
};

}  // namespace
}  // namespace kinet::gpukit::mp

// =============================================================================
// Banderwagon dispatch -- delegates to the proven multiexp.cpp body.
// =============================================================================
//
// We do NOT re-implement the signed-digit Pippenger here for Banderwagon. The
// existing kinet::banderwagon::multi_scalar_mul body has shipped KATs against
// the Go reference; using it directly preserves byte-equality across the
// repo. Wire format: 32-byte canonical-LE for points (compressed Banderwagon
// encoding) and 32-byte canonical-LE for scalars.
//
// For consistency with the unified gpukit_multi_pippenger ABI (64-byte
// affine x||y), we accept the 64-byte form: Banderwagon's wire encoding
// fits in 32 bytes (compressed) or 64 bytes (uncompressed = x||y), and the
// public Element supports both. We use the uncompressed path so the ABI is
// uniform with secp256k1 / bn254 / bls.

namespace kinet::gpukit::mp {

static int multi_pippenger_banderwagon(const std::uint8_t* scalars,
                                       const std::uint8_t* points,
                                       std::size_t n,
                                       std::uint8_t* result) {
    using kinet::banderwagon::Element;
    using kinet::banderwagon::Fr;

    std::vector<Element> elts(n);
    std::vector<Fr> ss(n);
    for (std::size_t i = 0; i < n; ++i) {
        std::uint8_t pt[64];
        std::memcpy(pt, points + 64 * i, 64);
        bool any = false;
        for (int j = 0; j < 64; ++j) any |= (pt[j] != 0);
        if (!any) {
            elts[i] = Element::identity();
        } else {
            if (!Element::deserialize_uncompressed(pt, elts[i])) {
                return GPUKIT_ERR_BAD_SIZE;
            }
        }
        if (!Fr::from_bytes_le(scalars + 32 * i, ss[i])) {
            return GPUKIT_ERR_BAD_SIZE;
        }
    }

    Element r = kinet::banderwagon::multi_scalar_mul(elts.data(), ss.data(), n);
    // Emit uncompressed x||y (64 bytes) to match the unified ABI. Banderwagon
    // emits 32-byte compressed by default; for the unified surface we use the
    // uncompressed serialiser that is part of Element's public API.
    std::array<std::uint8_t, 64> wire{};
    r.serialize_uncompressed(wire.data());
    std::memcpy(result, wire.data(), 64);
    return GPUKIT_OK;
}

}  // namespace kinet::gpukit::mp

// =============================================================================
// Public C-ABI entry.
// =============================================================================

extern "C" int gpukit_multi_pippenger_cpu(uint32_t curve,
                                          const uint8_t* scalars,
                                          const uint8_t* points,
                                          size_t n,
                                          uint8_t* result) {
    if (!result) return GPUKIT_ERR_NULL_ARG;
    if (n > 0 && (!scalars || !points)) return GPUKIT_ERR_NULL_ARG;

    using namespace kinet::gpukit::mp;

    switch (curve) {
        case GPUKIT_CURVE_SECP256K1: {
            std::vector<Secp256k1Trait::Point> pts(n);
            for (std::size_t i = 0; i < n; ++i) {
                pts[i] = Secp256k1Trait::read_affine(points + 64 * i);
            }
            auto out = pippenger<Secp256k1Trait>(pts.data(), scalars, n);
            Secp256k1Trait::write_affine(out, result);
            return GPUKIT_OK;
        }
        case GPUKIT_CURVE_BN254_G1: {
            std::vector<BN254G1Trait::Point> pts(n);
            for (std::size_t i = 0; i < n; ++i) {
                pts[i] = BN254G1Trait::read_affine(points + 64 * i);
            }
            auto out = pippenger<BN254G1Trait>(pts.data(), scalars, n);
            BN254G1Trait::write_affine(out, result);
            return GPUKIT_OK;
        }
        case GPUKIT_CURVE_BLS12_381_G1: {
            // 96-byte BE x||y wire (48-byte BE per coordinate).  Identity is
            // all-zero per the unified ABI; the trait's read_affine handles
            // that branch up front.  Pippenger runs over the same 256-bit
            // window as the other curves; scalars are LE canonical and
            // already < r (the test harness clips top byte).
            std::vector<BLS12381G1FirstPartyTrait::Point> pts(n);
            for (std::size_t i = 0; i < n; ++i) {
                pts[i] = BLS12381G1FirstPartyTrait::read_affine(points + 96 * i);
            }
            auto out = pippenger<BLS12381G1FirstPartyTrait>(pts.data(), scalars, n);
            BLS12381G1FirstPartyTrait::write_affine(out, result);
            return GPUKIT_OK;
        }
        case GPUKIT_CURVE_BANDERWAGON: {
            return multi_pippenger_banderwagon(scalars, points, n, result);
        }
        default:
            return GPUKIT_ERR_BACKEND;
    }
}
