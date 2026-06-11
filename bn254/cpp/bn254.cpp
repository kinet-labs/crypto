// First-party bn254 (alt_bn128) implementation -- public API.
// All arithmetic lives in bn254_fp.hpp (field) and bn254_g1.hpp (curve).

#include "bn254.hpp"
#include "bn254_hash_to_curve.hpp"

namespace evmmax::bn254 {

using kinet::crypto::bn254::U256;
using kinet::crypto::bn254::P;
using kinet::crypto::bn254::FR_ORDER;

namespace lc = kinet::crypto::bn254;

static bool fp_in_range(const U256& v) noexcept {
    return U256::cmp(v, P) < 0;
}

static lc::G1Affine api_to_affine(const AffinePoint& pt) noexcept {
    lc::G1Affine a;
    if (pt.x.is_zero() && pt.y.is_zero()) {
        a.x = U256{}; a.y = U256{}; a.infinity = true;
        return a;
    }
    a.x = lc::to_mont_fp(pt.x);
    a.y = lc::to_mont_fp(pt.y);
    a.infinity = false;
    return a;
}

static AffinePoint affine_to_api(const lc::G1Affine& a) noexcept {
    AffinePoint r{};
    if (a.infinity) {
        r.x = U256{}; r.y = U256{};
        return r;
    }
    r.x = lc::from_mont_fp(a.x);
    r.y = lc::from_mont_fp(a.y);
    return r;
}

bool validate(const AffinePoint& pt) noexcept {
    if (pt.x.is_zero() && pt.y.is_zero()) return true;
    if (!fp_in_range(pt.x) || !fp_in_range(pt.y)) return false;
    const lc::G1Affine a = api_to_affine(pt);
    return lc::g1_is_on_curve(a);
}

AffinePoint mul(const AffinePoint& pt, const uint256& c) noexcept {
    if ((pt.x.is_zero() && pt.y.is_zero()) || c.is_zero()) {
        AffinePoint zero{};
        zero.x = U256{}; zero.y = U256{};
        return zero;
    }

    U256 k = c;
    while (U256::cmp(k, FR_ORDER) >= 0) {
        uint64_t bw;
        k = lc::sub_256(k, FR_ORDER, bw);
    }

    const lc::G1Affine a = api_to_affine(pt);
    const lc::G1Jac jr = lc::g1_scalar_mul(a, k);
    const lc::G1Affine ar = lc::g1_to_affine(jr);
    return affine_to_api(ar);
}

std::optional<bool> pairing_check(
    std::span<const std::pair<G1Point, ExtPoint>> pairs) noexcept {
    if (pairs.empty()) return true;

    std::vector<lc::G1Affine> Pv;
    std::vector<lc::G2Affine> Qv;
    Pv.reserve(pairs.size());
    Qv.reserve(pairs.size());

    for (const auto& [g1, g2] : pairs) {
        // Range check: each coordinate must be in [0, p).
        if (!fp_in_range(g1.x) || !fp_in_range(g1.y)) return std::nullopt;
        if (!fp_in_range(g2.x.first)  || !fp_in_range(g2.x.second)) return std::nullopt;
        if (!fp_in_range(g2.y.first)  || !fp_in_range(g2.y.second)) return std::nullopt;

        // G1 affine.
        lc::G1Affine pa;
        if (g1.x.is_zero() && g1.y.is_zero()) {
            pa.x = U256{}; pa.y = U256{}; pa.infinity = true;
        } else {
            pa.x = lc::to_mont_fp(g1.x);
            pa.y = lc::to_mont_fp(g1.y);
            pa.infinity = false;
            if (!lc::g1_is_on_curve(pa)) return std::nullopt;
        }

        // G2 affine. ExtPoint stores (real, imag) per the C-ABI convention;
        // gnark's E2 = a0 + a1*u so a0 = real (.first), a1 = imag (.second).
        lc::G2Affine qa;
        const bool g2_zero = g2.x.first.is_zero() && g2.x.second.is_zero()
                          && g2.y.first.is_zero() && g2.y.second.is_zero();
        if (g2_zero) {
            qa.x = lc::fp2_zero(); qa.y = lc::fp2_zero(); qa.infinity = true;
        } else {
            qa.x.a0 = lc::to_mont_fp(g2.x.first);
            qa.x.a1 = lc::to_mont_fp(g2.x.second);
            qa.y.a0 = lc::to_mont_fp(g2.y.first);
            qa.y.a1 = lc::to_mont_fp(g2.y.second);
            qa.infinity = false;
            if (!lc::g2_is_on_curve(qa)) return std::nullopt;
        }

        Pv.push_back(pa);
        Qv.push_back(qa);
    }

    return lc::multi_pairing_check(Pv.data(), Qv.data(), Pv.size());
}

bool hash_to_g1(std::span<const uint8_t> msg, std::span<const uint8_t> dst,
                AffinePoint& out) noexcept {
    // RFC 9380 BN254G1_XMD:SHA-256_SVDW_RO_ -- see bn254_hash_to_curve.hpp.
    // Misuse (DST > 255 bytes) returns false; otherwise the result is always
    // a well-formed point on the curve (cofactor = 1, no clearing required).
    if (dst.size() > 255) {
        out.x = U256{}; out.y = U256{};
        return false;
    }
    const lc::G1Affine ar = lc::h2c::hash_to_curve_g1(msg, dst);
    out = affine_to_api(ar);
    return true;
}

}  // namespace evmmax::bn254
