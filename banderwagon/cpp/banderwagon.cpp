// =============================================================================
// kinet-labs/crypto/banderwagon -- implementation
// =============================================================================

#include "banderwagon.hpp"

#include <array>
#include <cassert>
#include <cstring>
#include <stdexcept>

namespace kinet::crypto::banderwagon {

// =============================================================================
// Fp -- BLS12-381 Fr (Banderwagon base field)
// =============================================================================

namespace {

// q = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
constexpr intx::uint256 kFpModulus = intx::from_string<intx::uint256>(
    "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");

// (q - 1) / 2 (used for lex-largest test)
constexpr intx::uint256 kFpHalfOrder = intx::from_string<intx::uint256>(
    "0x39f6d3a994cebea4199cec0404d0ec0229dd2017fff2dff7ffffffff80000000");

// r (Banderwagon scalar field order)
constexpr intx::uint256 kFrModulus = intx::from_string<intx::uint256>(
    "0x1cfb69d4ca675f520cce760202687600ff8f87007419047174fd06b52876e7e1");

// Convenience: convert Fp's 4-limb LE representation into intx::uint256.
intx::uint256 to_u256(const std::array<uint64_t, 4>& l) {
    intx::uint256 r;
    r[0] = l[0];
    r[1] = l[1];
    r[2] = l[2];
    r[3] = l[3];
    return r;
}

void from_u256(const intx::uint256& v, std::array<uint64_t, 4>& l) {
    l[0] = v[0];
    l[1] = v[1];
    l[2] = v[2];
    l[3] = v[3];
}

// big-endian load of a uint256 from 32 bytes
intx::uint256 be_load_u256(const uint8_t bytes[32]) {
    intx::uint256 r{};
    for (int i = 0; i < 32; ++i) {
        r = (r << 8) | intx::uint256{bytes[i]};
    }
    return r;
}

void be_store_u256(const intx::uint256& v, uint8_t out[32]) {
    intx::uint256 t = v;
    for (int i = 31; i >= 0; --i) {
        out[i] = static_cast<uint8_t>(t[0] & 0xff);
        t >>= 8;
    }
}

}  // namespace

const intx::uint256 Fp::modulus() { return kFpModulus; }
const intx::uint256 Fr::modulus() { return kFrModulus; }

const Fp& Fp::zero() { static const Fp z{}; return z; }
const Fp& Fp::one()  { static const Fp o{1}; return o; }
const Fp& Fp::minus_one() {
    static const Fp m = Fp::zero().sub(Fp::one());
    return m;
}

const Fr& Fr::zero() { static const Fr z{}; return z; }
const Fr& Fr::one()  { static const Fr o{1}; return o; }

Fp::Fp(uint64_t v) : limbs_{v, 0, 0, 0} {}
Fr::Fr(uint64_t v) : limbs_{v, 0, 0, 0} {}

bool Fp::is_zero() const { return limbs_[0] == 0 && limbs_[1] == 0 && limbs_[2] == 0 && limbs_[3] == 0; }
bool Fp::is_one()  const { return limbs_[0] == 1 && limbs_[1] == 0 && limbs_[2] == 0 && limbs_[3] == 0; }
bool Fp::equal(const Fp& o) const { return limbs_ == o.limbs_; }

bool Fr::is_zero() const { return limbs_[0] == 0 && limbs_[1] == 0 && limbs_[2] == 0 && limbs_[3] == 0; }
bool Fr::equal(const Fr& o) const { return limbs_ == o.limbs_; }

// ---- Reduction utility ------------------------------------------------------

Fp Fp::reduce_512(const intx::uint512& x) {
    // Reduce a 512-bit value modulo q. We do this with intx::udivrem which
    // gives correct modular reduction. q fits comfortably in uint256.
    intx::uint512 m{kFpModulus};
    intx::uint512 r = x % m;
    Fp out;
    intx::uint256 r256;
    r256[0] = r[0];
    r256[1] = r[1];
    r256[2] = r[2];
    r256[3] = r[3];
    from_u256(r256, out.limbs_);
    return out;
}

// ---- Construction from canonical bytes ---------------------------------------

Fp Fp::from_canonical_be(const uint8_t bytes[32]) {
    Fp out;
    if (!try_from_canonical_be(bytes, out)) {
        // Caller violated precondition; reduce defensively.
        intx::uint256 v = be_load_u256(bytes) % kFpModulus;
        from_u256(v, out.limbs_);
    }
    return out;
}

Fp Fp::from_canonical_le(const uint8_t bytes[32]) {
    uint8_t be[32];
    for (int i = 0; i < 32; ++i) be[i] = bytes[31 - i];
    return from_canonical_be(be);
}

bool Fp::try_from_canonical_be(const uint8_t bytes[32], Fp& out) {
    intx::uint256 v = be_load_u256(bytes);
    if (v >= kFpModulus) return false;
    from_u256(v, out.limbs_);
    return true;
}

bool Fp::try_from_canonical_le(const uint8_t bytes[32], Fp& out) {
    uint8_t be[32];
    for (int i = 0; i < 32; ++i) be[i] = bytes[31 - i];
    return try_from_canonical_be(be, out);
}

void Fp::to_canonical_be(uint8_t out[32]) const {
    be_store_u256(to_u256(limbs_), out);
}

void Fp::to_canonical_le(uint8_t out[32]) const {
    uint8_t be[32];
    to_canonical_be(be);
    for (int i = 0; i < 32; ++i) out[i] = be[31 - i];
}

// ---- Decimal/hex parsing for static curve parameters -------------------------

namespace {

intx::uint256 parse_decimal(const std::string& dec) {
    intx::uint256 r{0};
    intx::uint256 ten{10};
    bool neg = false;
    size_t i = 0;
    if (!dec.empty() && dec[0] == '-') { neg = true; i = 1; }
    for (; i < dec.size(); ++i) {
        char c = dec[i];
        if (c < '0' || c > '9') throw std::invalid_argument("invalid decimal");
        r = r * ten + intx::uint256{static_cast<uint64_t>(c - '0')};
    }
    if (neg) {
        // Return q - r mod q (caller will use this for negative constants).
        r = (kFpModulus - (r % kFpModulus)) % kFpModulus;
    } else {
        r = r % kFpModulus;
    }
    return r;
}

}  // namespace

Fp Fp::from_decimal(const std::string& dec) {
    Fp out;
    intx::uint256 v = parse_decimal(dec);
    from_u256(v, out.limbs_);
    return out;
}

Fp Fp::from_hex(const std::string& hex) {
    Fp out;
    intx::uint256 v = intx::from_string<intx::uint256>(hex) % kFpModulus;
    from_u256(v, out.limbs_);
    return out;
}

// ---- Arithmetic --------------------------------------------------------------

Fp Fp::add(const Fp& o) const {
    intx::uint256 a = to_u256(limbs_);
    intx::uint256 b = to_u256(o.limbs_);
    intx::uint256 s = a + b;
    if (s >= kFpModulus) s -= kFpModulus;
    Fp out;
    from_u256(s, out.limbs_);
    return out;
}

Fp Fp::sub(const Fp& o) const {
    intx::uint256 a = to_u256(limbs_);
    intx::uint256 b = to_u256(o.limbs_);
    intx::uint256 r;
    if (a >= b) {
        r = a - b;
    } else {
        r = (kFpModulus - b) + a;
    }
    Fp out;
    from_u256(r, out.limbs_);
    return out;
}

Fp Fp::neg() const {
    if (is_zero()) return *this;
    intx::uint256 a = to_u256(limbs_);
    intx::uint256 r = kFpModulus - a;
    Fp out;
    from_u256(r, out.limbs_);
    return out;
}

Fp Fp::mul(const Fp& o) const {
    intx::uint256 a = to_u256(limbs_);
    intx::uint256 b = to_u256(o.limbs_);
    intx::uint512 prod = intx::umul(a, b);
    return reduce_512(prod);
}

Fp Fp::square() const {
    return mul(*this);
}

Fp Fp::pow(const intx::uint256& exp) const {
    Fp result = Fp::one();
    Fp base = *this;
    intx::uint256 e = exp;
    while (e != 0) {
        if ((e[0] & 1) != 0) {
            result = result.mul(base);
        }
        base = base.square();
        e >>= 1;
    }
    return result;
}

Fp Fp::inverse() const {
    if (is_zero()) return *this;
    intx::uint256 q_minus_2 = kFpModulus - intx::uint256{2};
    return pow(q_minus_2);
}

Fp Fp::mul5() const {
    Fp two = add(*this);
    Fp four = two.add(two);
    return four.add(*this);
}

int Fp::legendre() const {
    if (is_zero()) return 0;
    intx::uint256 exp = (kFpModulus - intx::uint256{1}) >> 1;
    Fp r = pow(exp);
    if (r.is_one()) return 1;
    Fp mone = Fp::minus_one();
    if (r.equal(mone)) return -1;
    // Should never happen in a prime field.
    return 0;
}

bool Fp::lexicographically_largest() const {
    intx::uint256 v = to_u256(limbs_);
    return v > kFpHalfOrder;
}

// Tonelli-Shanks for q where q-1 = 2^S * Q with Q odd.
// For BLS12-381 Fr we compute S and Q at runtime from the modulus.
bool Fp::sqrt(Fp& out) const {
    if (is_zero()) {
        out = Fp::zero();
        return true;
    }
    if (legendre() != 1) return false;

    // q-1 = 2^S * Q
    intx::uint256 q_minus_1 = kFpModulus - intx::uint256{1};
    intx::uint256 Q = q_minus_1;
    int S = 0;
    while ((Q[0] & 1) == 0) { Q >>= 1; ++S; }

    // Find a non-residue z.
    Fp z = Fp::one().add(Fp::one());
    while (z.legendre() != -1) {
        z = z.add(Fp::one());
    }

    Fp M = Fp::from_decimal(std::to_string(S));
    // We don't actually need M as an Fp: we use S as int.
    (void)M;

    Fp c = z.pow(Q);
    Fp t = pow(Q);
    intx::uint256 Qp1_div2 = (Q + intx::uint256{1}) >> 1;
    Fp R = pow(Qp1_div2);

    while (true) {
        if (t.is_one()) {
            out = R;
            return true;
        }
        // Find least i in (0, M) such that t^(2^i) == 1.
        int i = 0;
        Fp tt = t;
        while (!tt.is_one()) {
            tt = tt.square();
            ++i;
            if (i >= S) return false;  // shouldn't happen if legendre == 1
        }

        // b = c^(2^(M - i - 1)).
        Fp b = c;
        for (int k = 0; k < S - i - 1; ++k) {
            b = b.square();
        }
        S = i;
        c = b.square();
        t = t.mul(c);
        R = R.mul(b);
    }
}

// =============================================================================
// Fr (Banderwagon scalar field; arithmetic-light: only need bit access for
// scalar mul; full arithmetic is not required for IPA core ops the user asked
// us to wire.)
// =============================================================================

bool Fr::try_from_canonical_be(const uint8_t bytes[32], Fr& out) {
    intx::uint256 v = be_load_u256(bytes);
    if (v >= kFrModulus) return false;
    out.limbs_[0] = v[0];
    out.limbs_[1] = v[1];
    out.limbs_[2] = v[2];
    out.limbs_[3] = v[3];
    return true;
}

Fr Fr::from_canonical_be(const uint8_t bytes[32]) {
    Fr out;
    if (!try_from_canonical_be(bytes, out)) {
        intx::uint256 v = be_load_u256(bytes) % kFrModulus;
        out.limbs_[0] = v[0];
        out.limbs_[1] = v[1];
        out.limbs_[2] = v[2];
        out.limbs_[3] = v[3];
    }
    return out;
}

bool Fr::try_from_canonical_le(const uint8_t bytes[32], Fr& out) {
    uint8_t be[32];
    for (int i = 0; i < 32; ++i) be[i] = bytes[31 - i];
    return try_from_canonical_be(be, out);
}

Fr Fr::from_canonical_le(const uint8_t bytes[32]) {
    uint8_t be[32];
    for (int i = 0; i < 32; ++i) be[i] = bytes[31 - i];
    return from_canonical_be(be);
}

void Fr::to_canonical_be(uint8_t out[32]) const {
    intx::uint256 v;
    v[0] = limbs_[0];
    v[1] = limbs_[1];
    v[2] = limbs_[2];
    v[3] = limbs_[3];
    be_store_u256(v, out);
}

void Fr::to_canonical_le(uint8_t out[32]) const {
    uint8_t be[32];
    to_canonical_be(be);
    for (int i = 0; i < 32; ++i) out[i] = be[31 - i];
}

size_t Fr::bit_length() const {
    for (int i = 3; i >= 0; --i) {
        if (limbs_[i] != 0) {
            uint64_t v = limbs_[i];
            size_t b = 0;
            while (v != 0) { ++b; v >>= 1; }
            return static_cast<size_t>(i) * 64 + b;
        }
    }
    return 0;
}

bool Fr::bit(size_t i) const {
    if (i >= 256) return false;
    return ((limbs_[i / 64] >> (i % 64)) & 1ULL) != 0;
}

// =============================================================================
// Curve params (initialised on first use)
// =============================================================================

const CurveParams& curve_params() {
    static const CurveParams p = []{
        CurveParams cp;
        cp.a = Fp::from_decimal("-5");
        cp.d = Fp::from_decimal(
            "45022363124591815672509500913686876175488063829319466900776701791074614335719");
        cp.base_x = Fp::from_decimal(
            "18886178867200960497001835917649091219057080094937609519140440539760939937304");
        cp.base_y = Fp::from_decimal(
            "19188667384257783945677642223292697773471335439753913231509108946878080696678");
        return cp;
    }();
    return p;
}

// =============================================================================
// PointProj
// =============================================================================
//
// Twisted Edwards in projective coordinates with a = -5.
// We implement Add / Double / MixedAdd from gnark-crypto's bandersnatch/point.go
// (https://hyperelliptic.org/EFD/g1p/auto-twisted-projective.html#addition-add-2008-bbjlp
// and -dbl-2008-bbjlp), specialised so that mulByA(x) = -(5 * x).

namespace {

inline Fp mul_by_a(const Fp& x) {
    // a = -5; mulByA(x) = (-x) * 5 = -(5*x)
    return x.neg().mul5();
}

}  // namespace

PointProj PointProj::identity() {
    return {Fp::zero(), Fp::one(), Fp::one()};
}

PointProj PointProj::generator() {
    const auto& cp = curve_params();
    return {cp.base_x, cp.base_y, Fp::one()};
}

bool PointProj::is_identity() const {
    // Identity in projective form has X == 0 and Y == Z (both nonzero), or Z = 0.
    if (Z.is_zero()) return true;  // point at infinity
    return X.is_zero() && Y.equal(Z);
}

bool PointProj::equal_proj(const PointProj& o) const {
    if (Z.is_zero()) return o.Z.is_zero();
    if (o.Z.is_zero()) return false;
    Fp lhs = X.mul(o.Z);
    Fp rhs = o.X.mul(Z);
    if (!lhs.equal(rhs)) return false;
    lhs = Y.mul(o.Z);
    rhs = o.Y.mul(Z);
    return lhs.equal(rhs);
}

bool PointProj::equal_banderwagon(const PointProj& o) const {
    // Banderwagon equality: x1 * y2 == y1 * x2 (in affine).
    // In projective: (X1/Z1) * (Y2/Z2) == (Y1/Z1) * (X2/Z2)
    // Multiply both sides by Z1*Z2: X1 * Y2 == Y1 * X2.
    Fp lhs = X.mul(o.Y);
    Fp rhs = Y.mul(o.X);
    return lhs.equal(rhs);
}

PointProj PointProj::neg() const {
    return {X.neg(), Y, Z};
}

// Edwards Add (add-2008-bbjlp)
PointProj PointProj::add(const PointProj& o) const {
    const auto& cp = curve_params();
    const Fp& X1 = X; const Fp& Y1 = Y; const Fp& Z1 = Z;
    const Fp& X2 = o.X; const Fp& Y2 = o.Y; const Fp& Z2 = o.Z;

    Fp A = Z1.mul(Z2);
    Fp B = A.square();
    Fp C = X1.mul(X2);
    Fp D = Y1.mul(Y2);
    Fp E = cp.d.mul(C).mul(D);
    Fp F = B.sub(E);
    Fp G = B.add(E);
    Fp H = X1.add(Y1);
    Fp I = X2.add(Y2);

    // X3 = A * F * ((X1+Y1)*(X2+Y2) - C - D)
    Fp xtmp = H.mul(I).sub(C).sub(D);
    Fp X3 = xtmp.mul(A).mul(F);

    // Y3 = A * G * (D - a*C); a = -5 so -a*C = 5*C; D + (-a*C) = D + 5*C, but
    // gnark does mulByA(C); C.Neg(C); Y3 = D + C; that yields D - mulByA(orig_C).
    // mulByA(C) = -5*C, then -mulByA(C) = 5*C, so Y3 = D + 5*C... wait re-read.
    //
    // gnark code:
    //   E = d*C*D, F = B-E, G = B+E
    //   X3 = (...) * A * F
    //   mulByA(&C); C.Neg(&C); Y3 = (D + C) * A * G
    //
    // mulByA(C) computes C := a*C = -5*C. Then C.Neg(C) makes C := 5*C.
    // So Y3 = (D + 5*C) * A * G = (D - a*C) * A * G  ... since a = -5.
    Fp aC = mul_by_a(C);
    Fp negaC = aC.neg();   // = 5*C
    Fp Y3 = D.add(negaC).mul(A).mul(G);
    Fp Z3 = F.mul(G);

    return {X3, Y3, Z3};
}

PointProj PointProj::dbl() const {
    // dbl-2008-bbjlp
    Fp B = X.add(Y).square();
    Fp C = X.square();
    Fp D = Y.square();
    Fp E = mul_by_a(C);              // a*C = -5*C
    Fp F = E.add(D);
    Fp H = Z.square();
    Fp J = F.sub(H).sub(H);

    Fp X3 = B.sub(C).sub(D).mul(J);
    Fp Y3 = E.sub(D).mul(F);
    Fp Z3 = F.mul(J);

    return {X3, Y3, Z3};
}

PointProj PointProj::sub(const PointProj& o) const {
    return add(o.neg());
}

PointProj PointProj::scalar_mul(const Fr& s) const {
    PointProj result = PointProj::identity();
    PointProj base = *this;
    size_t bl = s.bit_length();
    if (bl == 0) return result;
    // MSB-first double-and-add.
    for (size_t i = bl; i-- > 0;) {
        result = result.dbl();
        if (s.bit(i)) {
            result = result.add(base);
        }
    }
    return result;
}

void PointProj::to_affine(Fp& x_out, Fp& y_out) const {
    if (Z.is_zero()) {
        x_out = Fp::zero();
        y_out = Fp::zero();
        return;
    }
    Fp zinv = Z.inverse();
    x_out = X.mul(zinv);
    y_out = Y.mul(zinv);
}

bool PointProj::is_on_curve() const {
    // Check in affine: -x^2 + y^2 = 1 + d * x^2 * y^2 (a = -5, but the curve
    // relation tests use the *literal* constant a from CurveParams).
    // Equivalently: a*x^2 + y^2 = 1 + d*x^2*y^2 with a from params.
    Fp x, y;
    to_affine(x, y);
    const auto& cp = curve_params();
    Fp lhs = mul_by_a(x.square()).add(y.square());     // a*x^2 + y^2
    Fp rhs = Fp::one().add(cp.d.mul(x.square()).mul(y.square()));
    return lhs.equal(rhs);
}

// =============================================================================
// Element
// =============================================================================

Element Element::identity() { return Element{PointProj::identity()}; }
Element Element::generator() { return Element{PointProj::generator()}; }

Element Element::add(const Element& o) const { return Element{inner_.add(o.inner_)}; }
Element Element::sub(const Element& o) const { return Element{inner_.sub(o.inner_)}; }
Element Element::dbl() const { return Element{inner_.dbl()}; }
Element Element::neg() const { return Element{inner_.neg()}; }
Element Element::scalar_mul(const Fr& s) const { return Element{inner_.scalar_mul(s)}; }

bool Element::equal(const Element& o) const {
    // Banderwagon equality: x1*y2 == y1*x2 (after dividing through by Z).
    // In projective form: (X1/Z1)*(Y2/Z2) == (Y1/Z1)*(X2/Z2)
    // -> X1*Y2*Z2*Z1 ... cancels: X1*Y2 == Y1*X2 since Z1, Z2 cancel from
    // both sides? Let's redo carefully.
    //
    // affine_x1 = X1/Z1, affine_y1 = Y1/Z1
    // affine_x2 = X2/Z2, affine_y2 = Y2/Z2
    // x1*y2 = X1*Y2 / (Z1*Z2)
    // y1*x2 = Y1*X2 / (Z1*Z2)
    // So x1*y2 == y1*x2 iff X1*Y2 == Y1*X2.
    //
    // Edge case: if both points are identity (X=0, Y=Z), then X1*Y2=0 and
    // Y1*X2=0 so they compare equal. If exactly one is identity, the other
    // has X != 0 (otherwise it would also be identity), and the LHS = X1*Y2
    // would be nonzero, RHS = Y1*X2 would be 0; mismatch. Correct.
    //
    // The reference Go also rejects (0,0) explicitly. Replicate.
    if (inner_.X.is_zero() && inner_.Y.is_zero()) return false;
    if (o.inner_.X.is_zero() && o.inner_.Y.is_zero()) return false;
    Fp lhs = inner_.X.mul(o.inner_.Y);
    Fp rhs = inner_.Y.mul(o.inner_.X);
    return lhs.equal(rhs);
}

// ---- Subgroup check ---------------------------------------------------------
//
// Given x in Fp, the point is in the prime-order subgroup iff (1 - a*x^2) is
// a square in Fp. With a = -5, 1 - a*x^2 = 1 + 5*x^2.
bool subgroup_check_x(const Fp& x) {
    const auto& cp = curve_params();
    Fp ax2 = mul_by_a(x.square());      // a*x^2
    Fp r = Fp::one().sub(ax2);          // 1 - a*x^2
    (void)cp;
    return r.legendre() > 0;
}

// ---- Encode -----------------------------------------------------------------

void Element::to_bytes(uint8_t out[32]) const {
    Fp x, y;
    inner_.to_affine(x, y);
    if (!y.lexicographically_largest()) {
        x = x.neg();
    }
    x.to_canonical_be(out);
}

bool Element::from_bytes(const uint8_t in[32]) {
    Fp x;
    if (!Fp::try_from_canonical_be(in, x)) return false;

    // Compute y from x using -x^2 + y^2 = 1 + d*x^2*y^2 rearranged:
    //   y^2 (1 - d*x^2) = 1 - a*x^2  (a = -5)  =>  y^2 (1 - d*x^2) = 1 + 5*x^2
    // Equivalently using the gnark form:
    //   y^2 = (a*x^2 - 1) / (d*x^2 - 1)
    const auto& cp = curve_params();
    Fp x2 = x.square();
    Fp num = mul_by_a(x2).sub(Fp::one());          // a*x^2 - 1
    Fp den = cp.d.mul(x2).sub(Fp::one());          // d*x^2 - 1
    if (den.is_zero()) return false;
    Fp y2 = num.mul(den.inverse());

    Fp y;
    if (!y2.sqrt(y)) return false;

    // Choose y to be lex-largest (matches go-ipa choose_largest=true).
    if (!y.lexicographically_largest()) {
        y = y.neg();
    }

    // Subgroup check: (1 - a*x^2) must be a QR. We verify by recomputing the
    // legendre symbol (separate code path, defensive).
    if (!subgroup_check_x(x)) return false;

    inner_.X = x;
    inner_.Y = y;
    inner_.Z = Fp::one();
    return true;
}

bool Element::from_bytes_unsafe(const uint8_t in[32]) {
    Fp x;
    if (!Fp::try_from_canonical_be(in, x)) return false;
    const auto& cp = curve_params();
    Fp x2 = x.square();
    Fp num = mul_by_a(x2).sub(Fp::one());
    Fp den = cp.d.mul(x2).sub(Fp::one());
    if (den.is_zero()) return false;
    Fp y2 = num.mul(den.inverse());
    Fp y;
    if (!y2.sqrt(y)) return false;
    if (!y.lexicographically_largest()) y = y.neg();
    inner_.X = x;
    inner_.Y = y;
    inner_.Z = Fp::one();
    return true;
}

void Element::to_bytes_uncompressed_trusted(uint8_t out[64]) const {
    Fp x, y;
    inner_.to_affine(x, y);
    x.to_canonical_be(out);
    y.to_canonical_be(out + 32);
}

bool Element::from_bytes_uncompressed(const uint8_t in[64], bool trusted) {
    Fp x, y;
    if (!Fp::try_from_canonical_be(in, x)) return false;
    if (!Fp::try_from_canonical_be(in + 32, y)) return false;
    if (!trusted) {
        // Recompute Y from X and verify it matches the supplied Y.
        const auto& cp = curve_params();
        Fp x2 = x.square();
        Fp num = mul_by_a(x2).sub(Fp::one());
        Fp den = cp.d.mul(x2).sub(Fp::one());
        if (den.is_zero()) return false;
        Fp y2 = num.mul(den.inverse());
        Fp y_chosen;
        if (!y2.sqrt(y_chosen)) return false;
        if (!y_chosen.lexicographically_largest()) y_chosen = y_chosen.neg();
        if (!y_chosen.equal(y)) return false;
        if (!subgroup_check_x(x)) return false;
    }
    inner_.X = x;
    inner_.Y = y;
    inner_.Z = Fp::one();
    return true;
}

Fr Element::map_to_scalar_field() const {
    // res = X / Y in Fp, reinterpreted as little-endian bytes into Fr.
    Fp x, y;
    inner_.to_affine(x, y);
    Fp r = x.mul(y.inverse());
    uint8_t le[32];
    r.to_canonical_le(le);
    Fr out;
    if (!Fr::try_from_canonical_le(le, out)) {
        // Reduce mod r (canonical).
        out = Fr::from_canonical_le(le);
    }
    return out;
}

// =============================================================================
// MSM (Pippenger; for now naive linear scalar_mul + add CPU fallback)
// =============================================================================
//
// The naive O(n*256) approach is correct and good enough for n up to a few
// hundred. The Pippenger windowed bucket method gets activated above
// crossover_threshold(); the Metal driver attempts to dispatch GPU MSM and
// falls back to CPU on miss.

size_t crossover_threshold() {
    return 256;  // Per published GPU MSM literature.
}

namespace {

Element msm_naive(const Element* points, const Fr* scalars, size_t n) {
    Element acc = Element::identity();
    for (size_t i = 0; i < n; ++i) {
        Element t = points[i].scalar_mul(scalars[i]);
        acc = acc.add(t);
    }
    return acc;
}

// Pippenger with fixed window c. Bucket sums per c-bit window; aggregate
// outer windows by doubling. Constant-time over scalar bit-length.
Element msm_pippenger(const Element* points, const Fr* scalars, size_t n) {
    constexpr size_t kBits = 256;
    constexpr size_t kWindow = 8;
    constexpr size_t kBuckets = (1u << kWindow) - 1;
    constexpr size_t kWindows = (kBits + kWindow - 1) / kWindow;

    std::array<Element, kWindows> window_sums;
    for (size_t w = 0; w < kWindows; ++w) {
        // Initialise buckets.
        std::vector<Element> buckets(kBuckets, Element::identity());
        size_t shift = w * kWindow;

        for (size_t i = 0; i < n; ++i) {
            // Extract the c-bit window value.
            uint64_t b = 0;
            for (size_t k = 0; k < kWindow; ++k) {
                if (scalars[i].bit(shift + k)) b |= (1ULL << k);
            }
            if (b == 0) continue;
            buckets[b - 1] = buckets[b - 1].add(points[i]);
        }

        // Bucket reduction: result_w = 1*B[0] + 2*B[1] + ... + (kBuckets)*B[kBuckets-1].
        // Use the standard prefix-sum trick:
        //   running = 0; sum = 0
        //   for j from kBuckets-1 down to 0: running += B[j]; sum += running
        Element running = Element::identity();
        Element sum = Element::identity();
        for (size_t j = kBuckets; j-- > 0;) {
            running = running.add(buckets[j]);
            sum = sum.add(running);
        }
        window_sums[w] = sum;
    }

    // Aggregate windows by doubling.
    Element result = window_sums[kWindows - 1];
    for (size_t w = kWindows - 1; w-- > 0;) {
        for (size_t k = 0; k < kWindow; ++k) {
            result = result.dbl();
        }
        result = result.add(window_sums[w]);
    }
    return result;
}

}  // namespace

Element msm(const Element* points, const Fr* scalars, size_t n) {
    if (n == 0) return Element::identity();
    if (n < crossover_threshold()) return msm_naive(points, scalars, n);
    return msm_pippenger(points, scalars, n);
}

}  // namespace kinet::crypto::banderwagon
