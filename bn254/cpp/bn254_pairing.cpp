// First-party optimal-ate pairing for bn254. See bn254_pairing.hpp for the
// public surface; this file holds the Miller loop, the Frobenius operators,
// the cyclotomic square (Granger-Scott), the addition-chain Expt, and the
// final exponentiation.

#include "bn254_pairing.hpp"

#include <vector>

namespace kinet::crypto::bn254 {

// =============================================================================
// 6x + 2 = 29793968203157093288, NAF (little-endian, 65 entries)
// =============================================================================
//
// Generated once via gnark-crypto's ecc.NafDecomposition. The leading entry is
// at index 64 (most significant), entry 0 is the LSB.
//
// We store the NAF as int8_t[65]; values are in {-1, 0, 1}. The Miller loop
// indexing matches gnark-crypto's: i ranges from len-3 down to 0 in the main
// loop, with the special tail at i=63 and the 6x+2 + Frobenius corrections
// after.
static constexpr int8_t kLoopCounter[65] = {
    0, 0, 0, 1, 0, 1, 0, -1, 0, 0, 1, -1, 0, 0, 1, 0,
    0, 1, 1, 0, -1, 0, 0, 1, 0, -1, 0, 0, 0, 0, 1, 1,
    1, 0, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, 1,
    1, 0, 0, -1, 0, 0, 0, 1, 1, 0, -1, 0, 0, 1, 0, 1,
    1
};

// =============================================================================
// Frobenius coefficients (Montgomery limbs, copied from gnark-crypto v0.19.2
// ecc/bn254/internal/fptower/frobenius.go init()). Each value is a constant of
// the field; copying the limb representation is identical to writing the
// decimal value and converting at runtime, but avoids a startup hop.
// =============================================================================

namespace {

constexpr U256 mk(u64 a, u64 b, u64 c, u64 d) noexcept { return U256{a, b, c, d}; }

// nonRes1Pow1to5[0..4]
constexpr Fp2 kNR1P1{
    mk(12653890742059813127ULL, 14585784200204367754ULL,
       1278438861261381767ULL,  212598772761311868ULL),
    mk(11683091849979440498ULL, 14992204589386555739ULL,
       15866167890766973222ULL, 1200023580730561873ULL)
};
constexpr Fp2 kNR1P2{
    mk(13075984984163199792ULL, 3782902503040509012ULL,
       8791150885551868305ULL,  1825854335138010348ULL),
    mk(7963664994991228759ULL,  12257807996192067905ULL,
       13179524609921305146ULL, 2767831111890561987ULL)
};
constexpr Fp2 kNR1P3{
    mk(16482010305593259561ULL, 13488546290961988299ULL,
       3578621962720924518ULL,  2681173117283399901ULL),
    mk(11661927080404088775ULL, 553939530661941723ULL,
       7860678177968807019ULL,  3208568454732775116ULL)
};
constexpr Fp2 kNR1P4{
    mk(8314163329781907090ULL,  11942187022798819835ULL,
       11282677263046157209ULL, 1576150870752482284ULL),
    mk(6763840483288992073ULL,  7118829427391486816ULL,
       4016233444936635065ULL,  2630958277570195709ULL)
};
constexpr Fp2 kNR1P5{
    mk(14515217250696892391ULL, 16303087968080972555ULL,
       3656613296917993960ULL,  1345095164996126785ULL),
    mk(957117326806663081ULL,   367382125163301975ULL,
       15253872307375509749ULL, 3396254757538665050ULL)
};

// nonRes2 (these are pure Fp scalars, applied to both A0 and A1 by gnark)
constexpr U256 kNR2P1 = mk(14595462726357228530ULL, 17349508522658994025ULL,
                           1017833795229664280ULL,  299787779797702374ULL);
constexpr U256 kNR2P2 = mk(3697675806616062876ULL,  9065277094688085689ULL,
                           6918009208039626314ULL,  2775033306905974752ULL);
constexpr U256 kNR2P3 = mk(7548957153968385962ULL,  10162512645738643279ULL,
                           5900175412809962033ULL,  2475245527108272378ULL);
constexpr U256 kNR2P4 = mk(8183898218631979349ULL,  12014359695528440611ULL,
                           12263358156045030468ULL, 3187210487005268291ULL);
constexpr U256 kNR2P5 = mk(634941064663593387ULL,   1851847049789797332ULL,
                           6363182743235068435ULL,  711964959896995913ULL);

// nonRes3Pow1To5[0..4]
constexpr Fp2 kNR3P1{
    mk(3914496794763385213ULL,  790120733010914719ULL,
       7322192392869644725ULL,  581366264293887267ULL),
    mk(12817045492518885689ULL, 4440270538777280383ULL,
       11178533038884588256ULL, 2767537931541304486ULL)
};
constexpr Fp2 kNR3P2{
    mk(14532872967180610477ULL, 12903226530429559474ULL,
       1868623743233345524ULL,  2316889217940299650ULL),
    mk(12447993766991532972ULL, 4121872836076202828ULL,
       7630813605053367399ULL,  740282956577754197ULL)
};
constexpr Fp2 kNR3P3{
    mk(6297350639395948318ULL,  15875321927225446337ULL,
       9702569988553770230ULL,  805825149519570764ULL),
    mk(11117433864585119104ULL, 10363184613815941297ULL,
       5420513773305887730ULL,  278429812070195549ULL)
};
constexpr Fp2 kNR3P4{
    mk(4938922280314430175ULL,  13823286637238282975ULL,
       15589480384090068090ULL, 481952561930628184ULL),
    mk(3105754162722846417ULL,  11647802298615474591ULL,
       13057042392041828081ULL, 1660844386505564338ULL)
};
constexpr Fp2 kNR3P5{
    mk(16193900971494954399ULL, 13995139551301264911ULL,
       9239559758168096094ULL,  1571199014989505406ULL),
    mk(3254114329011132839ULL,  11171599147282597747ULL,
       10965492220518093659ULL, 2657556514797346915ULL)
};

inline Fp2 mul_nr1_p1(const Fp2& x) noexcept { return fp2_mul(x, kNR1P1); }
inline Fp2 mul_nr1_p2(const Fp2& x) noexcept { return fp2_mul(x, kNR1P2); }
inline Fp2 mul_nr1_p3(const Fp2& x) noexcept { return fp2_mul(x, kNR1P3); }
inline Fp2 mul_nr1_p4(const Fp2& x) noexcept { return fp2_mul(x, kNR1P4); }
inline Fp2 mul_nr1_p5(const Fp2& x) noexcept { return fp2_mul(x, kNR1P5); }

inline Fp2 mul_nr2_p1(const Fp2& x) noexcept {
    return Fp2{fp_mul(x.a0, kNR2P1), fp_mul(x.a1, kNR2P1)};
}
inline Fp2 mul_nr2_p2(const Fp2& x) noexcept {
    return Fp2{fp_mul(x.a0, kNR2P2), fp_mul(x.a1, kNR2P2)};
}
inline Fp2 mul_nr2_p3(const Fp2& x) noexcept {
    return Fp2{fp_mul(x.a0, kNR2P3), fp_mul(x.a1, kNR2P3)};
}
inline Fp2 mul_nr2_p4(const Fp2& x) noexcept {
    return Fp2{fp_mul(x.a0, kNR2P4), fp_mul(x.a1, kNR2P4)};
}
inline Fp2 mul_nr2_p5(const Fp2& x) noexcept {
    return Fp2{fp_mul(x.a0, kNR2P5), fp_mul(x.a1, kNR2P5)};
}

inline Fp2 mul_nr3_p1(const Fp2& x) noexcept { return fp2_mul(x, kNR3P1); }
inline Fp2 mul_nr3_p2(const Fp2& x) noexcept { return fp2_mul(x, kNR3P2); }
inline Fp2 mul_nr3_p3(const Fp2& x) noexcept { return fp2_mul(x, kNR3P3); }
inline Fp2 mul_nr3_p4(const Fp2& x) noexcept { return fp2_mul(x, kNR3P4); }
inline Fp2 mul_nr3_p5(const Fp2& x) noexcept { return fp2_mul(x, kNR3P5); }

// =============================================================================
// Frobenius / Frobenius^2 / Frobenius^3 on Fp12 (Algorithms 28-30 from
// eprint 2010/354).
// =============================================================================

inline Fp12 frobenius(const Fp12& x) noexcept {
    Fp2 t0 = fp2_conjugate(x.c0.b0);
    Fp2 t1 = fp2_conjugate(x.c0.b1);
    Fp2 t2 = fp2_conjugate(x.c0.b2);
    Fp2 t3 = fp2_conjugate(x.c1.b0);
    Fp2 t4 = fp2_conjugate(x.c1.b1);
    Fp2 t5 = fp2_conjugate(x.c1.b2);

    t1 = mul_nr1_p2(t1);
    t2 = mul_nr1_p4(t2);
    t3 = mul_nr1_p1(t3);
    t4 = mul_nr1_p3(t4);
    t5 = mul_nr1_p5(t5);

    Fp12 z;
    z.c0.b0 = t0; z.c0.b1 = t1; z.c0.b2 = t2;
    z.c1.b0 = t3; z.c1.b1 = t4; z.c1.b2 = t5;
    return z;
}

inline Fp12 frobenius_sq(const Fp12& x) noexcept {
    Fp12 z;
    z.c0.b0 = x.c0.b0;
    z.c0.b1 = mul_nr2_p2(x.c0.b1);
    z.c0.b2 = mul_nr2_p4(x.c0.b2);
    z.c1.b0 = mul_nr2_p1(x.c1.b0);
    z.c1.b1 = mul_nr2_p3(x.c1.b1);
    z.c1.b2 = mul_nr2_p5(x.c1.b2);
    return z;
}

inline Fp12 frobenius_cube(const Fp12& x) noexcept {
    Fp2 t0 = fp2_conjugate(x.c0.b0);
    Fp2 t1 = fp2_conjugate(x.c0.b1);
    Fp2 t2 = fp2_conjugate(x.c0.b2);
    Fp2 t3 = fp2_conjugate(x.c1.b0);
    Fp2 t4 = fp2_conjugate(x.c1.b1);
    Fp2 t5 = fp2_conjugate(x.c1.b2);

    t1 = mul_nr3_p2(t1);
    t2 = mul_nr3_p4(t2);
    t3 = mul_nr3_p1(t3);
    t4 = mul_nr3_p3(t4);
    t5 = mul_nr3_p5(t5);

    Fp12 z;
    z.c0.b0 = t0; z.c0.b1 = t1; z.c0.b2 = t2;
    z.c1.b0 = t3; z.c1.b1 = t4; z.c1.b2 = t5;
    return z;
}

}  // namespace (close anonymous to expose cyclotomic_sqr publicly)

// =============================================================================
// Granger-Scott cyclotomic squaring (eprint 2009/565 §3.2). Equivalent to
// gnark-crypto's CyclotomicSquare. Public so the GPU determinism harness can
// invoke it as the CPU oracle.
// =============================================================================

Fp12 cyclotomic_sqr(const Fp12& x) noexcept {
    Fp2 t0 = fp2_sqr(x.c1.b1);
    Fp2 t1 = fp2_sqr(x.c0.b0);
    Fp2 t6 = fp2_sub(fp2_sub(fp2_sqr(fp2_add(x.c1.b1, x.c0.b0)), t0), t1);
    Fp2 t2 = fp2_sqr(x.c0.b2);
    Fp2 t3 = fp2_sqr(x.c1.b0);
    Fp2 t7 = fp2_sub(fp2_sub(fp2_sqr(fp2_add(x.c0.b2, x.c1.b0)), t2), t3);
    Fp2 t4 = fp2_sqr(x.c1.b2);
    Fp2 t5 = fp2_sqr(x.c0.b1);
    Fp2 t8 = fp2_sub(fp2_sub(fp2_sqr(fp2_add(x.c1.b2, x.c0.b1)), t4), t5);
    t8 = fp2_mul_by_nonres(t8);

    t0 = fp2_add(fp2_mul_by_nonres(t0), t1);
    t2 = fp2_add(fp2_mul_by_nonres(t2), t3);
    t4 = fp2_add(fp2_mul_by_nonres(t4), t5);

    Fp12 z;
    z.c0.b0 = fp2_add(fp2_double(fp2_sub(t0, x.c0.b0)), t0);
    z.c0.b1 = fp2_add(fp2_double(fp2_sub(t2, x.c0.b1)), t2);
    z.c0.b2 = fp2_add(fp2_double(fp2_sub(t4, x.c0.b2)), t4);

    z.c1.b0 = fp2_add(fp2_double(fp2_add(t8, x.c1.b0)), t8);
    z.c1.b1 = fp2_add(fp2_double(fp2_add(t6, x.c1.b1)), t6);
    z.c1.b2 = fp2_add(fp2_double(fp2_add(t7, x.c1.b2)), t7);
    return z;
}

inline Fp12 cyclotomic_n_sqr(Fp12 z, int n) noexcept {
    for (int i = 0; i < n; ++i) z = cyclotomic_sqr(z);
    return z;
}

namespace {  // re-open anonymous namespace for the rest of the file

// =============================================================================
// Expt: x^t with t = 4965661367192848881 (the curve seed). Uses the
// addition chain from gnark-crypto e12_pairing.go (62 squares + 17 muls).
// =============================================================================

inline Fp12 expt(const Fp12& x) noexcept {
    Fp12 t3 = cyclotomic_sqr(x);                   // x^2
    Fp12 t5 = cyclotomic_sqr(t3);                  // x^4
    Fp12 result = cyclotomic_sqr(t5);              // x^8
    Fp12 t0 = cyclotomic_sqr(result);              // x^16
    Fp12 t2 = fp12_mul(x, t0);                     // x^17
    t0 = fp12_mul(t3, t2);                         // x^19
    Fp12 t1 = fp12_mul(x, t0);                     // x^20
    Fp12 t4 = fp12_mul(result, t2);                // x^25
    Fp12 t6 = cyclotomic_sqr(t2);                  // x^34
    t1 = fp12_mul(t0, t1);                         // x^39
    t0 = fp12_mul(t3, t1);                         // x^41

    t6 = cyclotomic_n_sqr(t6, 6);                  // x^(34<<6) = x^0x880
    t5 = fp12_mul(t5, t6);                         // x^0x884
    t5 = fp12_mul(t4, t5);                         // x^0x89d

    t5 = cyclotomic_n_sqr(t5, 7);                  // x^0x44e80
    t4 = fp12_mul(t4, t5);                         // x^0x44e99

    t4 = cyclotomic_n_sqr(t4, 8);                  // x^0x44e9900
    t4 = fp12_mul(t0, t4);                         // x^0x44e9929
    t3 = fp12_mul(t3, t4);                         // x^0x44e992b

    t3 = cyclotomic_n_sqr(t3, 6);                  // x^0x113a64ac0
    t2 = fp12_mul(t2, t3);                         // x^0x113a64ad1

    t2 = cyclotomic_n_sqr(t2, 8);                  // x^0x113a64ad100
    t2 = fp12_mul(t0, t2);                         // x^0x113a64ad129

    t2 = cyclotomic_n_sqr(t2, 6);                  // x^0x44e992b44a40
    t2 = fp12_mul(t0, t2);                         // x^0x44e992b44a69

    t2 = cyclotomic_n_sqr(t2, 10);                 // x^0x113a64ad129a400
    t1 = fp12_mul(t1, t2);                         // x^0x113a64ad129a427

    t1 = cyclotomic_n_sqr(t1, 6);                  // x^0x44e992b44a6909c0
    t0 = fp12_mul(t0, t1);                         // x^0x44e992b44a6909e9
    return fp12_mul(result, t0);                   // x^0x44e992b44a6909f1 = x^t
}

// =============================================================================
// Miller-loop projective G2 point and line evaluations. Layout exactly as
// gnark-crypto's g2Proj { x, y, z } in homogeneous projective coords.
// =============================================================================

struct G2Proj {
    Fp2 x;
    Fp2 y;
    Fp2 z;
};

inline G2Proj g2_to_proj(const G2Affine& a) noexcept {
    G2Proj p;
    p.x = a.x; p.y = a.y; p.z = fp2_one();
    return p;
}

struct LineEvaluation {
    Fp2 r0;
    Fp2 r1;
    Fp2 r2;
};

inline Fp2 fp2_halve(const Fp2& x) noexcept {
    // (x.a0/2 + x.a1*u/2) -- x>>1 on each component if even, else add p first.
    auto half = [](const U256& v) -> U256 {
        U256 r = v;
        if (r.limbs[0] & 1ULL) {
            // r += P
            u64 c;
            r = add_256(r, P, c);
            // shift right by 1, importing the high bit from c
            for (int i = 0; i < 3; ++i)
                r.limbs[i] = (r.limbs[i] >> 1) | (r.limbs[i+1] << 63);
            r.limbs[3] = (r.limbs[3] >> 1) | ((u64)c << 63);
        } else {
            for (int i = 0; i < 3; ++i)
                r.limbs[i] = (r.limbs[i] >> 1) | (r.limbs[i+1] << 63);
            r.limbs[3] = r.limbs[3] >> 1;
        }
        return r;
    };
    return Fp2{half(x.a0), half(x.a1)};
}

inline Fp2 mul_b_twist(const Fp2& x) noexcept {
    // b' = 3 / (9 + u). This MulBybTwistCurveCoeff matches gnark-crypto.
    Fp2 res = fp2_mul_by_nonres_inv(x);
    return fp2_add(fp2_double(res), res);
}

// doubleStep: project line tangent at p; updates p in place to 2p.
inline void g2_double_step(G2Proj& p, LineEvaluation& ev) noexcept {
    Fp2 A = fp2_mul(p.x, p.y);
    A = fp2_halve(A);
    Fp2 B = fp2_sqr(p.y);
    Fp2 C = fp2_sqr(p.z);
    Fp2 D = fp2_double(C);
    D = fp2_add(D, C);
    Fp2 E = mul_b_twist(D);
    Fp2 F = fp2_double(E);
    F = fp2_add(F, E);
    Fp2 G = fp2_add(B, F);
    G = fp2_halve(G);
    Fp2 H = fp2_add(p.y, p.z);
    H = fp2_sqr(H);
    Fp2 t1 = fp2_add(B, C);
    H = fp2_sub(H, t1);
    Fp2 I = fp2_sub(E, B);
    Fp2 J = fp2_sqr(p.x);
    Fp2 EE = fp2_sqr(E);
    Fp2 K = fp2_double(EE);
    K = fp2_add(K, EE);

    p.x = fp2_sub(B, F);
    p.x = fp2_mul(p.x, A);
    p.y = fp2_sqr(G);
    p.y = fp2_sub(p.y, K);
    p.z = fp2_mul(B, H);

    ev.r0 = fp2_neg(H);
    ev.r1 = fp2_double(J);
    ev.r1 = fp2_add(ev.r1, J);
    ev.r2 = I;
}

// addMixedStep: line through p and a (in affine); updates p to p+a.
inline void g2_add_mixed_step(G2Proj& p, LineEvaluation& ev, const G2Affine& a) noexcept {
    Fp2 Y2Z1 = fp2_mul(a.y, p.z);
    Fp2 O = fp2_sub(p.y, Y2Z1);
    Fp2 X2Z1 = fp2_mul(a.x, p.z);
    Fp2 L = fp2_sub(p.x, X2Z1);
    Fp2 C = fp2_sqr(O);
    Fp2 D = fp2_sqr(L);
    Fp2 E = fp2_mul(L, D);
    Fp2 F = fp2_mul(p.z, C);
    Fp2 G = fp2_mul(p.x, D);
    Fp2 t0 = fp2_double(G);
    Fp2 H = fp2_add(E, F);
    H = fp2_sub(H, t0);
    Fp2 t1 = fp2_mul(p.y, E);

    p.x = fp2_mul(L, H);
    p.y = fp2_sub(G, H);
    p.y = fp2_mul(p.y, O);
    p.y = fp2_sub(p.y, t1);
    p.z = fp2_mul(E, p.z);

    Fp2 t2 = fp2_mul(L, a.y);
    Fp2 J = fp2_mul(a.x, O);
    J = fp2_sub(J, t2);

    ev.r0 = L;
    ev.r1 = fp2_neg(O);
    ev.r2 = J;
}

// lineCompute: line through p and a, without updating p (avoids p+a).
inline void g2_line_compute(const G2Proj& p, LineEvaluation& ev, const G2Affine& a) noexcept {
    Fp2 Y2Z1 = fp2_mul(a.y, p.z);
    Fp2 O = fp2_sub(p.y, Y2Z1);
    Fp2 X2Z1 = fp2_mul(a.x, p.z);
    Fp2 L = fp2_sub(p.x, X2Z1);
    Fp2 t2 = fp2_mul(L, a.y);
    Fp2 J = fp2_mul(a.x, O);
    J = fp2_sub(J, t2);

    ev.r0 = L;
    ev.r1 = fp2_neg(O);
    ev.r2 = J;
}

inline G2Affine g2_neg(const G2Affine& a) noexcept {
    G2Affine r;
    r.x = a.x;
    r.y = fp2_neg(a.y);
    r.infinity = a.infinity;
    return r;
}

}  // namespace

// =============================================================================
// Multi-Miller loop and final exponentiation.
// =============================================================================

Fp12 multi_miller_loop(const G1Affine* P, const G2Affine* Q, std::size_t n) noexcept {
    // Filter infinity points.
    std::vector<G1Affine> p;
    std::vector<G2Affine> q;
    p.reserve(n);
    q.reserve(n);
    for (std::size_t k = 0; k < n; ++k) {
        if (P[k].infinity || Q[k].infinity) continue;
        p.push_back(P[k]);
        q.push_back(Q[k]);
    }
    const std::size_t m = p.size();
    if (m == 0) return fp12_one();

    // Projective Q + cached -Q for the NAF case.
    std::vector<G2Proj> qProj(m);
    std::vector<G2Affine> qNeg(m);
    for (std::size_t k = 0; k < m; ++k) {
        qProj[k] = g2_to_proj(q[k]);
        qNeg[k] = g2_neg(q[k]);
    }

    Fp12 result = fp12_one();
    LineEvaluation l1{}, l2{};
    Fp12Sparse5 prodLines{};

    // i = 64 (LoopCounter[64] = 0) — we skip the leading square because
    // result is still 1 and 1*1 = 1.
    if (m >= 1) {
        // qProj[0] <- 2 qProj[0], with l1 the tangent line at 2 qProj[0].
        g2_double_step(qProj[0], l1);
        // line evaluation at P[0] (assign): result = (l1.r0*y, 0, 0, l1.r1*x, l1.r2, 0)
        result.c0.b0 = fp2_mul_by_fp(l1.r0, p[0].y);
        result.c1.b0 = fp2_mul_by_fp(l1.r1, p[0].x);
        result.c1.b1 = l1.r2;
    }
    if (m >= 2) {
        g2_double_step(qProj[1], l1);
        l1.r0 = fp2_mul_by_fp(l1.r0, p[1].y);
        l1.r1 = fp2_mul_by_fp(l1.r1, p[1].x);
        prodLines = fp12_mul_034_by_034(l1.r0, l1.r1, l1.r2,
                                        result.c0.b0, result.c1.b0, result.c1.b1);
        result.c0.b0 = prodLines.v00;
        result.c0.b1 = prodLines.v01;
        result.c0.b2 = prodLines.v02;
        result.c1.b0 = prodLines.v10;
        result.c1.b1 = prodLines.v11;
    }
    for (std::size_t k = 2; k < m; ++k) {
        g2_double_step(qProj[k], l1);
        l1.r0 = fp2_mul_by_fp(l1.r0, p[k].y);
        l1.r1 = fp2_mul_by_fp(l1.r1, p[k].x);
        result = fp12_mul_by_034(result, l1.r0, l1.r1, l1.r2);
    }

    // i = 63 — LoopCounter[63] = -1, equivalent to qProj += 2Q -> 3Q via a
    // doubleStep + addMixedStep merged into "lineCompute(qProj, -Q) and
    // addMixedStep(qProj, Q)".
    result = fp12_sqr(result);
    for (std::size_t k = 0; k < m; ++k) {
        g2_line_compute(qProj[k], l2, qNeg[k]);
        l2.r0 = fp2_mul_by_fp(l2.r0, p[k].y);
        l2.r1 = fp2_mul_by_fp(l2.r1, p[k].x);
        g2_add_mixed_step(qProj[k], l1, q[k]);
        l1.r0 = fp2_mul_by_fp(l1.r0, p[k].y);
        l1.r1 = fp2_mul_by_fp(l1.r1, p[k].x);
        prodLines = fp12_mul_034_by_034(l1.r0, l1.r1, l1.r2, l2.r0, l2.r1, l2.r2);
        result = fp12_mul_by_01234(result, prodLines);
    }

    // i = 62 down to 0.
    constexpr int kLen = sizeof(kLoopCounter) / sizeof(kLoopCounter[0]);
    for (int i = kLen - 4; i >= 0; --i) {
        result = fp12_sqr(result);
        for (std::size_t k = 0; k < m; ++k) {
            g2_double_step(qProj[k], l1);
            l1.r0 = fp2_mul_by_fp(l1.r0, p[k].y);
            l1.r1 = fp2_mul_by_fp(l1.r1, p[k].x);

            const int8_t lc = kLoopCounter[i];
            if (lc == 1) {
                g2_add_mixed_step(qProj[k], l2, q[k]);
                l2.r0 = fp2_mul_by_fp(l2.r0, p[k].y);
                l2.r1 = fp2_mul_by_fp(l2.r1, p[k].x);
                prodLines = fp12_mul_034_by_034(l1.r0, l1.r1, l1.r2, l2.r0, l2.r1, l2.r2);
                result = fp12_mul_by_01234(result, prodLines);
            } else if (lc == -1) {
                g2_add_mixed_step(qProj[k], l2, qNeg[k]);
                l2.r0 = fp2_mul_by_fp(l2.r0, p[k].y);
                l2.r1 = fp2_mul_by_fp(l2.r1, p[k].x);
                prodLines = fp12_mul_034_by_034(l1.r0, l1.r1, l1.r2, l2.r0, l2.r1, l2.r2);
                result = fp12_mul_by_01234(result, prodLines);
            } else {
                result = fp12_mul_by_034(result, l1.r0, l1.r1, l1.r2);
            }
        }
    }

    // Final 6x+2 + Frobenius corrections:
    //   Q1 = pi(Q):    X = conj(Q.X) * (9+u)^((p-1)/3)         (NR1Power2 on Fp2)
    //                  Y = conj(Q.Y) * (9+u)^((p-1)/2)         (NR1Power3 on Fp2)
    //   Q2 = -pi^2(Q): X = Q.X * (9+u)^(2*(p^2-1)/6)            (NR2Power2)
    //                  Y = -Q.Y * (9+u)^(3*(p^2-1)/6)           (NR2Power3, then negate)
    for (std::size_t k = 0; k < m; ++k) {
        G2Affine Q1, Q2;
        Q1.x = mul_nr1_p2(fp2_conjugate(q[k].x));
        Q1.y = mul_nr1_p3(fp2_conjugate(q[k].y));
        Q1.infinity = false;
        Q2.x = mul_nr2_p2(q[k].x);
        Q2.y = fp2_neg(mul_nr2_p3(q[k].y));
        Q2.infinity = false;

        g2_add_mixed_step(qProj[k], l2, Q1);
        l2.r0 = fp2_mul_by_fp(l2.r0, p[k].y);
        l2.r1 = fp2_mul_by_fp(l2.r1, p[k].x);

        g2_line_compute(qProj[k], l1, Q2);
        l1.r0 = fp2_mul_by_fp(l1.r0, p[k].y);
        l1.r1 = fp2_mul_by_fp(l1.r1, p[k].x);

        prodLines = fp12_mul_034_by_034(l1.r0, l1.r1, l1.r2, l2.r0, l2.r1, l2.r2);
        result = fp12_mul_by_01234(result, prodLines);
    }

    return result;
}

Fp12 final_exponentiation(const Fp12& z) noexcept {
    // Easy part: f -> f^((p^6 - 1)(p^2 + 1))
    //   t0 = conjugate(f); f = inv(f); t0 *= f; f = frob_sq(t0); f *= t0
    Fp12 result = z;
    Fp12 t0 = fp12_conjugate(result);
    result = fp12_inv(result);
    t0 = fp12_mul(t0, result);
    result = frobenius_sq(t0);
    result = fp12_mul(result, t0);

    // If easy part already lands at 1, the hard part below would still
    // produce 1 but waste work. Match gnark's early-exit for parity with
    // the reference oracle.
    if (fp12_is_one(result)) return result;

    // Hard part (Fuentes-Castaneda / Duquesne-Ghammam, eprint 2015/192 alg 6),
    // identical structure to gnark-crypto FinalExponentiation.
    Fp12 t[5];
    t[0] = expt(result);
    t[0] = fp12_conjugate(t[0]);
    t[0] = cyclotomic_sqr(t[0]);
    t[1] = cyclotomic_sqr(t[0]);
    t[1] = fp12_mul(t[0], t[1]);
    t[2] = expt(t[1]);
    t[2] = fp12_conjugate(t[2]);
    t[3] = fp12_conjugate(t[1]);
    t[1] = fp12_mul(t[2], t[3]);
    t[3] = cyclotomic_sqr(t[2]);
    t[4] = expt(t[3]);
    t[4] = fp12_mul(t[1], t[4]);
    t[3] = fp12_mul(t[0], t[4]);
    t[0] = fp12_mul(t[2], t[4]);
    t[0] = fp12_mul(result, t[0]);
    t[2] = frobenius(t[3]);
    t[0] = fp12_mul(t[2], t[0]);
    t[2] = frobenius_sq(t[4]);
    t[0] = fp12_mul(t[2], t[0]);
    t[2] = fp12_conjugate(result);
    t[2] = fp12_mul(t[2], t[3]);
    t[2] = frobenius_cube(t[2]);
    t[0] = fp12_mul(t[2], t[0]);

    return t[0];
}

Fp12 multi_pair(const G1Affine* P, const G2Affine* Q, std::size_t n) noexcept {
    return final_exponentiation(multi_miller_loop(P, Q, n));
}

bool multi_pairing_check(const G1Affine* P, const G2Affine* Q, std::size_t n) noexcept {
    return fp12_is_one(multi_pair(P, Q, n));
}

Fp12 cyclotomic_sqr_public(const Fp12& x) noexcept {
    return cyclotomic_sqr(x);
}

}  // namespace kinet::crypto::bn254
