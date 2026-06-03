// BLS12-381 optimal-ate Miller loop on Metal.
//
// Inputs:
//   Q in G2  (P2Aff = 192 bytes,  blst_p2_affine layout)
//   P in G1  (P1Aff =  96 bytes,  blst_p1_affine layout = 2*48-byte Fp)
// Output:
//   f in Fp12 (576 bytes), the value of  e_pre(P, Q)  = product of line evals,
//   matching blst_miller_loop  pre-final-exponentiation byte-for-byte.
//
// Algorithm mirrors blst src/pairing.c miller_loop() exactly:
//   1. Px2 = (-2*P.X, 2*P.Y)               (precomputed for line_by_Px2)
//   2. T = Q                                (Jacobian, Z = 1)
//   3. line_dbl(line, T, T) ; line_by_Px2 ; ret = unpack(line)   // first sqr fused
//   4. add_n_dbl(2)  ;  add_n_dbl(3)  ;  add_n_dbl(9)
//      add_n_dbl(32) ;  add_n_dbl(16)
//   5. ret = conjugate(ret)               // x is negative
//
// Loop scalar:  x = -0xd201000000010000
// Counts above (1+2+3+9+32+16 = 63 doublings + 5 add-then-double-runs)
// match the bit pattern of |x| = 0xd201000000010000 minus the leading bit
// already absorbed by step 3.
//
// Line layout — "xy00z0" packed as three Fp2:
//     Line { Fp2 x, y, z }
//   maps into Fp12 a = (a0, a1) where a0 = (x, y, 0) Fp6 and a1 = (0, z, 0) Fp6.
// This matches blst's vec384fp6 line[3] convention used in pairing.c +
// fp12_tower.c::mul_by_xy00z0_fp12.

#include "bls_fp12.metal"

#define BLS_FP2_NO_KERNELS
#define BLS_FP6_NO_KERNELS
#define BLS_FP12_NO_KERNELS
#define BLS_G2_NO_KERNELS
#include "bls_g2.metal"
#undef BLS_G2_NO_KERNELS
#undef BLS_FP12_NO_KERNELS
#undef BLS_FP6_NO_KERNELS
#undef BLS_FP2_NO_KERNELS

struct P1Aff { uint384 X, Y; };

struct Line { Fp2 x, y, z; };

// line_dbl  —  blst pairing.c:78
//   T <- 2*T,  line <- doubling-line at the original T.
// Q is passed by value (snapshot of the input); blst's reference call is
// line_dbl(line, T, T) — Q == T. Taking by value lets us safely overwrite T.
// Not inlined so the Miller loop fits in a single Metal compile unit.
static Line line_dbl(thread P2& T, P2 Q) {
    Fp2 A  = fp2_sqr(Q.X);                  // X1^2
    Fp2 B  = fp2_sqr(Q.Y);                  // Y1^2
    Fp2 ZZ = fp2_sqr(Q.Z);                  // Z1^2
    Fp2 C  = fp2_sqr(B);                    // C = B^2

    Fp2 D = fp2_add(Q.X, B);
    D = fp2_sqr(D);
    D = fp2_sub(D, A);
    D = fp2_sub(D, C);
    D = fp2_add(D, D);                      // D = 2*((X+B)^2 - A - C)

    // E = 3*A
    Fp2 E = fp2_add(A, A);
    E = fp2_add(E, A);

    Fp2 F = fp2_sqr(E);                     // F = E^2

    // line[0]  =  3A + X1   (will be squared+adjusted next)
    Fp2 line0 = fp2_add(E, Q.X);

    Fp2 Tx = fp2_sub(F, D);
    Tx     = fp2_sub(Tx, D);                // X3 = F - 2D

    Fp2 Tz = fp2_add(Q.Y, Q.Z);
    Tz     = fp2_sqr(Tz);
    Tz     = fp2_sub(Tz, B);
    Tz     = fp2_sub(Tz, ZZ);               // Z3 = (Y+Z)^2 - B - ZZ

    // 8*C  for Y3 path
    Fp2 C8 = fp2_add(C, C);
    C8 = fp2_add(C8, C8);
    C8 = fp2_add(C8, C8);                   // 8*C

    Fp2 Ty = fp2_sub(D, Tx);                // D - X3
    Ty     = fp2_mul(Ty, E);                // E*(D-X3)
    Ty     = fp2_sub(Ty, C8);               // Y3 = E*(D-X3) - 8C

    // line evaluation
    line0 = fp2_sqr(line0);
    line0 = fp2_sub(line0, A);
    line0 = fp2_sub(line0, F);              // (3A+X)^2 - X^2 - 9A^2  =  6X^3 - ...
    // 4*B
    Fp2 B4 = fp2_add(B, B);
    B4 = fp2_add(B4, B4);
    line0 = fp2_sub(line0, B4);             // 6*X^3 - 4*Y^2

    Fp2 line1 = fp2_mul(E, ZZ);             // 3*X^2 * Z^2
    Fp2 line2 = fp2_mul(Tz, ZZ);            // Z3 * Z^2

    T.X = Tx; T.Y = Ty; T.Z = Tz;

    Line L; L.x = line0; L.y = line1; L.z = line2;
    return L;
}

// line_add  —  blst pairing.c:14
//   T <- R + Q,  line <- addition-line at R.   (R is Jacobian, Q is affine.)
// R is passed by value so callers can pass `R = T` without aliasing risk
// (blst's reference call is line_add(line, T, T, Q)).
static Line line_add(thread P2& T, P2 R, P2Aff Q) {
    Fp2 Z1Z1 = fp2_sqr(R.Z);                // Z1^2
    Fp2 U2   = fp2_mul(Q.X, Z1Z1);          // U2 = X2*Z1Z1

    Fp2 S2   = fp2_mul(Q.Y, R.Z);
    S2       = fp2_mul(S2, Z1Z1);           // S2 = Y2*Z1*Z1Z1

    Fp2 H = fp2_sub(U2, R.X);               // H = U2 - X1

    Fp2 HH = fp2_sqr(H);
    Fp2 I  = fp2_add(HH, HH);
    I      = fp2_add(I, I);                 // I = 4*HH

    Fp2 J  = fp2_mul(H, I);                 // J = H*I

    Fp2 r  = fp2_sub(S2, R.Y);
    r      = fp2_add(r, r);                 // r = 2*(S2 - Y1)

    Fp2 V  = fp2_mul(R.X, I);               // V = X1*I

    Fp2 Tx = fp2_sqr(r);
    Tx     = fp2_sub(Tx, J);
    Tx     = fp2_sub(Tx, V);
    Tx     = fp2_sub(Tx, V);                // X3 = r^2 - J - 2V

    Fp2 Jy = fp2_mul(J, R.Y);
    Fp2 Ty = fp2_sub(V, Tx);
    Ty     = fp2_mul(Ty, r);
    Ty     = fp2_sub(Ty, Jy);
    Ty     = fp2_sub(Ty, Jy);               // Y3 = r*(V-X3) - 2*Y1*J

    Fp2 Tz = fp2_add(R.Z, H);
    Tz     = fp2_sqr(Tz);
    Tz     = fp2_sub(Tz, Z1Z1);
    Tz     = fp2_sub(Tz, HH);               // Z3 = (Z1+H)^2 - Z1Z1 - HH

    // line evaluation
    Fp2 lineI = fp2_mul(r, Q.X);
    Fp2 lineJ = fp2_mul(Q.Y, Tz);
    lineI     = fp2_sub(lineI, lineJ);
    Fp2 line0 = fp2_add(lineI, lineI);      // 2*(r*X2 - Y2*Z3)

    T.X = Tx; T.Y = Ty; T.Z = Tz;

    Line L; L.x = line0; L.y = r; L.z = Tz;
    return L;
}

// line_by_Px2  —  blst pairing.c:128
//   line[1] *= Px2->X    (where Px2->X = -2*P->X)
//   line[2] *= Px2->Y    (where Px2->Y =  2*P->Y)
// Both line[1], line[2] are Fp2; Px2 components are pure Fp -> componentwise.
inline Line line_by_Px2(Line L, uint384 px_neg2, uint384 py_2) {
    L.y.c0 = fp_mul(L.y.c0, px_neg2);
    L.y.c1 = fp_mul(L.y.c1, px_neg2);
    L.z.c0 = fp_mul(L.z.c0, py_2);
    L.z.c1 = fp_mul(L.z.c1, py_2);
    return L;
}

// fp6_mul_by_xy0  —  blst fp12_tower.c:437   (b = (b0, b1, 0))
inline Fp6 fp6_mul_by_xy0(Fp6 a, Fp2 b0, Fp2 b1) {
    Fp2 t0 = fp2_mul(a.c0, b0);
    Fp2 t1 = fp2_mul(a.c1, b1);

    // r0 = (a2 * b1) * (u+1) + a0*b0
    Fp2 t3 = fp2_mul(a.c2, b1);
    t3     = fp2_mul_by_1_plus_u(t3);

    // r1 = (a0+a1)(b0+b1) - t0 - t1
    Fp2 t4 = fp2_add(a.c0, a.c1);
    Fp2 t5 = fp2_add(b0, b1);
    Fp2 r1 = fp2_mul(t4, t5);
    r1     = fp2_sub(r1, t0);
    r1     = fp2_sub(r1, t1);

    // r2 = a2*b0 + t1
    Fp2 r2 = fp2_mul(a.c2, b0);
    r2     = fp2_add(r2, t1);

    Fp2 r0 = fp2_add(t3, t0);

    Fp6 r; r.c0 = r0; r.c1 = r1; r.c2 = r2; return r;
}

// fp6_mul_by_0y0  —  blst fp12_tower.c:426  (a * (0, b, 0))
inline Fp6 fp6_mul_by_0y0(Fp6 a, Fp2 b) {
    Fp2 t      = fp2_mul(a.c2, b);
    Fp6 r;
    r.c2       = fp2_mul(a.c1, b);
    r.c1       = fp2_mul(a.c0, b);
    r.c0       = fp2_mul_by_1_plus_u(t);
    return r;
}

// mul_by_xy00z0_fp12  —  blst fp12_tower.c:466
//   ret = a * line  where line packs as Fp6 (x, y, 0) for ret[0]
//                                and Fp6 (0, z, 0) for ret[1] (the "00z0" tail).
static Fp12 fp12_mul_by_xy00z0(Fp12 a, Line L) {
    // Build "Fp6 xy00z0" as (L.x, L.y, L.z) in blst layout
    // (note: blst stores xy00z0 as 3 fp2's [x, y, z]; the 0's are virtual).
    // mul_by_xy0_fp6:  t0 = a[0] * (x, y, 0)
    Fp6 t0 = fp6_mul_by_xy0(a.c0, L.x, L.y);

    // mul_by_0y0_fp6: t1 = a[1] * (0, z, 0)   (i.e. multiply by xy00z0[2] = z)
    Fp6 t1 = fp6_mul_by_0y0(a.c1, L.z);

    // ret[1] = (a0 + a1) * (x, y+z, 0) - t0 - t1
    Fp2 b1_alt = fp2_add(L.y, L.z);
    Fp6 sum    = fp6_add(a.c0, a.c1);
    Fp6 r1     = fp6_mul_by_xy0(sum, L.x, b1_alt);
    r1         = fp6_sub(r1, t0);
    r1         = fp6_sub(r1, t1);

    // ret[0] = t0 + t1 * v   (recall v applied to Fp6: (a,b,c) -> (c(u+1), a, b))
    //   t1*v = (t1.c2*(u+1), t1.c0, t1.c1)
    Fp6 t1v;
    t1v.c0 = fp2_mul_by_1_plus_u(t1.c2);
    t1v.c1 = t1.c0;
    t1v.c2 = t1.c1;
    Fp6 r0 = fp6_add(t0, t1v);

    Fp12 r; r.c0 = r0; r.c1 = r1; return r;
}

// Initial step:   ret = unpack( line_dbl( T = Q ) ).
// Mirrors blst pairing.c:166-170. After this, ret has nonzero coords only at
//   ret[0][0] = line.x,  ret[0][1] = line.y,   ret[1][1] = line.z.
inline Fp12 unpack_initial_line(Line L) {
    Fp12 ret;
    ret.c0.c0 = L.x;
    ret.c0.c1 = L.y;
    ret.c0.c2 = fp2_zero();
    ret.c1.c0 = fp2_zero();
    ret.c1.c1 = L.z;
    ret.c1.c2 = fp2_zero();
    return ret;
}

// Note: the doubling counts per Miller-loop phase are
//   1 (initial dbl) + 2 + 3 + 9 + 32 + 16 = 63 doublings,
// matching log2(0xd201000000010000) — the BLS12-381 ate scalar |x|.
// The host driver sequences these phases (see bls_miller_test.mm).
// See pairing.c::miller_loop in blst.

// =============================================================================
// Host-orchestrated Miller loop.
//
// The full Miller loop crashes MetalCompilerService when expressed as a
// single kernel function (XPC connection drops during AIR->GPU lowering on
// this kernel's call tree). Splitting into bounded sub-kernels keeps each
// kernel's compile within the service's budget while still running 100% on
// Metal — no host arithmetic, just dispatch orchestration.
//
// State buffers per workitem:
//   T_state  (288 B)  — POINTonE2 Jacobian (X, Y, Z)
//   ret_state (576 B) — Fp12 accumulator
//   px2      (96 B)   — (-2*P.X, 2*P.Y) packed as Fp2
// =============================================================================

struct MillerIn {
    P2Aff Q;
    P1Aff P;
};

// Storage for an evaluated line (line_by_Px2 already applied).  Three Fp2.
struct LineBuf { Fp2 x, y, z; };

// k_miller_init  —  set T = Q (Z=1), compute Px2, do initial line_dbl,
// store T_state + ret_state + px2 for each workitem.
kernel void k_miller_init(
    device const MillerIn* in     [[buffer(0)]],
    device       P2*       T_buf  [[buffer(1)]],
    device       Fp12*     ret_buf[[buffer(2)]],
    device       Fp2*      px2_buf[[buffer(3)]],
    constant uint& n              [[buffer(4)]],
    uint tid                      [[thread_position_in_grid]])
{
    if (tid >= n) return;

    P2Aff Q = in[tid].Q;
    P1Aff P = in[tid].P;

    uint384 two_px = fp_add(P.X, P.X);
    Fp2 Px2;
    Px2.c0 = fp_neg(two_px);
    Px2.c1 = fp_add(P.Y, P.Y);
    px2_buf[tid] = Px2;

    P2 T;
    T.X = Q.X; T.Y = Q.Y; T.Z = fp2_one();

    Line L0 = line_dbl(T, T);
    L0      = line_by_Px2(L0, Px2.c0, Px2.c1);
    Fp12 ret = unpack_initial_line(L0);

    T_buf[tid]   = T;
    ret_buf[tid] = ret;
}

// k_miller_add_T_and_line  —  T = T + Q ; line = addition-line at original T,
// with line_by_Px2 baked in.
kernel void k_miller_add_T_and_line(
    device const MillerIn* in       [[buffer(0)]],
    device       P2*       T_buf    [[buffer(1)]],
    device       LineBuf*  line_buf [[buffer(2)]],
    device const Fp2*      px2_buf  [[buffer(3)]],
    constant uint& n                [[buffer(4)]],
    uint tid                        [[thread_position_in_grid]])
{
    if (tid >= n) return;
    P2 T    = T_buf[tid];
    Fp2 Px2 = px2_buf[tid];

    Line L = line_add(T, T, in[tid].Q);
    L      = line_by_Px2(L, Px2.c0, Px2.c1);

    T_buf[tid]    = T;
    LineBuf lb;   lb.x = L.x;   lb.y = L.y;   lb.z = L.z;
    line_buf[tid] = lb;
}

// k_miller_dbl_T_and_line  —  T = 2*T ; line = doubling-line at original T,
// with line_by_Px2 baked in. Saves 3 fp2 into line_buf for k_miller_fold_line.
kernel void k_miller_dbl_T_and_line(
    device       P2*       T_buf    [[buffer(0)]],
    device       LineBuf*  line_buf [[buffer(1)]],
    device const Fp2*      px2_buf  [[buffer(2)]],
    constant uint& n                [[buffer(3)]],
    uint tid                        [[thread_position_in_grid]])
{
    if (tid >= n) return;
    P2 T   = T_buf[tid];
    Fp2 Px2 = px2_buf[tid];

    Line Ld = line_dbl(T, T);
    Ld      = line_by_Px2(Ld, Px2.c0, Px2.c1);

    T_buf[tid]      = T;
    LineBuf lb;  lb.x = Ld.x;  lb.y = Ld.y;  lb.z = Ld.z;
    line_buf[tid]   = lb;
}

// k_miller_sqr_ret  —  ret = ret^2 (in place).
kernel void k_miller_sqr_ret(
    device Fp12* ret_buf [[buffer(0)]],
    constant uint& n     [[buffer(1)]],
    uint tid             [[thread_position_in_grid]])
{
    if (tid >= n) return;
    ret_buf[tid] = fp12_sqr(ret_buf[tid]);
}

// k_miller_fold_line  —  ret *= line  (sparse Fp12 multiply).
kernel void k_miller_fold_line(
    device       Fp12*    ret_buf  [[buffer(0)]],
    device const LineBuf* line_buf [[buffer(1)]],
    constant uint& n               [[buffer(2)]],
    uint tid                       [[thread_position_in_grid]])
{
    if (tid >= n) return;
    LineBuf lb = line_buf[tid];
    Line L; L.x = lb.x; L.y = lb.y; L.z = lb.z;
    ret_buf[tid] = fp12_mul_by_xy00z0(ret_buf[tid], L);
}

// k_miller_finalize  —  conjugate ret (account for x being negative).
kernel void k_miller_finalize(
    device       Fp12* ret_buf [[buffer(0)]],
    device       Fp12* out     [[buffer(1)]],
    constant uint& n           [[buffer(2)]],
    uint tid                   [[thread_position_in_grid]])
{
    if (tid >= n) return;
    out[tid] = fp12_conj(ret_buf[tid]);
}
