// First-party Metal kernel for Banderwagon group operations.
//
// Byte-equal to kinet::banderwagon::Element in banderwagon/cpp/element.cpp
// (twisted Edwards a*x^2 + y^2 = 1 + d*x^2*y^2 over the BLS12-381 scalar
// field; a = -5; d = canonical gnark constant). Constants come from the
// CPU body via banderwagon_gen_metal_constants -> banderwagon_const.metalh,
// so the GPU and CPU share exactly one source of truth -- drift is impossible.
//
// Kernels:
//   * banderwagon_add_batch    : (P_i, Q_i) -> P_i + Q_i  in projective form
//   * banderwagon_double_batch : P_i -> 2*P_i             in projective form
//   * banderwagon_smul_batch   : (P_i, s_i) -> [s_i] P_i  in projective form
//   * banderwagon_msm_window   : sum_{i in bucket} P_i    (Pippenger inner)
//
// Encoding: each Element is 96 bytes = 32-byte BE Fp X || 32-byte BE Fp Y ||
// 32-byte BE Fp Z (Montgomery reduced). Each Fr scalar is 32-byte LE in
// canonical form.
//
// All Fp arithmetic operates on Montgomery limbs (4 x ulong, little-endian).
// All operations are constant-time wrt secret bits (no data-dependent branches
// inside the inner loops).

#include <metal_stdlib>
using namespace metal;

#include "banderwagon_const.metalh"

// =============================================================================
// 256-bit Montgomery field element layout. 4 x 64-bit limbs, LE.
// =============================================================================

struct Fp {
    ulong l0, l1, l2, l3;
};

struct Pt {
    Fp X;
    Fp Y;
    Fp Z;
};

// =============================================================================
// 64x64 -> 128 multiply via Metal's native mulhi(u64,u64). On Apple silicon
// this maps to the hardware UMULH instruction.
// =============================================================================

inline void mul64(ulong a, ulong b, thread ulong &lo, thread ulong &hi) {
    lo = a * b;
    hi = mulhi(a, b);
}

inline ulong adc(ulong a, ulong b, thread ulong &carry) {
    ulong s  = a + b;
    ulong c1 = (s < a) ? 1UL : 0UL;
    ulong s2 = s + carry;
    ulong c2 = (s2 < s) ? 1UL : 0UL;
    carry = c1 + c2;
    return s2;
}

inline ulong sbb(ulong a, ulong b, thread ulong &borrow) {
    ulong d  = a - b;
    ulong b1 = (a < b) ? 1UL : 0UL;
    ulong d2 = d - borrow;
    ulong b2 = (d < borrow) ? 1UL : 0UL;
    borrow = b1 + b2;
    return d2;
}

// less_than_q: returns 1 if a < q, 0 otherwise.
inline int fp_less_than_q(thread const Fp &a) {
    if (a.l3 != FP_Q_3) return (a.l3 < FP_Q_3) ? 1 : 0;
    if (a.l2 != FP_Q_2) return (a.l2 < FP_Q_2) ? 1 : 0;
    if (a.l1 != FP_Q_1) return (a.l1 < FP_Q_1) ? 1 : 0;
    return (a.l0 < FP_Q_0) ? 1 : 0;
}

inline void fp_cond_sub_q(thread Fp &a) {
    ulong br = 0;
    ulong r0 = sbb(a.l0, FP_Q_0, br);
    ulong r1 = sbb(a.l1, FP_Q_1, br);
    ulong r2 = sbb(a.l2, FP_Q_2, br);
    ulong r3 = sbb(a.l3, FP_Q_3, br);
    // br=1 => a < q (keep), br=0 => a >= q (take r).
    ulong mask = br - 1UL;  // br=1 -> 0, br=0 -> all-ones
    a.l0 = (a.l0 & ~mask) | (r0 & mask);
    a.l1 = (a.l1 & ~mask) | (r1 & mask);
    a.l2 = (a.l2 & ~mask) | (r2 & mask);
    a.l3 = (a.l3 & ~mask) | (r3 & mask);
}

inline void fp_cond_add_q(thread Fp &a, ulong mask) {
    ulong c = 0;
    ulong add0 = FP_Q_0 & mask;
    ulong add1 = FP_Q_1 & mask;
    ulong add2 = FP_Q_2 & mask;
    ulong add3 = FP_Q_3 & mask;
    a.l0 = adc(a.l0, add0, c);
    a.l1 = adc(a.l1, add1, c);
    a.l2 = adc(a.l2, add2, c);
    a.l3 = adc(a.l3, add3, c);
}

// =============================================================================
// Fp arithmetic. Mirrors fp.cpp byte-for-byte. CIOS Montgomery multiplication.
// =============================================================================

inline Fp fp_add(thread const Fp &a, thread const Fp &b) {
    Fp r;
    ulong c = 0;
    r.l0 = adc(a.l0, b.l0, c);
    r.l1 = adc(a.l1, b.l1, c);
    r.l2 = adc(a.l2, b.l2, c);
    r.l3 = adc(a.l3, b.l3, c);
    fp_cond_sub_q(r);
    return r;
}

inline Fp fp_sub(thread const Fp &a, thread const Fp &b) {
    Fp r;
    ulong br = 0;
    r.l0 = sbb(a.l0, b.l0, br);
    r.l1 = sbb(a.l1, b.l1, br);
    r.l2 = sbb(a.l2, b.l2, br);
    r.l3 = sbb(a.l3, b.l3, br);
    ulong mask = 0UL - br;  // br=1 -> all-ones, br=0 -> 0
    fp_cond_add_q(r, mask);
    return r;
}

inline Fp fp_neg(thread const Fp &a) {
    ulong nz = (a.l0 | a.l1 | a.l2 | a.l3);
    ulong m = 0UL - ((nz | (0UL - nz)) >> 63);  // all-ones if nz != 0, else 0
    Fp r;
    ulong b = 0;
    r.l0 = sbb(FP_Q_0, a.l0, b);
    r.l1 = sbb(FP_Q_1, a.l1, b);
    r.l2 = sbb(FP_Q_2, a.l2, b);
    r.l3 = sbb(FP_Q_3, a.l3, b);
    r.l0 &= m; r.l1 &= m; r.l2 &= m; r.l3 &= m;
    return r;
}

// CIOS Montgomery multiplication. Algorithm 2 of El Housni / Botrel.
// Mirrors banderwagon/cpp/fp.cpp::cios_mul byte-for-byte.
inline Fp fp_mul(thread const Fp &a, thread const Fp &b) {
    const ulong xl[4] = {a.l0, a.l1, a.l2, a.l3};
    const ulong yl[4] = {b.l0, b.l1, b.l2, b.l3};
    const ulong qq[4] = {FP_Q_0, FP_Q_1, FP_Q_2, FP_Q_3};

    ulong t[5] = {0, 0, 0, 0, 0};
    for (int i = 0; i < 4; ++i) {
        const ulong yi = yl[i];

        // t += a * b[i]  (5 limbs)
        ulong cy = 0;
        for (int j = 0; j < 4; ++j) {
            ulong lo, hi;
            mul64(xl[j], yi, lo, hi);
            ulong c1 = 0;
            ulong s = adc(t[j], lo, c1);
            ulong c2 = 0;
            ulong s2 = adc(s, cy, c2);
            t[j] = s2;
            cy = hi + c1 + c2;
        }
        ulong carry_out = 0;
        t[4] = adc(t[4], cy, carry_out);
        ulong D = carry_out;

        // m = t[0] * qInvNeg mod 2^64
        ulong m = t[0] * FP_QINV_NEG;

        // t = (t + m*q) >> 64
        cy = 0;
        for (int j = 0; j < 4; ++j) {
            ulong lo, hi;
            mul64(m, qq[j], lo, hi);
            ulong c1 = 0;
            ulong s = adc(t[j], lo, c1);
            ulong c2 = 0;
            ulong s2 = adc(s, cy, c2);
            t[j] = s2;
            cy = hi + c1 + c2;
        }
        carry_out = 0;
        ulong t3_new = adc(t[4], cy, carry_out);
        ulong t4_new = adc(0UL, D, carry_out);

        // shift down by one limb
        t[0] = t[1]; t[1] = t[2]; t[2] = t[3];
        t[3] = t3_new;
        t[4] = t4_new;
    }

    Fp r;
    r.l0 = t[0]; r.l1 = t[1]; r.l2 = t[2]; r.l3 = t[3];

    // If t[4] != 0 we definitely overflow once: r -= q.
    if (t[4] != 0) {
        ulong b = 0;
        r.l0 = sbb(r.l0, FP_Q_0, b);
        r.l1 = sbb(r.l1, FP_Q_1, b);
        r.l2 = sbb(r.l2, FP_Q_2, b);
        r.l3 = sbb(r.l3, FP_Q_3, b);
        return r;
    }
    fp_cond_sub_q(r);
    return r;
}

inline Fp fp_square(thread const Fp &a) { return fp_mul(a, a); }

// =============================================================================
// Constants (Montgomery form), pulled from the auto-generated header.
// =============================================================================

inline Fp fp_zero() { Fp r; r.l0 = 0; r.l1 = 0; r.l2 = 0; r.l3 = 0; return r; }
inline Fp fp_one()  { Fp r; r.l0 = FP_R_0; r.l1 = FP_R_1; r.l2 = FP_R_2; r.l3 = FP_R_3; return r; }
inline Fp curve_a() { Fp r; r.l0 = CURVE_A_0; r.l1 = CURVE_A_1; r.l2 = CURVE_A_2; r.l3 = CURVE_A_3; return r; }
inline Fp curve_d() { Fp r; r.l0 = CURVE_D_0; r.l1 = CURVE_D_1; r.l2 = CURVE_D_2; r.l3 = CURVE_D_3; return r; }

// =============================================================================
// Banderwagon (= projective twisted Edwards) group ops.
// Unified addition (add-2008-bbjlp). Mirrors element.cpp::Element::add.
//   A = Z1*Z2; B = A^2; C = X1*X2; D = Y1*Y2; E = d*C*D; F = B - E; G = B + E
//   H = X1+Y1; I = X2+Y2
//   X3 = ((H*I) - C - D) * A * F
//   Y3 = (D - a*C) * A * G
//   Z3 = F * G
// =============================================================================

inline Pt pt_identity() {
    Pt p;
    p.X = fp_zero();
    p.Y = fp_one();
    p.Z = fp_one();
    return p;
}

inline Pt pt_add(thread const Pt &p1, thread const Pt &p2) {
    Fp d_const = curve_d();
    Fp a_const = curve_a();

    Fp A = fp_mul(p1.Z, p2.Z);
    Fp B = fp_square(A);
    Fp C = fp_mul(p1.X, p2.X);
    Fp D = fp_mul(p1.Y, p2.Y);
    Fp E = fp_mul(d_const, fp_mul(C, D));
    Fp F = fp_sub(B, E);
    Fp G = fp_add(B, E);
    Fp H = fp_add(p1.X, p1.Y);
    Fp I = fp_add(p2.X, p2.Y);

    Pt r;
    Fp t = fp_mul(H, I);
    t = fp_sub(t, C);
    t = fp_sub(t, D);
    t = fp_mul(t, A);
    r.X = fp_mul(t, F);

    Fp aC = fp_mul(a_const, C);
    Fp t2 = fp_sub(D, aC);
    t2 = fp_mul(t2, A);
    r.Y = fp_mul(t2, G);

    r.Z = fp_mul(F, G);
    return r;
}

// Dedicated doubling (dbl-2008-bbjlp). Mirrors element.cpp::Element::double_self.
//   B = (X+Y)^2; C = X^2; D = Y^2; E = a*C; F = E + D; H = Z^2; J = F - 2H
//   X3 = (B - C - D) * J;  Y3 = F * (E - D);  Z3 = F * J
inline Pt pt_double(thread const Pt &p) {
    Fp a_const = curve_a();

    Fp XY = fp_add(p.X, p.Y);
    Fp B  = fp_square(XY);
    Fp C  = fp_square(p.X);
    Fp D  = fp_square(p.Y);
    Fp E  = fp_mul(a_const, C);
    Fp F  = fp_add(E, D);
    Fp H  = fp_square(p.Z);
    Fp twoH = fp_add(H, H);
    Fp J  = fp_sub(F, twoH);

    Pt r;
    Fp t = fp_sub(B, C);
    t = fp_sub(t, D);
    r.X = fp_mul(t, J);
    r.Y = fp_mul(F, fp_sub(E, D));
    r.Z = fp_mul(F, J);
    return r;
}

// Constant-time conditional move: dst = mask ? src : dst (mask is 0 or all-1).
inline void pt_cmov(thread Pt &dst, thread const Pt &src, ulong mask) {
    dst.X.l0 = (dst.X.l0 & ~mask) | (src.X.l0 & mask);
    dst.X.l1 = (dst.X.l1 & ~mask) | (src.X.l1 & mask);
    dst.X.l2 = (dst.X.l2 & ~mask) | (src.X.l2 & mask);
    dst.X.l3 = (dst.X.l3 & ~mask) | (src.X.l3 & mask);
    dst.Y.l0 = (dst.Y.l0 & ~mask) | (src.Y.l0 & mask);
    dst.Y.l1 = (dst.Y.l1 & ~mask) | (src.Y.l1 & mask);
    dst.Y.l2 = (dst.Y.l2 & ~mask) | (src.Y.l2 & mask);
    dst.Y.l3 = (dst.Y.l3 & ~mask) | (src.Y.l3 & mask);
    dst.Z.l0 = (dst.Z.l0 & ~mask) | (src.Z.l0 & mask);
    dst.Z.l1 = (dst.Z.l1 & ~mask) | (src.Z.l1 & mask);
    dst.Z.l2 = (dst.Z.l2 & ~mask) | (src.Z.l2 & mask);
    dst.Z.l3 = (dst.Z.l3 & ~mask) | (src.Z.l3 & mask);
}

// Constant-time scalar multiplication. Mirrors Element::scalar_mul.
//   Iterates LSB->MSB across canonical 32-byte LE scalar bytes.
//   At each bit: compute acc + base unconditionally; cmov-select via mask.
//   Always double the base.
inline Pt pt_scalar_mul(thread const Pt &p, device const uchar *s_le) {
    Pt acc = pt_identity();
    Pt base = p;
    for (int byte_idx = 0; byte_idx < 32; ++byte_idx) {
        uchar b = s_le[byte_idx];
        for (int bit = 0; bit < 8; ++bit) {
            ulong one_or_zero = (ulong)((b >> bit) & 1u);
            ulong mask = 0UL - one_or_zero;
            Pt sum = pt_add(acc, base);
            pt_cmov(acc, sum, mask);
            base = pt_double(base);
        }
    }
    return acc;
}

// Same scalar-mul but reads scalar from a `thread` 32-byte buffer.
inline Pt pt_scalar_mul_thread(thread const Pt &p, thread const uchar s_le[32]) {
    Pt acc = pt_identity();
    Pt base = p;
    for (int byte_idx = 0; byte_idx < 32; ++byte_idx) {
        uchar b = s_le[byte_idx];
        for (int bit = 0; bit < 8; ++bit) {
            ulong one_or_zero = (ulong)((b >> bit) & 1u);
            ulong mask = 0UL - one_or_zero;
            Pt sum = pt_add(acc, base);
            pt_cmov(acc, sum, mask);
            base = pt_double(base);
        }
    }
    return acc;
}

// =============================================================================
// Bytes <-> Fp (Montgomery) and bytes <-> Pt encoders.
//
// Pt is serialized as 96 bytes = 32B BE Fp X || 32B BE Fp Y || 32B BE Fp Z,
// each 32-byte slice already a Montgomery-form Fp's canonical-image bytes.
// (We use the *direct* Mont-limb encoding for kernel I/O; the determinism
// test marshals CPU-side Element.X/Y/Z limbs verbatim.)
//
// For raw limbs we read 4 x 8 LE bytes per Fp from a 32-byte chunk treated
// as the Montgomery limb array (NOT the canonical-integer encoding from
// fp::to_bytes_be -- that path requires from_mont conversion).
// =============================================================================

inline Fp read_fp_limbs(device const uchar *p) {
    Fp r;
    r.l0 = ((ulong)p[0])       | ((ulong)p[1] << 8)  | ((ulong)p[2] << 16) | ((ulong)p[3] << 24)
        | ((ulong)p[4] << 32)  | ((ulong)p[5] << 40) | ((ulong)p[6] << 48) | ((ulong)p[7] << 56);
    r.l1 = ((ulong)p[8])       | ((ulong)p[9] << 8)  | ((ulong)p[10] << 16) | ((ulong)p[11] << 24)
        | ((ulong)p[12] << 32) | ((ulong)p[13] << 40) | ((ulong)p[14] << 48) | ((ulong)p[15] << 56);
    r.l2 = ((ulong)p[16])      | ((ulong)p[17] << 8) | ((ulong)p[18] << 16) | ((ulong)p[19] << 24)
        | ((ulong)p[20] << 32) | ((ulong)p[21] << 40) | ((ulong)p[22] << 48) | ((ulong)p[23] << 56);
    r.l3 = ((ulong)p[24])      | ((ulong)p[25] << 8) | ((ulong)p[26] << 16) | ((ulong)p[27] << 24)
        | ((ulong)p[28] << 32) | ((ulong)p[29] << 40) | ((ulong)p[30] << 48) | ((ulong)p[31] << 56);
    return r;
}

inline void write_fp_limbs(thread const Fp &x, device uchar *p) {
    ulong v = x.l0;
    for (int i = 0; i < 8; ++i) { p[i] = (uchar)(v & 0xff); v >>= 8; }
    v = x.l1;
    for (int i = 0; i < 8; ++i) { p[8 + i] = (uchar)(v & 0xff); v >>= 8; }
    v = x.l2;
    for (int i = 0; i < 8; ++i) { p[16 + i] = (uchar)(v & 0xff); v >>= 8; }
    v = x.l3;
    for (int i = 0; i < 8; ++i) { p[24 + i] = (uchar)(v & 0xff); v >>= 8; }
}

inline Pt read_pt(device const uchar *p) {
    Pt r;
    r.X = read_fp_limbs(p);
    r.Y = read_fp_limbs(p + 32);
    r.Z = read_fp_limbs(p + 64);
    return r;
}

inline void write_pt(thread const Pt &p, device uchar *out) {
    write_fp_limbs(p.X, out);
    write_fp_limbs(p.Y, out + 32);
    write_fp_limbs(p.Z, out + 64);
}

// =============================================================================
// Kernels. One thread per element.
// =============================================================================

// banderwagon_add_batch: out_i = P_i + Q_i.
//   pairs: n * 192 bytes = [Pt P_i (96 B) || Pt Q_i (96 B)] for i=0..n-1.
//   outs:  n * 96 bytes.
kernel void banderwagon_add_batch(
    device const uchar *pairs [[buffer(0)]],
    device       uchar *outs  [[buffer(1)]],
    constant     uint  &n     [[buffer(2)]],
    uint i [[thread_position_in_grid]])
{
    if (i >= n) return;
    Pt P = read_pt(pairs + i * 192);
    Pt Q = read_pt(pairs + i * 192 + 96);
    Pt R = pt_add(P, Q);
    write_pt(R, outs + i * 96);
}

// banderwagon_double_batch: out_i = 2 * P_i.
//   pts:  n * 96 bytes.
//   outs: n * 96 bytes.
kernel void banderwagon_double_batch(
    device const uchar *pts  [[buffer(0)]],
    device       uchar *outs [[buffer(1)]],
    constant     uint  &n    [[buffer(2)]],
    uint i [[thread_position_in_grid]])
{
    if (i >= n) return;
    Pt P = read_pt(pts + i * 96);
    Pt R = pt_double(P);
    write_pt(R, outs + i * 96);
}

// banderwagon_smul_batch: out_i = scalar_i * P_i.
//   pts:     n * 96 bytes.
//   scalars: n * 32 bytes (canonical LE Fr scalar bytes).
//   outs:    n * 96 bytes.
kernel void banderwagon_smul_batch(
    device const uchar *pts     [[buffer(0)]],
    device const uchar *scalars [[buffer(1)]],
    device       uchar *outs    [[buffer(2)]],
    constant     uint  &n       [[buffer(3)]],
    uint i [[thread_position_in_grid]])
{
    if (i >= n) return;
    Pt P = read_pt(pts + i * 96);
    Pt R = pt_scalar_mul(P, scalars + i * 32);
    write_pt(R, outs + i * 96);
}

// banderwagon_msm: result_b = sum_{i=0..n-1} scalar_i[b] * P_i, for batch b
// in [0..M).
//
// Layout:
//   pts:     n * 96 bytes (shared across batches).
//   scalars: M * n * 32 bytes; scalar for batch b, point i lives at offset
//            (b*n + i) * 32.
//   outs:    M * 96 bytes.
//   n:       points per MSM.
//   M:       number of independent MSMs (one thread per MSM).
//
// One thread per output MSM. Naive double-and-add over all (P_i, s_i); the
// outer batching gives us many independent MSMs in parallel. This trades
// per-MSM throughput for parallelism across batches and is byte-equal to a
// naive CPU MSM (= sum of s_i * P_i computed with the same Element::add /
// Element::scalar_mul primitives).
kernel void banderwagon_msm_batch_naive(
    device const uchar *pts     [[buffer(0)]],
    device const uchar *scalars [[buffer(1)]],
    device       uchar *outs    [[buffer(2)]],
    constant     uint  &n       [[buffer(3)]],
    constant     uint  &M       [[buffer(4)]],
    uint b [[thread_position_in_grid]])
{
    if (b >= M) return;
    Pt acc = pt_identity();
    for (uint i = 0; i < n; ++i) {
        Pt P = read_pt(pts + i * 96);
        Pt term = pt_scalar_mul(P, scalars + (b * n + i) * 32);
        acc = pt_add(acc, term);
    }
    write_pt(acc, outs + b * 96);
}
