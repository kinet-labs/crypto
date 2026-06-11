// First-party WGSL kernel for Banderwagon group operations.
//
// Mechanical port of banderwagon/gpu/metal/banderwagon.metal -- byte-for-byte
// equivalent to kinet::banderwagon::Element {add, double_self, scalar_mul} in
// banderwagon/cpp/element.cpp (twisted Edwards a*x^2 + y^2 = 1 + d*x^2*y^2
// over the BLS12-381 scalar field; a = -5; d = canonical gnark constant).
//
// WGSL has no native u64. Each 64-bit Montgomery limb is represented as a
// pair of u32 (lo, hi), and 64-bit ops (adc, sbb, mulhi) are reconstructed
// from 32-bit primitives. Same approach as poseidon/gpu/wgsl/poseidon2_bn254.
//
// The constant table comes from banderwagon_const.wgslh, which is emitted by
// the CPU body's internal accessors via banderwagon_gen_gpu_constants. There
// is exactly one source of truth across CPU, Metal, CUDA, and WGSL.
//
// The host driver concatenates banderwagon_const.wgslh in front of this file
// before submitting it to wgpu. The kernel below references FP_Q_*_LO/HI,
// FP_QINV_NEG_LO/HI, etc.

// =============================================================================
// 64-bit unsigned represented as (lo, hi) pair of u32. Same layout as the
// host polyfill in banderwagon_driver.cpp.
// =============================================================================
struct U64 { lo: u32, hi: u32 };

fn u64_zero() -> U64 { return U64(0u, 0u); }

fn u64_lt(a: U64, b: U64) -> bool {
    if (a.hi != b.hi) { return a.hi < b.hi; }
    return a.lo < b.lo;
}

fn u64_eq(a: U64, b: U64) -> bool {
    return a.lo == b.lo && a.hi == b.hi;
}

struct U64Carry { v: U64, carry: u32 };

fn u64_add_carry(a: U64, b: U64, cin: u32) -> U64Carry {
    let lo1 = a.lo + b.lo;
    let c0: u32 = select(0u, 1u, lo1 < a.lo);
    let lo  = lo1 + cin;
    let c1: u32 = select(0u, 1u, lo  < lo1);
    let hi1 = a.hi + b.hi;
    let c2: u32 = select(0u, 1u, hi1 < a.hi);
    let hi2 = hi1 + (c0 + c1);
    let c3: u32 = select(0u, 1u, hi2 < hi1);
    return U64Carry(U64(lo, hi2), c2 + c3);
}

struct U64Borrow { v: U64, borrow: u32 };

fn u64_sub_borrow(a: U64, b: U64, bin: u32) -> U64Borrow {
    let lo1: u32 = a.lo - b.lo;
    let bor0: u32 = select(0u, 1u, a.lo < b.lo);
    let lo: u32 = lo1 - bin;
    let bor1: u32 = select(0u, 1u, lo1 < bin);
    let hi1: u32 = a.hi - b.hi;
    let bor2: u32 = select(0u, 1u, a.hi < b.hi);
    let hi: u32  = hi1 - (bor0 + bor1);
    let bor3: u32 = select(0u, 1u, hi1 < (bor0 + bor1));
    return U64Borrow(U64(lo, hi), bor2 + bor3);
}

fn u32_mul64(a: u32, b: u32) -> U64 {
    let al: u32 = a & 0xffffu;
    let ah: u32 = a >> 16u;
    let bl: u32 = b & 0xffffu;
    let bh: u32 = b >> 16u;
    let ll: u32 = al * bl;
    let lh: u32 = al * bh;
    let hl: u32 = ah * bl;
    let hh: u32 = ah * bh;
    let mid_a: u32 = (ll >> 16u) + (lh & 0xffffu);
    let mid_b: u32 = mid_a + (hl & 0xffffu);
    let mid_carry: u32 = (mid_b >> 16u);
    let lo: u32 = (ll & 0xffffu) | (mid_b << 16u);
    let hi: u32 = hh + (lh >> 16u) + (hl >> 16u) + mid_carry;
    return U64(lo, hi);
}

struct U128 { l0: u32, l1: u32, l2: u32, l3: u32 };

fn umul64(a: U64, b: U64) -> U128 {
    let p_ll: U64 = u32_mul64(a.lo, b.lo);
    let p_lh: U64 = u32_mul64(a.lo, b.hi);
    let p_hl: U64 = u32_mul64(a.hi, b.lo);
    let p_hh: U64 = u32_mul64(a.hi, b.hi);
    let w0: u32 = p_ll.lo;
    let s1a: u32 = p_ll.hi + p_lh.lo;
    let c1a: u32 = select(0u, 1u, s1a < p_ll.hi);
    let w1:  u32 = s1a + p_hl.lo;
    let c1b: u32 = select(0u, 1u, w1  < s1a);
    let carry1: u32 = c1a + c1b;
    let s2a: u32 = p_lh.hi + p_hl.hi;
    let c2a: u32 = select(0u, 1u, s2a < p_lh.hi);
    let s2b: u32 = s2a + p_hh.lo;
    let c2b: u32 = select(0u, 1u, s2b < s2a);
    let w2:  u32 = s2b + carry1;
    let c2c: u32 = select(0u, 1u, w2  < s2b);
    let carry2: u32 = c2a + c2b + c2c;
    let w3: u32 = p_hh.hi + carry2;
    return U128(w0, w1, w2, w3);
}

fn u64_mul_low(a: U64, b: U64) -> U64 {
    let p_ll: U64 = u32_mul64(a.lo, b.lo);
    let p_lh: U64 = u32_mul64(a.lo, b.hi);
    let p_hl: U64 = u32_mul64(a.hi, b.lo);
    let lo: u32 = p_ll.lo;
    let hi: u32 = p_ll.hi + p_lh.lo + p_hl.lo;
    return U64(lo, hi);
}

// =============================================================================
// 256-bit Fp in Montgomery form, four U64 limbs.
// =============================================================================
struct Fp { l0: U64, l1: U64, l2: U64, l3: U64 };
struct Pt { X: Fp,  Y: Fp,  Z: Fp };

fn fp_zero() -> Fp { return Fp(u64_zero(), u64_zero(), u64_zero(), u64_zero()); }

fn fp_q() -> Fp {
    return Fp(U64(FP_Q_0_LO, FP_Q_0_HI), U64(FP_Q_1_LO, FP_Q_1_HI),
              U64(FP_Q_2_LO, FP_Q_2_HI), U64(FP_Q_3_LO, FP_Q_3_HI));
}

fn fp_one() -> Fp {
    return Fp(U64(FP_R_0_LO, FP_R_0_HI), U64(FP_R_1_LO, FP_R_1_HI),
              U64(FP_R_2_LO, FP_R_2_HI), U64(FP_R_3_LO, FP_R_3_HI));
}

fn fp_curve_a() -> Fp {
    return Fp(U64(CURVE_A_0_LO, CURVE_A_0_HI), U64(CURVE_A_1_LO, CURVE_A_1_HI),
              U64(CURVE_A_2_LO, CURVE_A_2_HI), U64(CURVE_A_3_LO, CURVE_A_3_HI));
}

fn fp_curve_d() -> Fp {
    return Fp(U64(CURVE_D_0_LO, CURVE_D_0_HI), U64(CURVE_D_1_LO, CURVE_D_1_HI),
              U64(CURVE_D_2_LO, CURVE_D_2_HI), U64(CURVE_D_3_LO, CURVE_D_3_HI));
}

fn fp_qinv() -> U64 { return U64(FP_QINV_NEG_LO, FP_QINV_NEG_HI); }

fn fp_cond_sub_q(a_in: Fp) -> Fp {
    let q = fp_q();
    let r0 = u64_sub_borrow(a_in.l0, q.l0, 0u);
    let r1 = u64_sub_borrow(a_in.l1, q.l1, r0.borrow);
    let r2 = u64_sub_borrow(a_in.l2, q.l2, r1.borrow);
    let r3 = u64_sub_borrow(a_in.l3, q.l3, r2.borrow);
    let br: u32 = r3.borrow;
    let mask: u32 = select(0xffffffffu, 0u, br == 1u);
    return Fp(
        U64((a_in.l0.lo & ~mask) | (r0.v.lo & mask),
            (a_in.l0.hi & ~mask) | (r0.v.hi & mask)),
        U64((a_in.l1.lo & ~mask) | (r1.v.lo & mask),
            (a_in.l1.hi & ~mask) | (r1.v.hi & mask)),
        U64((a_in.l2.lo & ~mask) | (r2.v.lo & mask),
            (a_in.l2.hi & ~mask) | (r2.v.hi & mask)),
        U64((a_in.l3.lo & ~mask) | (r3.v.lo & mask),
            (a_in.l3.hi & ~mask) | (r3.v.hi & mask)),
    );
}

fn fp_cond_add_q(a_in: Fp, mask: u32) -> Fp {
    let q = fp_q();
    let add0 = U64(q.l0.lo & mask, q.l0.hi & mask);
    let add1 = U64(q.l1.lo & mask, q.l1.hi & mask);
    let add2 = U64(q.l2.lo & mask, q.l2.hi & mask);
    let add3 = U64(q.l3.lo & mask, q.l3.hi & mask);
    let r0 = u64_add_carry(a_in.l0, add0, 0u);
    let r1 = u64_add_carry(a_in.l1, add1, r0.carry);
    let r2 = u64_add_carry(a_in.l2, add2, r1.carry);
    let r3 = u64_add_carry(a_in.l3, add3, r2.carry);
    return Fp(r0.v, r1.v, r2.v, r3.v);
}

fn fp_add(a: Fp, b: Fp) -> Fp {
    let r0 = u64_add_carry(a.l0, b.l0, 0u);
    let r1 = u64_add_carry(a.l1, b.l1, r0.carry);
    let r2 = u64_add_carry(a.l2, b.l2, r1.carry);
    let r3 = u64_add_carry(a.l3, b.l3, r2.carry);
    return fp_cond_sub_q(Fp(r0.v, r1.v, r2.v, r3.v));
}

fn fp_sub(a: Fp, b: Fp) -> Fp {
    let r0 = u64_sub_borrow(a.l0, b.l0, 0u);
    let r1 = u64_sub_borrow(a.l1, b.l1, r0.borrow);
    let r2 = u64_sub_borrow(a.l2, b.l2, r1.borrow);
    let r3 = u64_sub_borrow(a.l3, b.l3, r2.borrow);
    let mask: u32 = select(0u, 0xffffffffu, r3.borrow == 1u);
    return fp_cond_add_q(Fp(r0.v, r1.v, r2.v, r3.v), mask);
}

fn fp_mul(a: Fp, b: Fp) -> Fp {
    var t0 = u64_zero();
    var t1 = u64_zero();
    var t2 = u64_zero();
    var t3 = u64_zero();
    var t4 = u64_zero();
    let al = array<U64, 4>(a.l0, a.l1, a.l2, a.l3);
    let bl = array<U64, 4>(b.l0, b.l1, b.l2, b.l3);
    let qq = array<U64, 4>(U64(FP_Q_0_LO, FP_Q_0_HI),
                            U64(FP_Q_1_LO, FP_Q_1_HI),
                            U64(FP_Q_2_LO, FP_Q_2_HI),
                            U64(FP_Q_3_LO, FP_Q_3_HI));
    let qinv = fp_qinv();

    for (var i: i32 = 0; i < 4; i = i + 1) {
        var cy: U64 = u64_zero();
        for (var j: i32 = 0; j < 4; j = j + 1) {
            let prod = umul64(al[j], bl[i]);
            let lo = U64(prod.l0, prod.l1);
            let hi = U64(prod.l2, prod.l3);
            var tj: U64 = u64_zero();
            if (j == 0) { tj = t0; }
            else if (j == 1) { tj = t1; }
            else if (j == 2) { tj = t2; }
            else { tj = t3; }
            let s  = u64_add_carry(tj, lo, 0u);
            let s2 = u64_add_carry(s.v,  cy, 0u);
            if (j == 0) { t0 = s2.v; }
            else if (j == 1) { t1 = s2.v; }
            else if (j == 2) { t2 = s2.v; }
            else { t3 = s2.v; }
            let cy1 = u64_add_carry(hi,    U64(s.carry,  0u), 0u);
            let cy2 = u64_add_carry(cy1.v, U64(s2.carry, 0u), 0u);
            cy = cy2.v;
        }
        let t4u = u64_add_carry(t4, cy, 0u);
        t4 = t4u.v;
        let big_carry: u32 = t4u.carry;

        let m: U64 = u64_mul_low(t0, qinv);

        cy = u64_zero();
        for (var j: i32 = 0; j < 4; j = j + 1) {
            let prod = umul64(m, qq[j]);
            let lo = U64(prod.l0, prod.l1);
            let hi = U64(prod.l2, prod.l3);
            var tj: U64 = u64_zero();
            if (j == 0) { tj = t0; }
            else if (j == 1) { tj = t1; }
            else if (j == 2) { tj = t2; }
            else { tj = t3; }
            let s  = u64_add_carry(tj, lo, 0u);
            let s2 = u64_add_carry(s.v,  cy, 0u);
            if (j == 0) { t0 = s2.v; }
            else if (j == 1) { t1 = s2.v; }
            else if (j == 2) { t2 = s2.v; }
            else { t3 = s2.v; }
            let cy1 = u64_add_carry(hi,    U64(s.carry,  0u), 0u);
            let cy2 = u64_add_carry(cy1.v, U64(s2.carry, 0u), 0u);
            cy = cy2.v;
        }
        let t3_step = u64_add_carry(t4, cy, 0u);
        let t4_step = u64_add_carry(u64_zero(),
                                     U64(big_carry, 0u),
                                     t3_step.carry);

        t0 = t1; t1 = t2; t2 = t3;
        t3 = t3_step.v;
        t4 = t4_step.v;
    }

    var r = Fp(t0, t1, t2, t3);
    if (!(t4.lo == 0u && t4.hi == 0u)) {
        let s0 = u64_sub_borrow(r.l0, U64(FP_Q_0_LO, FP_Q_0_HI), 0u);
        let s1 = u64_sub_borrow(r.l1, U64(FP_Q_1_LO, FP_Q_1_HI), s0.borrow);
        let s2 = u64_sub_borrow(r.l2, U64(FP_Q_2_LO, FP_Q_2_HI), s1.borrow);
        let s3 = u64_sub_borrow(r.l3, U64(FP_Q_3_LO, FP_Q_3_HI), s2.borrow);
        return Fp(s0.v, s1.v, s2.v, s3.v);
    }
    return fp_cond_sub_q(r);
}

fn fp_square(a: Fp) -> Fp { return fp_mul(a, a); }

fn pt_identity() -> Pt { return Pt(fp_zero(), fp_one(), fp_one()); }

fn pt_add(p1: Pt, p2: Pt) -> Pt {
    let d_const = fp_curve_d();
    let a_const = fp_curve_a();

    let A = fp_mul(p1.Z, p2.Z);
    let B = fp_square(A);
    let C = fp_mul(p1.X, p2.X);
    let D = fp_mul(p1.Y, p2.Y);
    let CD = fp_mul(C, D);
    let E = fp_mul(d_const, CD);
    let F = fp_sub(B, E);
    let G = fp_add(B, E);
    let H = fp_add(p1.X, p1.Y);
    let I = fp_add(p2.X, p2.Y);

    var t = fp_mul(H, I);
    t = fp_sub(t, C);
    t = fp_sub(t, D);
    t = fp_mul(t, A);
    let X3 = fp_mul(t, F);

    let aC = fp_mul(a_const, C);
    var t2 = fp_sub(D, aC);
    t2 = fp_mul(t2, A);
    let Y3 = fp_mul(t2, G);

    let Z3 = fp_mul(F, G);
    return Pt(X3, Y3, Z3);
}

fn pt_double(p: Pt) -> Pt {
    let a_const = fp_curve_a();
    let XY = fp_add(p.X, p.Y);
    let B  = fp_square(XY);
    let C  = fp_square(p.X);
    let D  = fp_square(p.Y);
    let E  = fp_mul(a_const, C);
    let F  = fp_add(E, D);
    let H  = fp_square(p.Z);
    let twoH = fp_add(H, H);
    let J  = fp_sub(F, twoH);

    var t = fp_sub(B, C);
    t = fp_sub(t, D);
    let X3 = fp_mul(t, J);
    let Y3 = fp_mul(F, fp_sub(E, D));
    let Z3 = fp_mul(F, J);
    return Pt(X3, Y3, Z3);
}

fn pt_cmov_select(dst: Pt, src: Pt, mask: u32) -> Pt {
    return Pt(
        Fp(U64((dst.X.l0.lo & ~mask) | (src.X.l0.lo & mask),
               (dst.X.l0.hi & ~mask) | (src.X.l0.hi & mask)),
           U64((dst.X.l1.lo & ~mask) | (src.X.l1.lo & mask),
               (dst.X.l1.hi & ~mask) | (src.X.l1.hi & mask)),
           U64((dst.X.l2.lo & ~mask) | (src.X.l2.lo & mask),
               (dst.X.l2.hi & ~mask) | (src.X.l2.hi & mask)),
           U64((dst.X.l3.lo & ~mask) | (src.X.l3.lo & mask),
               (dst.X.l3.hi & ~mask) | (src.X.l3.hi & mask))),
        Fp(U64((dst.Y.l0.lo & ~mask) | (src.Y.l0.lo & mask),
               (dst.Y.l0.hi & ~mask) | (src.Y.l0.hi & mask)),
           U64((dst.Y.l1.lo & ~mask) | (src.Y.l1.lo & mask),
               (dst.Y.l1.hi & ~mask) | (src.Y.l1.hi & mask)),
           U64((dst.Y.l2.lo & ~mask) | (src.Y.l2.lo & mask),
               (dst.Y.l2.hi & ~mask) | (src.Y.l2.hi & mask)),
           U64((dst.Y.l3.lo & ~mask) | (src.Y.l3.lo & mask),
               (dst.Y.l3.hi & ~mask) | (src.Y.l3.hi & mask))),
        Fp(U64((dst.Z.l0.lo & ~mask) | (src.Z.l0.lo & mask),
               (dst.Z.l0.hi & ~mask) | (src.Z.l0.hi & mask)),
           U64((dst.Z.l1.lo & ~mask) | (src.Z.l1.lo & mask),
               (dst.Z.l1.hi & ~mask) | (src.Z.l1.hi & mask)),
           U64((dst.Z.l2.lo & ~mask) | (src.Z.l2.lo & mask),
               (dst.Z.l2.hi & ~mask) | (src.Z.l2.hi & mask)),
           U64((dst.Z.l3.lo & ~mask) | (src.Z.l3.lo & mask),
               (dst.Z.l3.hi & ~mask) | (src.Z.l3.hi & mask))),
    );
}

fn read_fp(buf: ptr<storage, array<u32>, read>, word_off: u32) -> Fp {
    return Fp(
        U64((*buf)[word_off + 0u], (*buf)[word_off + 1u]),
        U64((*buf)[word_off + 2u], (*buf)[word_off + 3u]),
        U64((*buf)[word_off + 4u], (*buf)[word_off + 5u]),
        U64((*buf)[word_off + 6u], (*buf)[word_off + 7u]),
    );
}

fn write_fp(buf: ptr<storage, array<u32>, read_write>, word_off: u32, x: Fp) {
    (*buf)[word_off + 0u] = x.l0.lo; (*buf)[word_off + 1u] = x.l0.hi;
    (*buf)[word_off + 2u] = x.l1.lo; (*buf)[word_off + 3u] = x.l1.hi;
    (*buf)[word_off + 4u] = x.l2.lo; (*buf)[word_off + 5u] = x.l2.hi;
    (*buf)[word_off + 6u] = x.l3.lo; (*buf)[word_off + 7u] = x.l3.hi;
}

fn read_pt(buf: ptr<storage, array<u32>, read>, word_off: u32) -> Pt {
    return Pt(read_fp(buf, word_off       ),
              read_fp(buf, word_off +  8u ),
              read_fp(buf, word_off + 16u ));
}

fn write_pt(buf: ptr<storage, array<u32>, read_write>, word_off: u32, p: Pt) {
    write_fp(buf, word_off       , p.X);
    write_fp(buf, word_off +  8u , p.Y);
    write_fp(buf, word_off + 16u , p.Z);
}

fn pt_scalar_mul(p: Pt, scalars: ptr<storage, array<u32>, read>, word_off: u32) -> Pt {
    var acc  = pt_identity();
    var base = p;
    for (var w: u32 = 0u; w < 8u; w = w + 1u) {
        let word = (*scalars)[word_off + w];
        for (var byte_in_word: u32 = 0u; byte_in_word < 4u; byte_in_word = byte_in_word + 1u) {
            let b: u32 = (word >> (byte_in_word * 8u)) & 0xffu;
            for (var bit: u32 = 0u; bit < 8u; bit = bit + 1u) {
                let one_or_zero: u32 = (b >> bit) & 1u;
                let mask: u32 = select(0u, 0xffffffffu, one_or_zero == 1u);
                let sum = pt_add(acc, base);
                acc  = pt_cmov_select(acc, sum, mask);
                base = pt_double(base);
            }
        }
    }
    return acc;
}

@group(0) @binding(0) var<storage, read>       g_pts     : array<u32>;
@group(0) @binding(1) var<storage, read>       g_scalars : array<u32>;
@group(0) @binding(2) var<storage, read_write> g_outs    : array<u32>;
@group(0) @binding(3) var<uniform>             g_n       : u32;
@group(0) @binding(4) var<uniform>             g_M       : u32;

@compute @workgroup_size(64)
fn banderwagon_add_kernel(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x;
    if (i >= g_n) { return; }
    let off = i * 48u;
    let P = read_pt(&g_pts, off);
    let Q = read_pt(&g_pts, off + 24u);
    let R = pt_add(P, Q);
    write_pt(&g_outs, i * 24u, R);
}

@compute @workgroup_size(64)
fn banderwagon_double_kernel(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x;
    if (i >= g_n) { return; }
    let off = i * 24u;
    let P = read_pt(&g_pts, off);
    let R = pt_double(P);
    write_pt(&g_outs, off, R);
}

@compute @workgroup_size(32)
fn banderwagon_smul_kernel(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x;
    if (i >= g_n) { return; }
    let pt_off = i * 24u;
    let sc_off = i * 8u;
    let P = read_pt(&g_pts, pt_off);
    let R = pt_scalar_mul(P, &g_scalars, sc_off);
    write_pt(&g_outs, pt_off, R);
}

@compute @workgroup_size(32)
fn banderwagon_msm_kernel(@builtin(global_invocation_id) gid: vec3<u32>) {
    let b = gid.x;
    if (b >= g_M) { return; }
    let n = g_n;
    var acc = pt_identity();
    for (var i: u32 = 0u; i < n; i = i + 1u) {
        let P    = read_pt(&g_pts, i * 24u);
        let term = pt_scalar_mul(P, &g_scalars, (b * n + i) * 8u);
        acc = pt_add(acc, term);
    }
    write_pt(&g_outs, b * 24u, acc);
}
