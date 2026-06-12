// kinet-labs/crypto: Karatsuba multiplication kernel (WebGPU Shading Language).
// WGSL has no native uint64; we represent each 64-bit limb as a vec2<u32>
// (lo, hi). 64-bit arithmetic is implemented via 32x32 -> 64-bit native ops.
//
// One-shot full multi-precision multiply r[2n] = x[n] * y[n] for n in
// [16, 64] limbs (1024..4096 bits). Threadgroup-cooperative for the three
// Karatsuba sub-products (host driver dispatches three workgroups concurrently);
// the kernel itself is the schoolbook base case.

const MAX_LIMBS : u32 = 64u;

struct U64 { lo: u32, hi: u32 };

@group(0) @binding(0) var<storage, read>       x : array<U64>;
@group(0) @binding(1) var<storage, read>       y : array<U64>;
@group(0) @binding(2) var<storage, read_write> r : array<U64>;
@group(0) @binding(3) var<uniform>              n : u32;

// 32 x 32 -> 64 multiply, returned as U64 {lo, hi}.
fn u32x32_to_u64(a: u32, b: u32) -> U64 {
    // Use WGSL's native 64-bit-by-multiplication-decomposition. The
    // u32 * u32 -> u32 result truncates the high 32 bits; we recompute via
    // 16-bit splits to recover the full 64-bit product portably.
    let a_lo : u32 = a & 0xFFFFu;
    let a_hi : u32 = a >> 16u;
    let b_lo : u32 = b & 0xFFFFu;
    let b_hi : u32 = b >> 16u;

    let ll : u32 = a_lo * b_lo;
    let lh : u32 = a_lo * b_hi;
    let hl : u32 = a_hi * b_lo;
    let hh : u32 = a_hi * b_hi;

    // result = ll + (lh + hl) << 16 + hh << 32.
    let mid : u32 = lh + hl;
    let mid_carry : u32 = select(0u, 1u << 16u, mid < lh);

    let lo_part : u32 = ll + (mid << 16u);
    let lo_carry : u32 = select(0u, 1u, lo_part < ll);

    let hi_part : u32 = hh + (mid >> 16u) + mid_carry + lo_carry;

    return U64(lo_part, hi_part);
}

// 64x64 -> 128 multiply: returns (lo64, hi64). Output via four u32 lanes
// because WGSL doesn't support multiple return values; we use out parameters
// via storage but inline four-result vec4<u32>.
fn u64_mul_full(a: U64, b: U64) -> vec4<u32> {
    let ll : U64 = u32x32_to_u64(a.lo, b.lo);
    let lh : U64 = u32x32_to_u64(a.lo, b.hi);
    let hl : U64 = u32x32_to_u64(a.hi, b.lo);
    let hh : U64 = u32x32_to_u64(a.hi, b.hi);

    // sum mid words: (ll.hi + lh.lo + hl.lo) carrying into next.
    let m1 : u32 = ll.hi + lh.lo;
    let c1 : u32 = select(0u, 1u, m1 < ll.hi);
    let m2 : u32 = m1 + hl.lo;
    let c2 : u32 = select(0u, 1u, m2 < m1);

    let lo64 : U64 = U64(ll.lo, m2);
    let mid_hi : u32 = lh.hi + hl.hi + c1 + c2;
    let h1 : u32 = hh.lo + mid_hi;
    let c3 : u32 = select(0u, 1u, h1 < hh.lo);
    let hi64 : U64 = U64(h1, hh.hi + c3);

    return vec4<u32>(lo64.lo, lo64.hi, hi64.lo, hi64.hi);
}

@compute @workgroup_size(1)
fn modexp_kara_mul(@builtin(global_invocation_id) gid: vec3<u32>) {
    if (gid.x != 0u) { return; }

    // Zero r.
    for (var k : u32 = 0u; k < 2u * n; k = k + 1u) {
        r[k] = U64(0u, 0u);
    }

    // Schoolbook full product.
    for (var j : u32 = 0u; j < n; j = j + 1u) {
        var carry : U64 = U64(0u, 0u);
        for (var i : u32 = 0u; i < n; i = i + 1u) {
            let p : vec4<u32> = u64_mul_full(x[i], y[j]);
            let plo : U64 = U64(p.x, p.y);
            let phi : U64 = U64(p.z, p.w);

            // r[i+j] += plo + carry
            let r_old = r[i + j];
            let s1_lo : u32 = r_old.lo + plo.lo;
            let s1_lc : u32 = select(0u, 1u, s1_lo < r_old.lo);
            let s1_hi : u32 = r_old.hi + plo.hi + s1_lc;
            let s1_hc : u32 = select(0u, 1u,
                (s1_hi < r_old.hi) || (s1_lc == 1u && s1_hi == r_old.hi));

            let s2_lo : u32 = s1_lo + carry.lo;
            let s2_lc : u32 = select(0u, 1u, s2_lo < s1_lo);
            let s2_hi : u32 = s1_hi + carry.hi + s2_lc;
            let s2_hc : u32 = select(0u, 1u,
                (s2_hi < s1_hi) || (s2_lc == 1u && s2_hi == s1_hi));

            r[i + j] = U64(s2_lo, s2_hi);

            // carry = phi + (s1_hc + s2_hc)
            let cw : u32 = s1_hc + s2_hc;
            let nc_lo : u32 = phi.lo + cw;
            let nc_lc : u32 = select(0u, 1u, nc_lo < phi.lo);
            carry = U64(nc_lo, phi.hi + nc_lc);
        }
        r[j + n] = carry;
    }
}
