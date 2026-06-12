// WGSL kernel for the multi-curve Pippenger MSM.
//
// WGSL has neither templates nor preprocessor #include; per-curve
// specialisation is achieved via WGSL `override` constants set by the host
// driver at pipeline-creation time. Only constants change between curves;
// the field-arithmetic body is identical at the WGSL source level.
//
// v1.1 ships the kernel signature + override constants. Cross-curve
// byte-equality validation against the CPU oracle is scheduled for v1.2.
// The driver returns NOTIMPL until then.

// ---- Per-curve override constants (host sets these at pipeline build) -------
// 4-limb field (secp256k1 / bn254 / banderwagon) or 6-limb (bls12-381 g1).
override curve_field_limbs : u32 = 4u;
override curve_bits        : u32 = 256u;
// Modulus + Montgomery -p^-1 mod 2^32 (split into two u32 because WGSL only
// has u32; the host reconstructs from the curve's u64 const table).
override curve_p_inv_lo : u32 = 0u;
override curve_p_inv_hi : u32 = 0u;

// Window size. v1.1 fixes this at 8 to keep the kernel simple; the host
// dispatcher only routes to WGSL when the CPU's chosen c equals 8.
override window_bits : u32 = 8u;

// ---- Kernel signature -------------------------------------------------------
// One thread per (point, scalar) pair within one window. Bucket aggregation
// is finished on the host. The threadgroup-reduction-tree variant is the
// v1.2 work.

struct MpPoint4 {
    x : array<u32, 16>,  // 4 u64s in 8 u32 limbs LE; x then y
};

@group(0) @binding(0) var<storage, read>       points       : array<MpPoint4>;
@group(0) @binding(1) var<storage, read>       scalars_le   : array<u32>;
@group(0) @binding(2) var<storage, read_write> bucket_out   : array<MpPoint4>;
@group(0) @binding(3) var<uniform>             n            : u32;
@group(0) @binding(4) var<uniform>             window_idx   : u32;

@compute @workgroup_size(64)
fn msm_window(@builtin(global_invocation_id) gid : vec3<u32>) {
    let i = gid.x;
    if (i >= n) {
        return;
    }
    // v1.1: signature-only. v1.2 fills the bucket-extract + accumulation
    // path against the WGSL workgroup-shared reduction.
    bucket_out[i] = points[i];
}
