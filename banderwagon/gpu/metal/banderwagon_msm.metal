// =============================================================================
// kinet-labs/crypto/banderwagon -- Metal MSM kernel (WIP)
// =============================================================================
//
// 256-bit Montgomery field arithmetic over q = BLS12-381 r, plus twisted
// Edwards add/double for Bandersnatch (a = -5), plus windowed Pippenger MSM.
//
// Status: source compiles with `xcrun -sdk macosx metal` and lays out the
// kernel signature; bucket-aggregation and bit-reduction step are not yet
// validated against the CPU oracle. The driver does not dispatch this kernel
// until validation lands; the C-ABI shim therefore falls back to the CPU
// body. The kernel is kept in-tree so the metallib build target exists for
// the follow-up validation PR.
//
// =============================================================================

#include <metal_stdlib>
using namespace metal;

// 4 x 64-bit limb little-endian field element. Canonical (non-Montgomery)
// representation, mirrors Fp on the CPU side (cpp/banderwagon.cpp).
struct Fp { ulong4 v; };

// Banderwagon affine point.
struct PointAffine { Fp x; Fp y; };

// Window size (must match CPU msm_pippenger).
constant uint kWindow = 8u;
constant uint kBuckets = (1u << kWindow) - 1u;

// MSM dispatch signature. Each thread handles one (scalar, point) pair within
// one window; outer windows are aggregated on the host. Bucket sums are
// reduced per workgroup via threadgroup memory.
//
// THIS KERNEL BODY IS A PLACEHOLDER. It does not perform the MSM; the driver
// returns NOTIMPL and the host code falls back to CPU. See banderwagon_driver.mm.
[[host_name("banderwagon_msm_window")]]
kernel void banderwagon_msm_window_kernel(
    const device PointAffine* points       [[ buffer(0) ]],
    const device Fp*           scalars     [[ buffer(1) ]],
    device PointAffine*        bucket_out  [[ buffer(2) ]],
    constant uint&             n           [[ buffer(3) ]],
    constant uint&             window_idx  [[ buffer(4) ]],
    uint                       gid         [[ thread_position_in_grid ]])
{
    if (gid >= n) return;
    // Placeholder; real bucket accumulation goes here.
    bucket_out[gid] = points[gid];
}
