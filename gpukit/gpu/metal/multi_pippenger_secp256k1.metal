// secp256k1 specialisation of the multi-curve Pippenger MSM kernel (Metal).
// See gpu/metal/multi_pippenger.metal for the shared algorithm. v1.1 ships
// the entry-point signature so the metallib build target exists; the body
// is filled by v1.2 once cross-curve byte-equality vs the CPU reference
// is pinned.

#include <metal_stdlib>
using namespace metal;

#include "../curve_traits/secp256k1_traits.h.metal"

struct MpField4 { uint64_t limbs[4]; };
struct MpPointAffine4 { MpField4 x; MpField4 y; };

// Window-pass entry. One thread per (point, scalar) pair within a single
// c-bit window. Bucket aggregation is finished on the host (reduction tree
// in Metal threadgroup memory is the v1.2 work).
[[host_name("msm_secp256k1_window")]]
kernel void msm_secp256k1_window_kernel(
    const device MpPointAffine4* points       [[ buffer(0) ]],
    const device uint8_t*        scalars_le   [[ buffer(1) ]],
    device MpPointAffine4*       bucket_out   [[ buffer(2) ]],
    constant uint&               n            [[ buffer(3) ]],
    constant uint&               window_idx   [[ buffer(4) ]],
    uint                         gid          [[ thread_position_in_grid ]])
{
    if (gid >= n) return;
    // v1.1: signature-only. v1.2 fills the bucket extraction + per-thread
    // accumulation against the threadgroup reduction tree.
    bucket_out[gid] = points[gid];
    (void)scalars_le; (void)window_idx;
}
