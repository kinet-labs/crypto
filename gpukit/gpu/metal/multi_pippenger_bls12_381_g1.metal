// BLS12-381 G1 specialisation of the multi-curve Pippenger MSM kernel (Metal).
// 6-limb 384-bit field. See gpu/metal/multi_pippenger.metal.

#include <metal_stdlib>
using namespace metal;

#include "../curve_traits/bls12_381_g1_traits.h.metal"

struct MpField6 { uint64_t limbs[6]; };
struct MpPointAffine6 { MpField6 x; MpField6 y; };

[[host_name("msm_bls12_381_g1_window")]]
kernel void msm_bls12_381_g1_window_kernel(
    const device MpPointAffine6* points       [[ buffer(0) ]],
    const device uint8_t*        scalars_le   [[ buffer(1) ]],
    device MpPointAffine6*       bucket_out   [[ buffer(2) ]],
    constant uint&               n            [[ buffer(3) ]],
    constant uint&               window_idx   [[ buffer(4) ]],
    uint                         gid          [[ thread_position_in_grid ]])
{
    if (gid >= n) return;
    bucket_out[gid] = points[gid];
    (void)scalars_le; (void)window_idx;
}
