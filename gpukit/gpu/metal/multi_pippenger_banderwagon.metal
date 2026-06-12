// Banderwagon specialisation of the multi-curve Pippenger MSM kernel (Metal).
// Twisted-Edwards group with a = -5; addition formula differs from short
// Weierstrass but the bucket-sort skeleton is identical.

#include <metal_stdlib>
using namespace metal;

#include "../curve_traits/banderwagon_traits.h.metal"

struct MpField4 { uint64_t limbs[4]; };
struct MpPointAffine4 { MpField4 x; MpField4 y; };

[[host_name("msm_banderwagon_window")]]
kernel void msm_banderwagon_window_kernel(
    const device MpPointAffine4* points       [[ buffer(0) ]],
    const device uint8_t*        scalars_le   [[ buffer(1) ]],
    device MpPointAffine4*       bucket_out   [[ buffer(2) ]],
    constant uint&               n            [[ buffer(3) ]],
    constant uint&               window_idx   [[ buffer(4) ]],
    uint                         gid          [[ thread_position_in_grid ]])
{
    if (gid >= n) return;
    bucket_out[gid] = points[gid];
    (void)scalars_le; (void)window_idx;
}
