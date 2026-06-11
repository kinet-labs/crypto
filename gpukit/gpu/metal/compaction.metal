// Stream compaction. Two-stage:
//   1. compaction_mark: convert flags[i]!=0 to 0/1, store in scan_in.
//   2. host runs prefix_sum on scan_in to produce scan_out (exclusive scan
//      conceptually, computed as inclusive scan minus self).
//   3. compaction_scatter: if flags[i] then out[scan_out[i] - 1] = in[i].
//
// We use inclusive scan and shift on-the-fly inside scatter (cheaper than
// a separate exclusive-scan kernel).

#include <metal_stdlib>
using namespace metal;

kernel void compaction_mark_u32(
    device const uchar*  flags    [[ buffer(0) ]],
    device       uint*   scan_in  [[ buffer(1) ]],
    constant     uint&   n        [[ buffer(2) ]],
    uint                 gid      [[ thread_position_in_grid ]])
{
    if (gid >= n) return;
    scan_in[gid] = (flags[gid] != 0) ? 1u : 0u;
}

kernel void compaction_scatter_u32(
    device const uint*   in       [[ buffer(0) ]],
    device const uchar*  flags    [[ buffer(1) ]],
    device const uint*   scan_out [[ buffer(2) ]],   // inclusive scan of marks
    device       uint*   out      [[ buffer(3) ]],
    constant     uint&   n        [[ buffer(4) ]],
    uint                 gid      [[ thread_position_in_grid ]])
{
    if (gid >= n) return;
    if (flags[gid] == 0) return;
    uint dst = scan_out[gid] - 1u;
    out[dst] = in[gid];
}
