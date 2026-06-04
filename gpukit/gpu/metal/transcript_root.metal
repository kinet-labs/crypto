// Skeleton entry point for batched Fiat-Shamir transcript -- v1.2 work.

#include <metal_stdlib>
using namespace metal;

kernel void transcript_root_finalize(
    uint gid [[ thread_position_in_grid ]]) { (void)gid; }
