// Skeleton entry point for parallel Merkle compose. Real impl v1.2.

#include <metal_stdlib>
using namespace metal;

kernel void merkle_compose_layer(
    uint gid [[ thread_position_in_grid ]]) { (void)gid; }
