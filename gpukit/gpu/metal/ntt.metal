// Skeleton entry points for forward NTT (Kyber/Dilithium) -- v1.2 work.

#include <metal_stdlib>
using namespace metal;

kernel void ntt_kyber_butterfly(
    uint gid [[ thread_position_in_grid ]]) { (void)gid; }

kernel void ntt_dilithium_butterfly(
    uint gid [[ thread_position_in_grid ]]) { (void)gid; }
