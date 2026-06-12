// WGSL peer of bls_combined_miller.metal — tree-reduce kernel for the
// k-pair Miller-loop fan-in.
//
// The Miller per-bit kernels are not yet ported to WGSL on this stage
// (Stage 4 ships Fp-tower parity only; full miller_loop remains on the
// host CPU oracle for WGSL until Stage 5b).  This shader provides the
// canonical pairwise Fp12 reduction over k Miller outputs:
//
//   round 0: out[i] = in[2*i] * in[2*i+1]   (i < pairs)
//            out[pairs] = in[2*pairs]        (carry, when n is odd)
//   round 1: same shape, halved n
//   ...
//   final:   out[0] = prod_i in[i]
//
// Determinism: index map (in[2i], in[2i+1]) -> out[i] is canonical and
// matches tree_reduce_fp12 in cpp/bls_pairing.cpp + the Metal/CUDA peers.
//
// Concatenated by the WGSL host driver after bls_fp_ops.wgsl, bls_fp2.wgsl,
// bls_fp6.wgsl, bls_fp12.wgsl (same scheme as bls_fp_tower_kernels.wgsl).

@group(0) @binding(0) var<storage, read>       in_a: array<u32>;
@group(0) @binding(2) var<storage, read_write> out:  array<u32>;
// params.x = pairs, params.y = carry (0 or 1), params.z = total threads
@group(0) @binding(3) var<uniform>             params: vec4<u32>;

var<private> g_a: array<u32, 144>;
var<private> g_b: array<u32, 144>;
var<private> g_r: array<u32, 144>;

fn load_fp12_at(slot: u32, dst: ptr<private, array<u32, 144>>) {
    let base = slot * 144u;
    for (var i = 0u; i < 144u; i = i + 1u) { (*dst)[i] = in_a[base + i]; }
}
fn store_fp12_at(slot: u32, src: ptr<private, array<u32, 144>>) {
    let base = slot * 144u;
    for (var i = 0u; i < 144u; i = i + 1u) { out[base + i] = (*src)[i]; }
}

// One round of canonical pairwise tree reduction.
//
//   tid <  pairs        : out[tid] = in[2*tid] * in[2*tid+1]
//   tid == pairs (carry): out[tid] = in[2*tid]   (last element passes through)
//
// Caller dispatches with threads = pairs + carry and runs ceil(log2(k))
// rounds, swapping in_a / out between dispatches.
@compute @workgroup_size(1)
fn k_combined_miller_reduce(@builtin(global_invocation_id) gid: vec3<u32>) {
    let tid   = gid.x;
    let pairs = params.x;
    let carry = params.y;

    if (tid < pairs) {
        load_fp12_at(2u * tid,        &g_a);
        load_fp12_at(2u * tid + 1u,   &g_b);
        fp12_mul_priv(&g_a, &g_b, &g_r);
        store_fp12_at(tid, &g_r);
        return;
    }
    if (carry != 0u && tid == pairs) {
        load_fp12_at(2u * tid, &g_a);
        store_fp12_at(tid, &g_a);
    }
}
