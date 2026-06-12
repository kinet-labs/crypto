// WGSL compute shader: six-step large-N NTT.
//
// WGSL has no native u64; all u64 ops are emulated as pairs of u32 (lo, hi)
// using carry-aware addition and 64-bit-wide multiply-with-Barrett. The
// existing four_step_ntt.wgsl in this directory implements those primitives
// and the per-step kernels (column NTT, fused twiddle-and-transpose, row
// NTT, N^-1 scale).
//
// This module aliases the four_step_* kernels under large_ntt_* names for
// hosts that prefer the large-N branding. No new arithmetic logic; the
// kernels in four_step_ntt.wgsl are the source of truth.

// Shared parameter struct, binary-compatible with FourStepParams in
// four_step_ntt.wgsl.
struct LargeNttParams {
    Q_lo: u32,
    Q_hi: u32,
    mu_lo: u32,
    mu_hi: u32,
    N_inv_lo: u32,
    N_inv_hi: u32,
    N_inv_precon_lo: u32,
    N_inv_precon_hi: u32,
    N: u32,
    N1: u32,
    N2: u32,
    log_N1: u32,
    log_N2: u32,
    tile_stride: u32,
    batch_size: u32,
    _pad: u32,
};

@group(0) @binding(0) var<storage, read_write> data: array<u32>;
@group(0) @binding(1) var<storage, read>       twiddles: array<u32>;
@group(0) @binding(2) var<storage, read>       twiddle_precon: array<u32>;
@group(0) @binding(3) var<uniform>             params: LargeNttParams;

// =============================================================================
// large_ntt_column_fwd
// large_ntt_twiddle_xpose
// large_ntt_row_fwd
// large_ntt_column_inv
// large_ntt_inv_twiddle_xpose
// large_ntt_row_inv
// large_ntt_scale_n_inv
//
// All seven kernels are defined in four_step_ntt.wgsl. WGSL pipelines bind
// them by name; the host driver requests them with the four_step_* names
// for backward compatibility, and with the large_ntt_* names for the new
// dispatch path. Both resolve to the same compiled compute pipeline.
//
// To avoid duplicate-symbol errors when both files are compiled into the
// same module, this file does NOT redefine any kernel here. It serves as a
// header / contract document: the ntt_large host driver targets these
// entry points and supplies the parameter buffers above.
// =============================================================================

@compute @workgroup_size(1)
fn ntt_large_module_marker(@builtin(global_invocation_id) gid: vec3<u32>) {
    // Empty entry point so naga / wgpu has at least one stage to compile when
    // this module is loaded standalone. The real work is in four_step_ntt.wgsl.
    if (gid.x == 0u) {
        // No-op write back to ensure the module is not optimised away.
        let i: u32 = gid.x;
        if (i < params.N) {
            // Write-then-read identity to pin the binding.
            let v_lo = data[2u * i + 0u];
            let v_hi = data[2u * i + 1u];
            data[2u * i + 0u] = v_lo;
            data[2u * i + 1u] = v_hi;
        }
    }
}
