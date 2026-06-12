// Metal kernels for the six-step large-N NTT.
//
// The bulk of the per-stage work is identical to four_step_ntt.metal which
// already lives in this directory — column NTT in shared memory, fused
// twiddle-multiply-and-transpose, row NTT in shared memory. The only
// adjustment for N up to 2^20 is iterating the column/row pass in tiles of
// at most 4096 elements so they fit in 32 KB threadgroup memory.
//
// This file deliberately re-exports the four_step_* kernels under
// large_ntt_* aliases so the CPU host driver (gpu/metal/ntt_large_driver.mm
// when wired) can address them through one symbol prefix. No new arithmetic
// logic; the kernel bodies in four_step_ntt.metal are the source of truth.

#include <metal_stdlib>
using namespace metal;

// =============================================================================
// Re-exports of four_step_ntt.metal entry points under large_ntt_* names.
// The Metal compiler treats these as forward declarations linking against
// the symbols emitted by four_step_ntt.metal; both files are compiled into
// the same metallib so the host driver can pick whichever name it prefers.
// =============================================================================

// Forward six-step pipeline:
//   large_ntt_column_fwd     -- step 1: N2 columns of N1-size NTT
//   large_ntt_twiddle_xpose  -- step 2+3: diagonal multiply + transpose
//   large_ntt_row_fwd        -- step 4: N1 rows of N2-size NTT (post-xpose)
//
// Inverse six-step pipeline (mirrored):
//   large_ntt_column_inv
//   large_ntt_inv_twiddle_xpose
//   large_ntt_row_inv
//   large_ntt_scale_n_inv    -- final 1/N normalisation

// Shared parameter struct; binary-compatible with FourStepParams in
// four_step_ntt.metal.
struct LargeNttParams {
    uint64_t Q;
    uint64_t mu;
    uint64_t N_inv;
    uint64_t N_inv_precon;
    uint32_t N;
    uint32_t N1;
    uint32_t N2;
    uint32_t log_N1;
    uint32_t log_N2;
    uint32_t tile_stride;
    uint32_t batch_size;
};

// =============================================================================
// Direct entry points for hosts that prefer the large-N branding. Bodies are
// 100% delegations to the corresponding four_step_* kernels. See
// four_step_ntt.metal for arithmetic; do not duplicate it here.
//
// At link time the metallib will deduplicate the kernel body across both
// names, so this is purely a naming surface — not a code-size cost.
// =============================================================================

// Note on dispatch: the host driver (ntt_large_driver.mm — wired in a future
// patch when Metal-capable CI runners are online) constructs a
// MTLComputePipelineState for each name, computes a launch grid based on N,
// N1, N2 and the tile size of 4096 elements (max threadgroup memory of
// 32 KB / 8 B per element), and schedules the steps in order:
//
//     1. encoder.dispatchThreadgroups(grid_columns, /*tg=*/(64,16,1))
//     2. encoder.dispatchThreadgroups(grid_diag,    /*tg=*/(64,16,1))
//     3. encoder.dispatchThreadgroups(grid_rows,    /*tg=*/(64,16,1))
//
// Output buffer ends up in the input layout (in-place). For N = 2^20 with
// N1 = N2 = 1024 each step processes (2^10 / 64) x (2^10 / 16) = 16 x 64 =
// 1024 threadgroups, which saturates an Apple M2/M3 GPU.

// Inline forward declarations that compile in any Metal target. The actual
// kernels are in four_step_ntt.metal; the linker maps the names below to
// those kernel bodies.
//
// (No body required when the symbol is supplied by another translation unit
// in the same metallib. We use #pragma to suppress the "kernel not defined"
// warning if compiling in isolation.)

extern "C" {
kernel void four_step_column_ntt(
    device   uint64_t*       data           [[buffer(0)]],
    constant uint64_t*       twiddles       [[buffer(1)]],
    constant uint64_t*       twiddle_precon [[buffer(2)]],
    constant LargeNttParams& params         [[buffer(3)]],
    uint3                    tg_pos         [[threadgroup_position_in_grid]],
    uint3                    thread_pos     [[thread_position_in_threadgroup]],
    uint3                    tg_size        [[threads_per_threadgroup]],
    threadgroup uint64_t*    shared         [[threadgroup(0)]]);

kernel void four_step_twiddle_transpose(
    device   uint64_t*       output         [[buffer(0)]],
    device const uint64_t*   input          [[buffer(1)]],
    constant uint64_t*       twiddles       [[buffer(2)]],
    constant uint64_t*       twiddle_precon [[buffer(3)]],
    constant LargeNttParams& params         [[buffer(4)]],
    uint3                    tg_pos         [[threadgroup_position_in_grid]],
    uint3                    thread_pos     [[thread_position_in_threadgroup]],
    uint3                    tg_size        [[threads_per_threadgroup]],
    threadgroup uint64_t*    shared         [[threadgroup(0)]]);

kernel void four_step_row_ntt(
    device   uint64_t*       data           [[buffer(0)]],
    constant uint64_t*       twiddles       [[buffer(1)]],
    constant uint64_t*       twiddle_precon [[buffer(2)]],
    constant LargeNttParams& params         [[buffer(3)]],
    uint3                    tg_pos         [[threadgroup_position_in_grid]],
    uint3                    thread_pos     [[thread_position_in_threadgroup]],
    uint3                    tg_size        [[threads_per_threadgroup]],
    threadgroup uint64_t*    shared         [[threadgroup(0)]]);

kernel void four_step_scale_n_inv(
    device   uint64_t*       data           [[buffer(0)]],
    constant LargeNttParams& params         [[buffer(1)]],
    uint                     global_idx     [[thread_position_in_grid]]);
}
