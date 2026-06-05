// SPDX-License-Identifier: BSD-3-Clause-Eco
// gpukit batch_inversion -- WGSL skeleton. Real implementation v1.2.
@compute @workgroup_size(64) fn batch_inv_step(@builtin(global_invocation_id) gid: vec3<u32>) {}
