// SPDX-License-Identifier: BSD-3-Clause-Eco
// gpukit NTT -- WGSL skeleton. Real implementation v1.2.
@compute @workgroup_size(64) fn ntt_butterfly(@builtin(global_invocation_id) gid: vec3<u32>) {}
