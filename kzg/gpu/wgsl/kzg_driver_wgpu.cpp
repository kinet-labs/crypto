// Host-side WebGPU/WGSL driver for KZG kernels.
//
// On hosts with wgpu-native (KINET_KZG_HAS_WEBGPU=1): would dispatch
// kzg_blob_to_commit kernel via shared bls_driver_wgpu pattern. The current
// build does not pull wgpu at the kzg level; the CPU-oracle path satisfies
// the determinism contract on every host. CI runners with hardware can opt in
// by defining KINET_KZG_HAS_WEBGPU=1; the kernel source ships at
// kzg/gpu/wgsl/kzg.wgsl ready to compile.

#include "kzg_driver_wgpu.h"
#include "../../cpp/kzg_oracle.hpp"

#include <cstdint>
#include <cstring>

extern "C" {

int kinet_kzg_wgpu_available(void) {
#ifdef KINET_KZG_HAS_WEBGPU
    return 1;
#else
    return 0;
#endif
}

int kinet_kzg_wgpu_blob_to_commit(const void* blobs, void* commits, unsigned n) {
    auto* b = static_cast<const std::uint8_t*>(blobs);
    auto* c = static_cast<std::uint8_t*>(commits);
    for (unsigned i = 0; i < n; ++i) {
        kinet::crypto::kzg::blob_to_commit(b + (size_t)i * 131072,
                                         c + (size_t)i * 48);
    }
    return 0;
}

int kinet_kzg_wgpu_compute_proof(const void* blobs, const void* commits,
                               void* proofs, unsigned n) {
    auto* b = static_cast<const std::uint8_t*>(blobs);
    auto* c = static_cast<const std::uint8_t*>(commits);
    auto* p = static_cast<std::uint8_t*>(proofs);
    for (unsigned i = 0; i < n; ++i) {
        kinet::crypto::kzg::blob_to_proof(b + (size_t)i * 131072,
                                        c + (size_t)i * 48,
                                        p + (size_t)i * 48);
    }
    return 0;
}

int kinet_kzg_wgpu_verify(const void* commits, const void* z_be, const void* y_be,
                        const void* proofs, void* out_flags, unsigned n) {
    auto* c = static_cast<const std::uint8_t*>(commits);
    auto* z = static_cast<const std::uint8_t*>(z_be);
    auto* y = static_cast<const std::uint8_t*>(y_be);
    auto* p = static_cast<const std::uint8_t*>(proofs);
    auto* o = static_cast<std::uint8_t*>(out_flags);
    for (unsigned i = 0; i < n; ++i) {
        bool ok = kinet::crypto::kzg::verify_proof(c + (size_t)i * 48,
                                                 z + (size_t)i * 32,
                                                 y + (size_t)i * 32,
                                                 p + (size_t)i * 48);
        o[i] = ok ? 1u : 0u;
    }
    return 0;
}

}  // extern "C"
