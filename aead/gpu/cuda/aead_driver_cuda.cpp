// CUDA host driver for batched AEAD ciphers (ChaCha20-Poly1305 +
// AES-256-GCM). One dispatch per call; one thread per message.
//
// Build modes:
//   1. With CUDA toolkit (KINET_AEAD_HAVE_CUDA defined): launches the
//      first-party kernels in chacha20_poly1305.cu / aes_gcm.cu. Output is
//      byte-equal to kinet::crypto::aead::chacha20_poly1305::encrypt() and
//      kinet::crypto::aead::aes_256_gcm::encrypt() in cpp/aead.cpp.
//
//   2. Without CUDA (KINET_AEAD_HAVE_CUDA not defined): stubs return -1. The
//      determinism test prints a [skipped on Apple] banner. The CI runner
//      with a real CUDA device sets KINET_AEAD_HAVE_CUDA and exercises the
//      same byte-equality vectors used by the Metal harness.

#include "aead_driver_cuda.h"

#include <cstdint>
#include <cstring>

#ifdef KINET_AEAD_HAVE_CUDA
#include <cuda_runtime.h>

extern "C" {

struct AeadJob;

__global__ void chacha20_poly1305_jobs(
    const AeadJob* jobs,
    const uint8_t* keys,
    const uint8_t* nonces,
    const uint8_t* inputs_arena,
    uint8_t*       outputs_arena,
    uint32_t       n_jobs);

__global__ void aes_gcm_jobs(
    const AeadJob* jobs,
    const uint8_t* keys,
    const uint8_t* nonces,
    const uint8_t* inputs_arena,
    uint8_t*       outputs_arena,
    uint32_t       n_jobs);

}  // extern "C"

namespace {

constexpr unsigned kThreadsPerBlock = 64u;

unsigned grid_for(unsigned n) {
    return (n + kThreadsPerBlock - 1u) / kThreadsPerBlock;
}

// Common dispatch path: marshal host -> device, launch kernel, copy back.
// Returns 0 on success, negative on failure. Used for both ChaCha and AES.
template <typename Launcher>
int dispatch_aead(
    const uint8_t* keys,         size_t keys_bytes,    // n * 32
    const uint8_t* nonces,       size_t nonces_bytes,  // n * 12
    const uint8_t* inputs_arena, size_t inputs_bytes,
    const void*    jobs,         size_t jobs_bytes,
    uint8_t*       outputs,      size_t outputs_bytes,
    unsigned       n,
    Launcher       launch) {

    // Substitute a single non-empty byte for empty inputs_arena (CUDA
    // requires non-NULL for cudaMemcpy; matches Metal driver convention).
    static const uint8_t kEmpty = 0;
    const uint8_t* in_ptr = inputs_arena ? inputs_arena : &kEmpty;
    size_t in_len         = inputs_bytes > 0 ? inputs_bytes : 1;

    void *d_keys=nullptr, *d_nonces=nullptr, *d_in=nullptr, *d_jobs=nullptr,
         *d_out=nullptr;

    auto cleanup = [&]() {
        if (d_keys)   cudaFree(d_keys);
        if (d_nonces) cudaFree(d_nonces);
        if (d_in)     cudaFree(d_in);
        if (d_jobs)   cudaFree(d_jobs);
        if (d_out)    cudaFree(d_out);
    };

    if (cudaMalloc(&d_keys,   keys_bytes)   != cudaSuccess) { cleanup(); return -10; }
    if (cudaMalloc(&d_nonces, nonces_bytes) != cudaSuccess) { cleanup(); return -11; }
    if (cudaMalloc(&d_in,     in_len)       != cudaSuccess) { cleanup(); return -12; }
    if (cudaMalloc(&d_jobs,   jobs_bytes)   != cudaSuccess) { cleanup(); return -13; }
    if (cudaMalloc(&d_out,    outputs_bytes)!= cudaSuccess) { cleanup(); return -14; }

    if (cudaMemcpy(d_keys,   keys,   keys_bytes,   cudaMemcpyHostToDevice) != cudaSuccess) { cleanup(); return -20; }
    if (cudaMemcpy(d_nonces, nonces, nonces_bytes, cudaMemcpyHostToDevice) != cudaSuccess) { cleanup(); return -21; }
    if (cudaMemcpy(d_in,     in_ptr, in_len,       cudaMemcpyHostToDevice) != cudaSuccess) { cleanup(); return -22; }
    if (cudaMemcpy(d_jobs,   jobs,   jobs_bytes,   cudaMemcpyHostToDevice) != cudaSuccess) { cleanup(); return -23; }
    if (cudaMemset(d_out, 0, outputs_bytes) != cudaSuccess) { cleanup(); return -24; }

    launch(grid_for(n), kThreadsPerBlock,
           d_jobs, d_keys, d_nonces, d_in, d_out, n);

    if (cudaDeviceSynchronize() != cudaSuccess) { cleanup(); return -30; }
    if (cudaMemcpy(outputs, d_out, outputs_bytes, cudaMemcpyDeviceToHost) != cudaSuccess) { cleanup(); return -31; }

    cleanup();
    return 0;
}

}  // namespace

extern "C" {

int kinet_aead_cuda_available(void) {
    int count = 0;
    cudaError_t e = cudaGetDeviceCount(&count);
    return (e == cudaSuccess && count > 0) ? 1 : 0;
}

int aead_chacha20poly1305_batch_cuda(
    const uint8_t* keys,
    const uint8_t* nonces,
    const uint8_t* inputs_arena,
    size_t         inputs_arena_len,
    const void*    jobs,
    size_t         n,
    uint8_t*       outputs_arena,
    size_t         outputs_arena_len) {
    if (n == 0) return 0;
    if (!keys || !nonces || !jobs || !outputs_arena) return -1;
    if (!kinet_aead_cuda_available()) return -2;

    return dispatch_aead(
        keys,         n * 32,
        nonces,       n * 12,
        inputs_arena, inputs_arena_len,
        jobs,         n * 32,  // sizeof(AeadJob) = 8 * uint32_t = 32 bytes
        outputs_arena, outputs_arena_len,
        (unsigned)n,
        [](unsigned grid, unsigned tg,
           void* d_jobs, void* d_keys, void* d_nonces, void* d_in, void* d_out,
           unsigned n) {
            chacha20_poly1305_jobs<<<grid, tg>>>(
                static_cast<const AeadJob*>(d_jobs),
                static_cast<const uint8_t*>(d_keys),
                static_cast<const uint8_t*>(d_nonces),
                static_cast<const uint8_t*>(d_in),
                static_cast<uint8_t*>(d_out),
                n);
        });
}

int aead_aes_256_gcm_batch_cuda(
    const uint8_t* keys,
    const uint8_t* ivs,
    const uint8_t* inputs_arena,
    size_t         inputs_arena_len,
    const void*    jobs,
    size_t         n,
    uint8_t*       outputs_arena,
    size_t         outputs_arena_len) {
    if (n == 0) return 0;
    if (!keys || !ivs || !jobs || !outputs_arena) return -1;
    if (!kinet_aead_cuda_available()) return -2;

    return dispatch_aead(
        keys,         n * 32,
        ivs,          n * 12,
        inputs_arena, inputs_arena_len,
        jobs,         n * 32,
        outputs_arena, outputs_arena_len,
        (unsigned)n,
        [](unsigned grid, unsigned tg,
           void* d_jobs, void* d_keys, void* d_nonces, void* d_in, void* d_out,
           unsigned n) {
            aes_gcm_jobs<<<grid, tg>>>(
                static_cast<const AeadJob*>(d_jobs),
                static_cast<const uint8_t*>(d_keys),
                static_cast<const uint8_t*>(d_nonces),
                static_cast<const uint8_t*>(d_in),
                static_cast<uint8_t*>(d_out),
                n);
        });
}

}  // extern "C"

#else  // KINET_AEAD_HAVE_CUDA not defined: stub mode

extern "C" {

int kinet_aead_cuda_available(void) { return 0; }

int aead_chacha20poly1305_batch_cuda(
    const uint8_t*, const uint8_t*, const uint8_t*, size_t,
    const void*, size_t, uint8_t*, size_t) {
    return -1;
}

int aead_aes_256_gcm_batch_cuda(
    const uint8_t*, const uint8_t*, const uint8_t*, size_t,
    const void*, size_t, uint8_t*, size_t) {
    return -1;
}

}  // extern "C"

#endif  // KINET_AEAD_HAVE_CUDA
