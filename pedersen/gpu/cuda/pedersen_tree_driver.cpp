// CUDA host driver for the tree-reduce Pedersen vector commitment.

#include "pedersen_tree_driver.h"

#include <cstdint>
#include <cstring>

#ifdef KINET_PEDERSEN_HAVE_CUDA
#include <cuda_runtime.h>

struct PedTreeDimsHost { uint32_t M; uint32_t N; };

extern "C" __global__ void k_pedersen_tree_commit(
    const uint8_t*, const uint8_t*, const uint8_t*,
    uint8_t*, PedTreeDimsHost);

extern "C" int kinet_pedersen_tree_cuda_available(void) {
    int count = 0;
    cudaError_t e = cudaGetDeviceCount(&count);
    return (e == cudaSuccess && count > 0) ? 1 : 0;
}

extern "C" int pedersen_tree_cuda(
    const uint8_t* gens_be,
    const uint8_t* scalars_be,
    const uint8_t* blindings_be,
    uint32_t       M,
    uint8_t*       out_be) {
    if (M == 0) return 0;
    if (!gens_be || !scalars_be || !blindings_be || !out_be) return -1;
    if (!kinet_pedersen_tree_cuda_available()) return -1;

    const uint32_t N = PEDERSEN_TREE_WIDTH;
    size_t gens_len    = (size_t)(N + 1) * 64;
    size_t scalars_len = (size_t)M * N * 32;
    size_t blind_len   = (size_t)M * 32;
    size_t out_len     = (size_t)M * 64;

    uint8_t  *dGens=nullptr, *dScalars=nullptr, *dBlind=nullptr, *dOut=nullptr;

    auto cleanup = [&]() {
        if (dGens)    cudaFree(dGens);
        if (dScalars) cudaFree(dScalars);
        if (dBlind)   cudaFree(dBlind);
        if (dOut)     cudaFree(dOut);
    };

    if (cudaMalloc((void**)&dGens,    gens_len)    != cudaSuccess) { cleanup(); return -2; }
    if (cudaMalloc((void**)&dScalars, scalars_len) != cudaSuccess) { cleanup(); return -2; }
    if (cudaMalloc((void**)&dBlind,   blind_len)   != cudaSuccess) { cleanup(); return -2; }
    if (cudaMalloc((void**)&dOut,     out_len)     != cudaSuccess) { cleanup(); return -2; }

    cudaMemcpy(dGens,    gens_be,      gens_len,    cudaMemcpyHostToDevice);
    cudaMemcpy(dScalars, scalars_be,   scalars_len, cudaMemcpyHostToDevice);
    cudaMemcpy(dBlind,   blindings_be, blind_len,   cudaMemcpyHostToDevice);

    PedTreeDimsHost dims{ M, N };

    // M blocks of 256 threads each. Single dispatch: log_2 N round-trips
    // collapse into one shared-memory reduction.
    k_pedersen_tree_commit<<<M, N>>>(dGens, dScalars, dBlind, dOut, dims);
    if (cudaDeviceSynchronize() != cudaSuccess) { cleanup(); return -3; }

    cudaMemcpy(out_be, dOut, out_len, cudaMemcpyDeviceToHost);
    cleanup();
    return 0;
}

#else // KINET_PEDERSEN_HAVE_CUDA not defined: stub mode

extern "C" int kinet_pedersen_tree_cuda_available(void) { return 0; }

extern "C" int pedersen_tree_cuda(
    const uint8_t*, const uint8_t*, const uint8_t*,
    uint32_t, uint8_t*) {
    return -1;
}

#endif
