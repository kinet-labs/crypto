// CUDA host driver for Stage A (Montgomery batch inversion) of the v0.63
// ecrecover pipeline. Mirrors gpu/metal/secp256k1_batch_inv_driver.mm.
//
// Entry point matches the Metal driver's signature shape: byte buffers in
// Mont form (limb little-endian), kind = 0 for Fp / 1 for Fn. The CUDA
// "metallib_path" slot is ignored (kept in API for symmetry with future
// PTX-from-cubin loading); kernels are statically linked.
//
// On hosts without nvcc, this TU compiles as plain C++ and the launcher
// returns the NOTIMPL sentinel from secp256k1_batch_inv.cu.

#include <cstddef>
#include <cstdint>

extern "C" int cuda_secp256k1_batch_inv_launch(
    const uint8_t* in_mont, size_t n, uint8_t* out_mont, int kind);

// Public entry point; signature mirrors secp256k1_batch_inv_metal so the test
// harness can swap drivers by recompile.
extern "C" int cuda_secp256k1_batch_inv(
    const uint8_t* in_mont,    // n * 32 bytes (Mont-form, limb little-endian)
    size_t         n,
    uint8_t*       out_mont,   // n * 32 bytes
    int            kind,       // 0 = Fp, 1 = Fn
    const char*    /*unused_path*/) {
    return cuda_secp256k1_batch_inv_launch(in_mont, n, out_mont, kind);
}
