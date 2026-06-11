// Public C surface for the Lamport-SHA256 Metal driver. The driver hashes a
// flat array of 32-byte preimages with FIPS 180-4 padding, byte-equal to
// lamport/cpp/lamport.cpp.

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// One thread per slot. `slots` and `digests` are flat arenas of size
/// num_slots * 32 bytes. Returns 0 on success, negative on failure.
int lamport_hash_batch_metal(
    const uint8_t* slots,
    size_t num_slots,
    uint8_t*       digests,
    const char*    metallib_path);

#ifdef __cplusplus
}
#endif
