/*
 * Fiat-Shamir transcript root.
 *
 * State is a Keccak-256 sponge:
 *   * init(domain_sep)          -- absorb the ASCII domain separator
 *   * append(data, n)           -- absorb data
 *   * finalize(out_root[32])    -- pad + squeeze 32 bytes
 *
 * State fits in 64 bytes (sponge state) + 8 bytes (offset), so 72 bytes total.
 * The packed struct is 256 bytes for forward extensibility.
 */
#ifndef KINET_GPUKIT_TRANSCRIPT_ROOT_H
#define KINET_GPUKIT_TRANSCRIPT_ROOT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct gpukit_transcript {
    uint8_t opaque[256];
} gpukit_transcript;

void gpukit_transcript_init_cpu(gpukit_transcript* t,
                                const char* domain_sep);
void gpukit_transcript_append_cpu(gpukit_transcript* t,
                                  const uint8_t* data, size_t n);
void gpukit_transcript_finalize_cpu(gpukit_transcript* t,
                                    uint8_t out_root[32]);

/* Convenience one-shot (init + append + finalize). */
void gpukit_transcript_root_cpu(const char* domain_sep,
                                const uint8_t* data, size_t n,
                                uint8_t out_root[32]);

int gpukit_transcript_root_metal(const char* domain_sep,
                                 const uint8_t* data, size_t n,
                                 uint8_t out_root[32]);
int gpukit_transcript_root_cuda(const char* domain_sep,
                                const uint8_t* data, size_t n,
                                uint8_t out_root[32]);
int gpukit_transcript_root_wgsl(const char* domain_sep,
                                const uint8_t* data, size_t n,
                                uint8_t out_root[32]);

#ifdef __cplusplus
}
#endif

#endif /* KINET_GPUKIT_TRANSCRIPT_ROOT_H */
