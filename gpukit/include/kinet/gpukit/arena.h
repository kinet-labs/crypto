/*
 * Linear arena allocator. Used by GPU drivers to pack staging buffers without
 * malloc churn. CPU-only -- GPU buffers are allocated by the per-backend driver.
 */
#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct gpukit_arena {
    uint8_t* base;
    size_t   capacity;
    size_t   offset;
} gpukit_arena;

static inline void gpukit_arena_init(gpukit_arena* a, void* base, size_t cap) {
    a->base = (uint8_t*)base;
    a->capacity = cap;
    a->offset = 0;
}

static inline void* gpukit_arena_alloc(gpukit_arena* a, size_t n, size_t align) {
    size_t mask = align ? (align - 1) : 0;
    size_t off = (a->offset + mask) & ~mask;
    if (off + n > a->capacity) return 0;
    a->offset = off + n;
    return a->base + off;
}

static inline void gpukit_arena_reset(gpukit_arena* a) {
    a->offset = 0;
}

#ifdef __cplusplus
}
#endif
