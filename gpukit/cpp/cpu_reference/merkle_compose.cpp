// Parallel binary Merkle tree -- CPU reference. Keccak-256 inner hash.
//
// Layout: leaves are 32-byte values, consumed in input order. Tree is
// zero-padded to next-power-of-two with the all-zero leaf. Inner node:
//   keccak256( left || right )

#include "kinet/gpukit/merkle_compose.h"
#include "kinet/crypto/keccak.h"
#include <vector>
#include <cstring>

namespace {

inline size_t next_pow2(size_t n) {
    if (n <= 1) return 1;
    size_t p = 1;
    while (p < n) p <<= 1;
    return p;
}

}  // namespace

extern "C" void gpukit_merkle_root_cpu(const uint8_t* leaves, size_t n,
                                       uint8_t out_root[32]) {
    if (n == 0) {
        // Empty tree -> all-zero root by convention.
        std::memset(out_root, 0, 32);
        return;
    }
    size_t m = next_pow2(n);
    std::vector<uint8_t> layer(m * 32, 0);
    std::memcpy(layer.data(), leaves, n * 32);
    while (m > 1) {
        size_t half = m / 2;
        std::vector<uint8_t> next(half * 32, 0);
        for (size_t i = 0; i < half; ++i) {
            uint8_t buf[64];
            std::memcpy(buf,      layer.data() + (2*i + 0) * 32, 32);
            std::memcpy(buf + 32, layer.data() + (2*i + 1) * 32, 32);
            keccak256(buf, 64, next.data() + i * 32);
        }
        layer.swap(next);
        m = half;
    }
    std::memcpy(out_root, layer.data(), 32);
}
