// Ed25519 host CPU implementation. Wraps ed25519-donna (vendored under
// cpp/ed25519-donna/) and exposes the kinet::crypto::ed25519 API.
//
// Strategy: include the upstream `ed25519.c` translation unit directly,
// pre-loaded with our compile-time switches:
//   ED25519_CUSTOMHASH      => use cpp/ed25519-donna/ed25519-hash-custom.h
//   ED25519_CUSTOMRANDOM    => use cpp/ed25519-donna/ed25519-randombytes-custom.h
//   ED25519_NO_INLINE_ASM   => skip x86 inline-asm choose-niels (works on ARM64)
//   ED25519_SUFFIX=_donna   => upstream symbols become *_donna so the wrapper
//                              namespace owns the public surface.
//
// All upstream code stays unmodified inside cpp/ed25519-donna/.

#include "ed25519.hpp"

// ----- ed25519-donna compile switches ---------------------------------------
#define ED25519_CUSTOMHASH 1
#define ED25519_CUSTOMRANDOM 1
#define ED25519_NO_INLINE_ASM 1
#define ED25519_SUFFIX _donna

// ----- Upstream translation unit -------------------------------------------
// ed25519.c is plain C; bring it into this C++ TU via include. The wrapping
// extern "C" gives the symbols C linkage even though the file is compiled
// as C++ (clang/gcc both accept this; no language-level constructs in the
// upstream code rely on C-only semantics).
extern "C" {
#include "ed25519-donna/ed25519.c"
}

// ----- Forward declarations of upstream entry points ------------------------
extern "C" {
void ed25519_publickey_donna   (const uint8_t sk[32], uint8_t pk[32]);
void ed25519_sign_donna        (const uint8_t* m, std::size_t mlen,
                                 const uint8_t sk[32], const uint8_t pk[32],
                                 uint8_t RS[64]);
int  ed25519_sign_open_donna   (const uint8_t* m, std::size_t mlen,
                                 const uint8_t pk[32], const uint8_t RS[64]);
int  ed25519_sign_open_batch_donna(const uint8_t** m, std::size_t* mlen,
                                    const uint8_t** pk, const uint8_t** RS,
                                    std::size_t num, int* valid);
}

namespace kinet::crypto::ed25519 {

void keygen(uint8_t pk[32], uint8_t sk[64], const uint8_t seed[32]) {
    // sk layout: [0..32) = seed, [32..64) = pk (NaCl convention).
    for (int i = 0; i < 32; ++i) sk[i] = seed[i];
    ed25519_publickey_donna(seed, pk);
    for (int i = 0; i < 32; ++i) sk[32 + i] = pk[i];
}

void sign(uint8_t       sig[64],
          const uint8_t* msg, std::size_t msg_len,
          const uint8_t pk[32],
          const uint8_t sk[64]) {
    // Upstream ed25519_sign reads only sk[0..32) (the seed) and pk.
    ed25519_sign_donna(msg, msg_len, sk, pk, sig);
}

bool verify(const uint8_t* msg, std::size_t msg_len,
            const uint8_t sig[64],
            const uint8_t pk[32]) {
    return ed25519_sign_open_donna(msg, msg_len, pk, sig) == 0;
}

bool batch_verify(std::size_t          n,
                  const uint8_t* const* msgs,
                  const std::size_t*    msg_lens,
                  const uint8_t* const* sigs,
                  const uint8_t* const* pks) {
    if (n == 0) return true;

    // The upstream API takes mutable double-pointers but does not modify
    // them; cast away const at the API boundary, never inside the impl.
    const uint8_t** m_in   = const_cast<const uint8_t**>(msgs);
    const uint8_t** sig_in = const_cast<const uint8_t**>(sigs);
    const uint8_t** pk_in  = const_cast<const uint8_t**>(pks);

    // ed25519-donna's sign_open_batch wants a mutable mlen array; copy.
    // Stack-allocate up to 256 entries, fall back to heap above that.
    constexpr std::size_t kStackLimit = 256;
    std::size_t  small[kStackLimit];
    std::size_t* lens = (n <= kStackLimit) ? small : new std::size_t[n];
    for (std::size_t i = 0; i < n; ++i) lens[i] = msg_lens[i];

    // valid[] receives 1/0 per signature; we only need the aggregate result
    // ("did all verify"). The function returns 0 if all valid, 1 otherwise.
    int  small_valid[kStackLimit];
    int* valid = (n <= kStackLimit) ? small_valid : new int[n];

    int rc = ed25519_sign_open_batch_donna(m_in, lens, pk_in, sig_in, n, valid);

    if (lens  != small)       delete[] lens;
    if (valid != small_valid) delete[] valid;

    return rc == 0;
}

} // namespace kinet::crypto::ed25519
