// =============================================================================
// kinet-labs/crypto/mlkem - C-ABI shim (FIPS 203)
// =============================================================================
// Dispatches mlkem_{keygen,encap,decap} into the vendored PQClean reference.
// mode in {2,3,5} selects FIPS 203 NIST level:
//   2 -> ML-KEM-512  (NIST L1)
//   3 -> ML-KEM-768  (NIST L3)
//   5 -> ML-KEM-1024 (NIST L5)
//
// =============================================================================

#include "kinet_crypto.h"

#include "../cpp/mlkem.hpp"

extern "C" int mlkem_keygen(int mode,
                            const uint8_t /*seed*/[32],
                            uint8_t* pk,
                            uint8_t* sk) {
    bool ok = false;
    switch (mode) {
        case 2: ok = kinet::crypto::mlkem::keypair_512(pk, sk);  break;
        case 3: ok = kinet::crypto::mlkem::keypair_768(pk, sk);  break;
        case 5: ok = kinet::crypto::mlkem::keypair_1024(pk, sk); break;
        default: return CRYPTO_ERR_INPUT;
    }
    return ok ? CRYPTO_OK : CRYPTO_ERR_INTERNAL;
}

extern "C" int mlkem_encap(int mode,
                           const uint8_t* pk,
                           uint8_t* ct,
                           uint8_t ss[32]) {
    bool ok = false;
    switch (mode) {
        case 2: ok = kinet::crypto::mlkem::encap_512(ct, ss, pk);  break;
        case 3: ok = kinet::crypto::mlkem::encap_768(ct, ss, pk);  break;
        case 5: ok = kinet::crypto::mlkem::encap_1024(ct, ss, pk); break;
        default: return CRYPTO_ERR_INPUT;
    }
    return ok ? CRYPTO_OK : CRYPTO_ERR_INTERNAL;
}

extern "C" int mlkem_decap(int mode,
                           const uint8_t* sk,
                           const uint8_t* ct,
                           uint8_t ss[32]) {
    bool ok = false;
    switch (mode) {
        case 2: ok = kinet::crypto::mlkem::decap_512(ss, ct, sk);  break;
        case 3: ok = kinet::crypto::mlkem::decap_768(ss, ct, sk);  break;
        case 5: ok = kinet::crypto::mlkem::decap_1024(ss, ct, sk); break;
        default: return CRYPTO_ERR_INPUT;
    }
    return ok ? CRYPTO_OK : CRYPTO_ERR_INTERNAL;
}
