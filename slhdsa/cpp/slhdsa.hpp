// =============================================================================
// kinet-labs/crypto/slhdsa - SLH-DSA (FIPS 205) C++ surface
// =============================================================================
//
// Thin wrappers over the vendored PQClean reference implementations
// (cpp/pqclean/sphincs-{sha2,shake}-{128,192,256}f-simple/, CC0 / public
// domain). Six 'f' (fast) parameter sets ship; the 's' (small) variants are
// out of scope for the initial port.
//
// FIPS 205 NIST levels:
//   128f -> NIST L1
//   192f -> NIST L3
//   256f -> NIST L5
// SHA2/SHAKE selects the inner hash family (per the FIPS 205 §10 parameter
// catalogue). SLH-DSA-SHA2 instantiates the WOTS+ chains and Merkle trees
// with SHA-256 / SHA-512; SLH-DSA-SHAKE uses SHAKE-256.
//
// Buffer sizes (FIPS 205 fixed, identical between SHA2 and SHAKE for the
// same security level):
//   128f : pk=32   sk=64    sig=17088
//   192f : pk=48   sk=96    sig=35664
//   256f : pk=64   sk=128   sig=49856
//
// =============================================================================

#ifndef CRYPTO_SLHDSA_HPP
#define CRYPTO_SLHDSA_HPP

#include <cstddef>
#include <cstdint>

namespace kinet::crypto::slhdsa {

constexpr std::size_t PK_128 = 32, SK_128 = 64,  SIG_128 = 17088;
constexpr std::size_t PK_192 = 48, SK_192 = 96,  SIG_192 = 35664;
constexpr std::size_t PK_256 = 64, SK_256 = 128, SIG_256 = 49856;

// SHA2 family (NIST L1 / L3 / L5).
bool keypair_sha2_128f(std::uint8_t* pk, std::uint8_t* sk);
bool keypair_sha2_192f(std::uint8_t* pk, std::uint8_t* sk);
bool keypair_sha2_256f(std::uint8_t* pk, std::uint8_t* sk);

bool sign_sha2_128f(std::uint8_t* sig, std::size_t* siglen,
                    const std::uint8_t* msg, std::size_t mlen,
                    const std::uint8_t* sk);
bool sign_sha2_192f(std::uint8_t* sig, std::size_t* siglen,
                    const std::uint8_t* msg, std::size_t mlen,
                    const std::uint8_t* sk);
bool sign_sha2_256f(std::uint8_t* sig, std::size_t* siglen,
                    const std::uint8_t* msg, std::size_t mlen,
                    const std::uint8_t* sk);

bool verify_sha2_128f(const std::uint8_t* sig, std::size_t siglen,
                      const std::uint8_t* msg, std::size_t mlen,
                      const std::uint8_t* pk);
bool verify_sha2_192f(const std::uint8_t* sig, std::size_t siglen,
                      const std::uint8_t* msg, std::size_t mlen,
                      const std::uint8_t* pk);
bool verify_sha2_256f(const std::uint8_t* sig, std::size_t siglen,
                      const std::uint8_t* msg, std::size_t mlen,
                      const std::uint8_t* pk);

// SHAKE family (NIST L1 / L3 / L5).
bool keypair_shake_128f(std::uint8_t* pk, std::uint8_t* sk);
bool keypair_shake_192f(std::uint8_t* pk, std::uint8_t* sk);
bool keypair_shake_256f(std::uint8_t* pk, std::uint8_t* sk);

bool sign_shake_128f(std::uint8_t* sig, std::size_t* siglen,
                     const std::uint8_t* msg, std::size_t mlen,
                     const std::uint8_t* sk);
bool sign_shake_192f(std::uint8_t* sig, std::size_t* siglen,
                     const std::uint8_t* msg, std::size_t mlen,
                     const std::uint8_t* sk);
bool sign_shake_256f(std::uint8_t* sig, std::size_t* siglen,
                     const std::uint8_t* msg, std::size_t mlen,
                     const std::uint8_t* sk);

bool verify_shake_128f(const std::uint8_t* sig, std::size_t siglen,
                       const std::uint8_t* msg, std::size_t mlen,
                       const std::uint8_t* pk);
bool verify_shake_192f(const std::uint8_t* sig, std::size_t siglen,
                       const std::uint8_t* msg, std::size_t mlen,
                       const std::uint8_t* pk);
bool verify_shake_256f(const std::uint8_t* sig, std::size_t siglen,
                       const std::uint8_t* msg, std::size_t mlen,
                       const std::uint8_t* pk);

}  // namespace kinet::crypto::slhdsa

#endif  // CRYPTO_SLHDSA_HPP
