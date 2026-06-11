// =============================================================================
// kinet-labs/crypto/mldsa - ML-DSA (FIPS 204) C++ surface
// =============================================================================
//
// Thin wrappers over the PQClean reference implementation pulled via
// FetchContent from kinet-labs/pqclean (crypto_sign/ml-dsa-{44,65,87}/clean,
// CC0 / public domain).
//
// One function per (operation, parameter set). Parameter sets correspond to
// FIPS 204 NIST levels:
//   ml-dsa-44 -> NIST L2 (Dilithium2 in legacy spec)
//   ml-dsa-65 -> NIST L3 (Dilithium3)
//   ml-dsa-87 -> NIST L5 (Dilithium5)
//
// Buffer sizes for callers (FIPS 204 fixed):
//   ml-dsa-44 : pk=1312  sk=2560  sig<=2420
//   ml-dsa-65 : pk=1952  sk=4032  sig<=3309
//   ml-dsa-87 : pk=2592  sk=4896  sig<=4627
//
// =============================================================================

#ifndef KINET_CRYPTO_MLDSA_HPP
#define KINET_CRYPTO_MLDSA_HPP

#include <cstddef>
#include <cstdint>

namespace kinet::crypto::mldsa {

// Fixed sizes from FIPS 204.
constexpr std::size_t PK44 = 1312, SK44 = 2560, SIG44 = 2420;
constexpr std::size_t PK65 = 1952, SK65 = 4032, SIG65 = 3309;
constexpr std::size_t PK87 = 2592, SK87 = 4896, SIG87 = 4627;

// Keypair generation. Uses OS getentropy(3); seed argument unused (FIPS 204
// keygen consumes 32 bytes of fresh entropy internally via PQClean's
// randombytes hook). pk/sk buffers must be sized for the parameter set.
bool keypair_44(std::uint8_t* pk, std::uint8_t* sk);
bool keypair_65(std::uint8_t* pk, std::uint8_t* sk);
bool keypair_87(std::uint8_t* pk, std::uint8_t* sk);

// Detached signature. siglen is updated to the actual signature length
// (variable-length, bounded by SIG{44,65,87}).
bool sign_44(std::uint8_t* sig, std::size_t* siglen,
             const std::uint8_t* msg, std::size_t mlen,
             const std::uint8_t* sk);
bool sign_65(std::uint8_t* sig, std::size_t* siglen,
             const std::uint8_t* msg, std::size_t mlen,
             const std::uint8_t* sk);
bool sign_87(std::uint8_t* sig, std::size_t* siglen,
             const std::uint8_t* msg, std::size_t mlen,
             const std::uint8_t* sk);

// Detached verification. Returns true iff sig is a valid signature of msg
// under pk per FIPS 204.
bool verify_44(const std::uint8_t* sig, std::size_t siglen,
               const std::uint8_t* msg, std::size_t mlen,
               const std::uint8_t* pk);
bool verify_65(const std::uint8_t* sig, std::size_t siglen,
               const std::uint8_t* msg, std::size_t mlen,
               const std::uint8_t* pk);
bool verify_87(const std::uint8_t* sig, std::size_t siglen,
               const std::uint8_t* msg, std::size_t mlen,
               const std::uint8_t* pk);

}  // namespace kinet::crypto::mldsa

#endif  // KINET_CRYPTO_MLDSA_HPP
