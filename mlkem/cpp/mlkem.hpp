// =============================================================================
// kinet-labs/crypto/mlkem - ML-KEM (FIPS 203) C++ surface
// =============================================================================
//
// Thin wrappers over the PQClean reference implementation pulled via
// FetchContent from kinet-labs/pqclean (crypto_kem/ml-kem-{512,768,1024}/clean,
// CC0 / public domain).
//
// FIPS 203 NIST levels:
//   ml-kem-512  -> NIST L1 (Kyber512 in legacy spec)
//   ml-kem-768  -> NIST L3 (Kyber768)
//   ml-kem-1024 -> NIST L5 (Kyber1024)
//
// Buffer sizes:
//   ml-kem-512  : pk=800   sk=1632  ct=768   ss=32
//   ml-kem-768  : pk=1184  sk=2400  ct=1088  ss=32
//   ml-kem-1024 : pk=1568  sk=3168  ct=1568  ss=32
//
// =============================================================================

#ifndef CRYPTO_MLKEM_HPP
#define CRYPTO_MLKEM_HPP

#include <cstddef>
#include <cstdint>

namespace kinet::crypto::mlkem {

constexpr std::size_t PK512  = 800,  SK512  = 1632, CT512  = 768,  SS = 32;
constexpr std::size_t PK768  = 1184, SK768  = 2400, CT768  = 1088;
constexpr std::size_t PK1024 = 1568, SK1024 = 3168, CT1024 = 1568;

bool keypair_512 (std::uint8_t* pk, std::uint8_t* sk);
bool keypair_768 (std::uint8_t* pk, std::uint8_t* sk);
bool keypair_1024(std::uint8_t* pk, std::uint8_t* sk);

bool encap_512 (std::uint8_t* ct, std::uint8_t* ss, const std::uint8_t* pk);
bool encap_768 (std::uint8_t* ct, std::uint8_t* ss, const std::uint8_t* pk);
bool encap_1024(std::uint8_t* ct, std::uint8_t* ss, const std::uint8_t* pk);

bool decap_512 (std::uint8_t* ss, const std::uint8_t* ct, const std::uint8_t* sk);
bool decap_768 (std::uint8_t* ss, const std::uint8_t* ct, const std::uint8_t* sk);
bool decap_1024(std::uint8_t* ss, const std::uint8_t* ct, const std::uint8_t* sk);

}  // namespace kinet::crypto::mlkem

#endif  // CRYPTO_MLKEM_HPP
