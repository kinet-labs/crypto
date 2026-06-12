// cevm: Fast Ethereum Virtual Machine implementation

#pragma once
#include <cstdint>
#include <span>

namespace cevm::crypto
{
/// Performs modular exponentiation (modexp) operation, which computes
/// (base^exp) % mod. Handles various sizes of inputs dynamically.
///
/// @param base The base in the modular exponentiation operation, represented
///             as a span of bytes in big-endian format. The maximum supported
///             input size is 1024 bytes.
/// @param exp  The exponent in the modular exponentiation operation,
///             represented as a span of bytes in big-endian format. Leading
///             zero bytes in the exponent are ignored.
/// @param mod  The modulus in the modular exponentiation operation, represented
///             as a span of bytes in big-endian format. The maximum supported
///             input size is 1024 bytes. The modulus must not be zero.
/// @param output Pointer to an output buffer where the result of the computation
///               is stored. The output size matches the size of the modulus to
///               ensure consistent representation in big-endian format.
void modexp(std::span<const uint8_t> base, std::span<const uint8_t> exp,
    std::span<const uint8_t> mod, uint8_t* output) noexcept;

/// Performs the same operation as modexp() but forces the Karatsuba-Montgomery
/// (SOS) inner loop for moduli ≥ 1024 bits. For smaller moduli the function
/// is byte-identical to modexp() since Karatsuba is not profitable below the
/// crossover.
///
/// Used by RSA-attestation lanes (SEV-SNP / TDX RSA-4096) where the base path
/// dominates work. Produces byte-identical output to modexp() for any input.
void modexp_karatsuba(std::span<const uint8_t> base, std::span<const uint8_t> exp,
    std::span<const uint8_t> mod, uint8_t* output) noexcept;
}  // namespace cevm::crypto
