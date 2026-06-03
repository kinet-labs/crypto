// =============================================================================
// blake2b_full - full BLAKE2b hash on top of cevm's compression function
// =============================================================================
// cevm/crypto only ships blake2b_compress (the F function used by EIP-152).
// This file wraps it in the standard BLAKE2b construction (RFC 7693) so that
// kinet_blake2b can produce a 64-byte digest of an arbitrary message.
// =============================================================================
#pragma once
#include <cstddef>
#include <cstdint>

namespace kinet::crypto::blake2b {

/// Compute a BLAKE2b-512 digest. RFC 7693, no key, no salt, no personalisation.
void hash(const uint8_t* in, size_t in_len, uint8_t out[64]) noexcept;

}  // namespace kinet::crypto::blake2b
