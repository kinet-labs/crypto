// CGGMP21 batched pre-signing kernel — CPU canonical body (header).
//
// CGGMP21 (Canetti-Gennaro-Goldfeder-Makriyannis-Peled, eprint 2021/060) is a
// 4-round threshold ECDSA protocol with identifiable abort. The pre-signing
// phase ("auxiliary info + key refresh + presign") is local crypto only:
// every signer i computes a presignature record
//
//     R_i  = k_i * G                (secp256k1 commit, 33 bytes)
//     K_i  = Paillier_enc(N_i, k_i, rho_k)        (2 * BitsPaillier bits)
//     G_i  = Paillier_enc(N_i, gamma_i, rho_g)    (2 * BitsPaillier bits)
//
// where (k_i, gamma_i) ← F_n × F_n are sampled fresh per slot and
// (rho_k, rho_g) ← Z_{N_i}^* are sampled fresh per slot.
//
// Plus the matching range proofs (RFC 9591-equivalent ZK proofs):
//   * Π^enc  — proves K_i is well-formed (commitment + sigma response)
//   * Π^aff-g, Π^log-star — for round 2/3, but the round-1 batch only
//     emits Π^enc commitments here.
//
// Like FROST round-1, this entire phase is independent across (signer, slot)
// and across (party_id_for_zk_proof). One GPU kernel does M*N*P parallel
// jobs where P is the ZK-iteration count.
//
// === Batched contract (what the GPU kernel emits) ===
//
// Per slot, the kernel writes to device memory:
//
//   PresignRecord {
//     uint8_t R[33];               // k_i * G (compressed sec1)
//     uint8_t K[BITS_PAILLIER/4];  // Paillier ciphertext, big-endian
//     uint8_t G_cmt[BITS_PAILLIER/4]; // Paillier ciphertext, big-endian
//     uint8_t pi_enc[ZK_PI_ENC_BYTES];  // sigma proof commitment + response
//     uint8_t status;              // 0 = ok, 1..n = signer index that aborted
//   };
//
// Per slot, secrets stay in attested memory:
//
//   PresignSecret {
//     uint8_t k[32];               // k_i (mod n), big-endian
//     uint8_t gamma[32];           // gamma_i (mod n), big-endian
//     uint8_t rho_k[BITS_PAILLIER/8];   // Paillier blinding for K
//     uint8_t rho_g[BITS_PAILLIER/8];   // Paillier blinding for G
//     // ZK witnesses (alpha, beta, mu) live alongside.
//   };
//
// Identifiable abort: status field in the public record names the signer
// whose well-formedness check failed (Π^enc verify) — aggregator excludes
// that signer before the next round.
//
// === GPU residency ===
//
// Like FROST, every secret is in private/threadgroup memory. The Paillier
// modexp is the heaviest op: 2048-bit modexp at ~2 µs/exponent on M-series
// Metal vs ~50 µs on a single CPU core. Reuses modexp/cpp/karatsuba.hpp
// for the host body (the Karatsuba target paired with this work).
//
// === Status of this header (2026-04-28) ===
//
// The host body is implemented for the secp256k1 portion (R_i = k_i * G);
// the Paillier ciphertext + ZK proof generation are scaffolded to the
// contract pinned above and currently return CRYPTO_ERR_NOTIMPL until the
// kinet-labs/crypto Paillier primitive (modexp/cpp/karatsuba.hpp) lands an
// fp_modexp_2048 entry point. This file freezes the byte layout so the
// GPU kernel and the Go reference can cross-validate today.

#pragma once

#include <cstddef>
#include <cstdint>

namespace kinet::crypto::cggmp21 {

// Paillier modulus size in bits. Matches kinet/threshold params.BitsPaillier.
constexpr std::size_t BITS_PAILLIER       = 2048;
constexpr std::size_t PAILLIER_CTBYTES    = 2 * BITS_PAILLIER / 8;     // 512 bytes
constexpr std::size_t PAILLIER_BLINDBYTES = BITS_PAILLIER / 8;         // 256 bytes

// ZK proof Π^enc (zk/enc) sigma transcript: A commitment (G^alpha mod N^2)
// + e challenge (32 bytes) + (z1, z2, z3) responses. Layout pinned per
// CGGMP21 §6.1.
constexpr std::size_t ZK_PI_ENC_BYTES = PAILLIER_CTBYTES + 32 + PAILLIER_BLINDBYTES + PAILLIER_BLINDBYTES + 32;

struct PresignRecord {
    uint8_t R[33];                               // k_i * G
    uint8_t K[PAILLIER_CTBYTES];                 // Paillier_enc(k_i)
    uint8_t G_cmt[PAILLIER_CTBYTES];             // Paillier_enc(gamma_i)
    uint8_t pi_enc[ZK_PI_ENC_BYTES];             // sigma proof for K_i
    uint8_t status;                              // 0 ok, otherwise abort signer id
    uint8_t _pad[7];
};

// Secrets — never crosses the device boundary in a real deployment.
struct PresignSecret {
    uint8_t k[32];
    uint8_t gamma[32];
    uint8_t rho_k[PAILLIER_BLINDBYTES];
    uint8_t rho_g[PAILLIER_BLINDBYTES];
    // ZK witnesses
    uint8_t alpha[PAILLIER_BLINDBYTES];
    uint8_t mu[PAILLIER_BLINDBYTES];
};

// Per-signer Paillier setup (passed into batch by ctx).
struct PaillierKey {
    uint8_t N[PAILLIER_BLINDBYTES];   // public modulus N = p*q
    // N^2 (cached) — kernel input only, never re-derived on device
    uint8_t N_sq[PAILLIER_CTBYTES];
};

// Per-(signer, slot) presign. Returns 0 on ok; otherwise CRYPTO_ERR_NOTIMPL
// if the Paillier sub-step is unavailable, or -1 on input error.
//
// Currently the secp256k1 portion (R_i = k_i * G) is wired and byte-equal
// to the GPU kernel; Paillier + ZK proof emit zero bytes and a status of
// 0xFF (signaling "not implemented") that the aggregator must reject. This
// is the "scaffold" state — wire is fixed, the body fills as the Paillier
// primitive lands.
int presign_one(const uint8_t        seed[32],
                const PaillierKey&   pk,
                uint32_t             signer_id,
                uint32_t             slot_id,
                PresignRecord&       record_out,
                PresignSecret&       secret_out) noexcept;

// Batched: M signers × N slots, signer-major.
int presign_batch(const uint8_t            seed[32],
                  const PaillierKey*       pks,            // m entries
                  const uint32_t*          signer_ids,     // m entries
                  uint32_t                 m,
                  uint32_t                 slot_id_base,
                  uint32_t                 n_slots,
                  PresignRecord*           records_out,    // m*n entries
                  PresignSecret*           secrets_out)    // m*n entries
                  noexcept;

}  // namespace kinet::crypto::cggmp21
