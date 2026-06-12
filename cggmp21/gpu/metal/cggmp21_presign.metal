// CGGMP21 batched pre-signing kernel — Metal compute shader scaffold.
//
// Each thread = one (signer, slot) pair. The full body needs four big
// pieces and two of them are blocked on the 2048-bit modexp Karatsuba
// primitive that sits in modexp/cpp/karatsuba.hpp:
//
//   1. (k_i, gamma_i) ← HKDF-SHA256(seed, signer || slot)        DONE in CPU oracle
//   2. R_i = k_i * G   (secp256k1, compressed sec1)              DONE in CPU oracle
//   3. (K_i, G_cmt_i) = Paillier_enc(k_i || gamma_i)             BLOCKED on Karatsuba
//   4. Π^enc sigma proof (commitment + responses)                BLOCKED on Karatsuba
//
// The wire format is locked (PresignRecord). Once Karatsuba lands, this
// file fills in the bodies using the same {to_mont, fp_mul, mont_reduce}
// scalar arithmetic as frost_presign.metal — the secp256k1 path is a
// straight clone of frost_presign.metal::scalar_mul_base.
//
// Today the kernel writes a sentinel record (status = 0xFF) so the
// aggregator can exercise the wire format end-to-end while the body lands.
//
// GPU residency invariant. Same as FROST: nonces (k, gamma) live in
// thread address space; only the 33-byte R + Paillier ciphertext bytes
// land in commits_out. Verifiable via metallib-disassemble.

#include <metal_stdlib>
using namespace metal;

constant uint REC_SZ_FIXED = 33u + 512u + 512u + (512u + 32u + 256u + 256u + 32u) + 8u;
constant uint STATUS_OFFSET = 33u + 512u + 512u + (512u + 32u + 256u + 256u + 32u);

kernel void cggmp21_presign(
    constant uchar* seed         [[buffer(0)]],   // 32 bytes
    constant uint*  signer_ids   [[buffer(1)]],   // m entries
    constant uint&  m            [[buffer(2)]],
    constant uint&  slot_id_base [[buffer(3)]],
    constant uint&  n_slots      [[buffer(4)]],
    device   uchar* records_out  [[buffer(5)]],   // m*n_slots * REC_SZ
    uint            gid          [[thread_position_in_grid]])
{
    uint total = m * n_slots;
    if (gid >= total) return;

    uint signer_id = signer_ids[gid / n_slots];
    if (signer_id == 0u) return;

    (void)seed; (void)slot_id_base;

    device uchar* rec = records_out + (ulong)gid * (ulong)REC_SZ_FIXED;
    for (uint i = 0; i < REC_SZ_FIXED; ++i) rec[i] = 0;
    rec[STATUS_OFFSET] = 0xFF;
}
