// RIPEMD-160 (Dobbertin et al. 1996) compute shader in WGSL.
//
// One thread per input. Byte-equal to ripemd160/cpp/ripemd160.cpp::ripemd160(),
// ripemd160/gpu/cuda/ripemd160.cu::ripemd160_batch, and the Metal kernel.
//
// Two parallel "lines": z[0] uses f1..f5 with K0/R0/S0, z[1] uses f5..f1
// (mirrored function index 4 - round) with K1/R1/S1. Final mixdown
// interleaves the two lines back into the 5-word state.
//
// Padding: MD4-style — append 0x80 byte, zero-pad to 56 mod 64, append
// 64-bit little-endian bit length.

struct HashInput {
    offset: u32,
    length: u32,
}

@group(0) @binding(0) var<storage, read> inputs: array<HashInput>;
@group(0) @binding(1) var<storage, read> data: array<u32>;
@group(0) @binding(2) var<storage, read_write> outputs: array<u32>;

// Round added constants. K0 = left line, K1 = right line.
const K0 = array<u32, 5>(
    0x00000000u, 0x5a827999u, 0x6ed9eba1u, 0x8f1bbcdcu, 0xa953fd4eu
);
const K1 = array<u32, 5>(
    0x50a28be6u, 0x5c4dd124u, 0x6d703ef3u, 0x7a6d76e9u, 0x00000000u
);

// Message word selection (left).
const R0 = array<u32, 80>(
     0u,  1u,  2u,  3u,  4u,  5u,  6u,  7u,  8u,  9u, 10u, 11u, 12u, 13u, 14u, 15u,
     7u,  4u, 13u,  1u, 10u,  6u, 15u,  3u, 12u,  0u,  9u,  5u,  2u, 14u, 11u,  8u,
     3u, 10u, 14u,  4u,  9u, 15u,  8u,  1u,  2u,  7u,  0u,  6u, 13u, 11u,  5u, 12u,
     1u,  9u, 11u, 10u,  0u,  8u, 12u,  4u, 13u,  3u,  7u, 15u, 14u,  5u,  6u,  2u,
     4u,  0u,  5u,  9u,  7u, 12u,  2u, 10u, 14u,  1u,  3u,  8u, 11u,  6u, 15u, 13u
);

// Message word selection (right).
const R1 = array<u32, 80>(
     5u, 14u,  7u,  0u,  9u,  2u, 11u,  4u, 13u,  6u, 15u,  8u,  1u, 10u,  3u, 12u,
     6u, 11u,  3u,  7u,  0u, 13u,  5u, 10u, 14u, 15u,  8u, 12u,  4u,  9u,  1u,  2u,
    15u,  5u,  1u,  3u,  7u, 14u,  6u,  9u, 11u,  8u, 12u,  2u, 10u,  0u,  4u, 13u,
     8u,  6u,  4u,  1u,  3u, 11u, 15u,  0u,  5u, 12u,  2u, 13u,  9u,  7u, 10u, 14u,
    12u, 15u, 10u,  4u,  1u,  5u,  8u,  7u,  6u,  2u, 13u, 14u,  0u,  3u,  9u, 11u
);

// Rotation amounts (left).
const S0 = array<u32, 80>(
    11u, 14u, 15u, 12u,  5u,  8u,  7u,  9u, 11u, 13u, 14u, 15u,  6u,  7u,  9u,  8u,
     7u,  6u,  8u, 13u, 11u,  9u,  7u, 15u,  7u, 12u, 15u,  9u, 11u,  7u, 13u, 12u,
    11u, 13u,  6u,  7u, 14u,  9u, 13u, 15u, 14u,  8u, 13u,  6u,  5u, 12u,  7u,  5u,
    11u, 12u, 14u, 15u, 14u, 15u,  9u,  8u,  9u, 14u,  5u,  6u,  8u,  6u,  5u, 12u,
     9u, 15u,  5u, 11u,  6u,  8u, 13u, 12u,  5u, 12u, 13u, 14u, 11u,  8u,  5u,  6u
);

// Rotation amounts (right).
const S1 = array<u32, 80>(
     8u,  9u,  9u, 11u, 13u, 15u, 15u,  5u,  7u,  7u,  8u, 11u, 14u, 14u, 12u,  6u,
     9u, 13u, 15u,  7u, 12u,  8u,  9u, 11u,  7u,  7u, 12u,  7u,  6u, 15u, 13u, 11u,
     9u,  7u, 15u, 11u,  8u,  6u,  6u, 14u, 12u, 13u,  5u, 14u, 13u, 13u,  7u,  5u,
    15u,  5u,  8u, 11u, 14u, 14u,  6u, 14u,  6u,  9u, 12u,  9u, 12u,  5u, 15u,  8u,
     8u,  5u, 12u,  9u, 12u,  5u, 14u,  6u,  8u, 13u,  6u,  5u, 15u, 13u, 11u, 11u
);

fn rotl32(x: u32, n: u32) -> u32 {
    return (x << n) | (x >> (32u - n));
}

// Boolean selection functions (Dobbertin §3, eq. 1-5).
fn round_f(round_idx: u32, x: u32, y: u32, z: u32) -> u32 {
    if (round_idx == 0u) { return x ^ y ^ z; }                    // f1
    if (round_idx == 1u) { return ((y ^ z) & x) ^ z; }            // f2
    if (round_idx == 2u) { return (x | (~y)) ^ z; }               // f3
    if (round_idx == 3u) { return ((x ^ y) & z) ^ y; }            // f4
    return x ^ (y | (~z));                                         // f5
}

// Read a single byte from the packed u32 data array (little-endian).
fn read_byte(byte_offset: u32) -> u32 {
    let word_idx = byte_offset >> 2u;
    let byte_pos = byte_offset & 3u;
    return (data[word_idx] >> (byte_pos * 8u)) & 0xFFu;
}

// Per-thread scratch.
var<private> h: array<u32, 5>;
var<private> w: array<u32, 16>;
var<private> block: array<u32, 64>;  // u32 per byte for simplicity

fn compress() {
    var a0 = h[0]; var b0 = h[1]; var c0 = h[2]; var d0 = h[3]; var e0 = h[4];
    var a1 = h[0]; var b1 = h[1]; var c1 = h[2]; var d1 = h[3]; var e1 = h[4];

    for (var j = 0u; j < 80u; j = j + 1u) {
        let round_idx = j / 16u;

        // Left line.
        let t0 = rotl32(a0 + round_f(round_idx, b0, c0, d0)
                          + w[R0[j]] + K0[round_idx], S0[j]) + e0;
        a0 = e0; e0 = d0; d0 = rotl32(c0, 10u); c0 = b0; b0 = t0;

        // Right line.
        let inv_round = 4u - round_idx;
        let t1 = rotl32(a1 + round_f(inv_round, b1, c1, d1)
                          + w[R1[j]] + K1[round_idx], S1[j]) + e1;
        a1 = e1; e1 = d1; d1 = rotl32(c1, 10u); c1 = b1; b1 = t1;
    }

    let t = h[1] + c0 + d1;
    h[1] = h[2] + d0 + e1;
    h[2] = h[3] + e0 + a1;
    h[3] = h[4] + a0 + b1;
    h[4] = h[0] + b0 + c1;
    h[0] = t;
}

@compute @workgroup_size(64)
fn ripemd160_batch(@builtin(global_invocation_id) gid: vec3<u32>) {
    let tid = gid.x;
    let inp = inputs[tid];
    let offset = inp.offset;
    let len = inp.length;

    // IV.
    h[0] = 0x67452301u;
    h[1] = 0xefcdab89u;
    h[2] = 0x98badcfeu;
    h[3] = 0x10325476u;
    h[4] = 0xc3d2e1f0u;

    // Process full 64-byte blocks.
    var pos = 0u;
    for (; pos + 64u <= len; pos = pos + 64u) {
        for (var i = 0u; i < 16u; i = i + 1u) {
            let b0 = read_byte(offset + pos + i * 4u + 0u);
            let b1 = read_byte(offset + pos + i * 4u + 1u);
            let b2 = read_byte(offset + pos + i * 4u + 2u);
            let b3 = read_byte(offset + pos + i * 4u + 3u);
            w[i] = b0 | (b1 << 8u) | (b2 << 16u) | (b3 << 24u);
        }
        compress();
    }

    // Final block(s) with MD4-style padding. Use byte-granular scratch.
    let rem = len - pos;
    for (var i = 0u; i < 64u; i = i + 1u) {
        block[i] = 0u;
    }
    for (var i = 0u; i < rem; i = i + 1u) {
        block[i] = read_byte(offset + pos + i);
    }
    block[rem] = 0x80u;

    if (rem >= 56u) {
        // First final block: data + padding bit, no length yet.
        for (var i = 0u; i < 16u; i = i + 1u) {
            w[i] = block[i * 4u + 0u]
                 | (block[i * 4u + 1u] << 8u)
                 | (block[i * 4u + 2u] << 16u)
                 | (block[i * 4u + 3u] << 24u);
        }
        compress();
        for (var i = 0u; i < 64u; i = i + 1u) {
            block[i] = 0u;
        }
    }

    // Append 64-bit little-endian bit length.
    let bit_len_lo = len << 3u;                  // low 32 bits of len*8
    let bit_len_hi = len >> 29u;                 // high 32 bits of len*8
    block[56] = bit_len_lo & 0xFFu;
    block[57] = (bit_len_lo >> 8u) & 0xFFu;
    block[58] = (bit_len_lo >> 16u) & 0xFFu;
    block[59] = (bit_len_lo >> 24u) & 0xFFu;
    block[60] = bit_len_hi & 0xFFu;
    block[61] = (bit_len_hi >> 8u) & 0xFFu;
    block[62] = (bit_len_hi >> 16u) & 0xFFu;
    block[63] = (bit_len_hi >> 24u) & 0xFFu;

    for (var i = 0u; i < 16u; i = i + 1u) {
        w[i] = block[i * 4u + 0u]
             | (block[i * 4u + 1u] << 8u)
             | (block[i * 4u + 2u] << 16u)
             | (block[i * 4u + 3u] << 24u);
    }
    compress();

    // Emit 20-byte digest, packed into 5 u32 lanes (little-endian).
    let out_base = tid * 5u;
    outputs[out_base + 0u] = h[0];
    outputs[out_base + 1u] = h[1];
    outputs[out_base + 2u] = h[2];
    outputs[out_base + 3u] = h[3];
    outputs[out_base + 4u] = h[4];
}
