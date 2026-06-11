// SHA-256 (FIPS 180-4) compute shader in WGSL.
//
// One thread per input. Each thread reads its (offset, length) descriptor,
// processes 64-byte blocks through the canonical 64-round compression
// function, then emits a 32-byte big-endian digest. Padding is canonical
// (FIPS 180-4 §5.1.1): append 0x80, zero pad to 64 mod 56, append 8-byte
// big-endian bit length.
//
// Byte-equal to sha256/cpp/sha256.cpp and sha256/gpu/cuda/sha256.cu and
// sha256/gpu/metal/sha256_batch.metal.

struct HashInput {
    offset: u32,
    length: u32,
}

@group(0) @binding(0) var<storage, read>       inputs:  array<HashInput>;
@group(0) @binding(1) var<storage, read>       data:    array<u32>;
@group(0) @binding(2) var<storage, read_write> outputs: array<u32>;

// FIPS 180-4 round constants (§4.2.2).
const K = array<u32, 64>(
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
);

fn rotr32(x: u32, n: u32) -> u32 {
    return (x >> n) | (x << (32u - n));
}

// Read a single byte from the packed u32 input arena (little-endian packing).
fn read_byte(byte_offset: u32) -> u32 {
    let word_idx = byte_offset >> 2u;
    let byte_pos = byte_offset & 3u;
    return (data[word_idx] >> (byte_pos * 8u)) & 0xFFu;
}

// Process one 64-byte block: build big-endian-encoded message schedule,
// run the 64-round compression, accumulate into h[0..7].
fn sha256_block(block: ptr<function, array<u32, 64>>, h: ptr<function, array<u32, 8>>) {
    var w: array<u32, 64>;
    for (var i = 0u; i < 16u; i = i + 1u) {
        w[i] = (*block)[i];
    }
    for (var i = 16u; i < 64u; i = i + 1u) {
        let s0 = rotr32(w[i - 15u], 7u) ^ rotr32(w[i - 15u], 18u) ^ (w[i - 15u] >> 3u);
        let s1 = rotr32(w[i -  2u], 17u) ^ rotr32(w[i -  2u], 19u) ^ (w[i -  2u] >> 10u);
        w[i] = w[i - 16u] + s0 + w[i - 7u] + s1;
    }

    var a: u32 = (*h)[0];
    var b: u32 = (*h)[1];
    var c: u32 = (*h)[2];
    var d: u32 = (*h)[3];
    var e: u32 = (*h)[4];
    var f: u32 = (*h)[5];
    var g: u32 = (*h)[6];
    var hh: u32 = (*h)[7];

    for (var i = 0u; i < 64u; i = i + 1u) {
        let S1 = rotr32(e, 6u) ^ rotr32(e, 11u) ^ rotr32(e, 25u);
        let ch = (e & f) ^ ((~e) & g);
        let t1 = hh + S1 + ch + K[i] + w[i];
        let S0 = rotr32(a, 2u) ^ rotr32(a, 13u) ^ rotr32(a, 22u);
        let mj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = S0 + mj;
        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    (*h)[0] = (*h)[0] + a;
    (*h)[1] = (*h)[1] + b;
    (*h)[2] = (*h)[2] + c;
    (*h)[3] = (*h)[3] + d;
    (*h)[4] = (*h)[4] + e;
    (*h)[5] = (*h)[5] + f;
    (*h)[6] = (*h)[6] + g;
    (*h)[7] = (*h)[7] + hh;
}

// Build the i-th big-endian message word from `block_offset` byte position.
fn be_word(block_offset: u32) -> u32 {
    let b0 = read_byte(block_offset + 0u);
    let b1 = read_byte(block_offset + 1u);
    let b2 = read_byte(block_offset + 2u);
    let b3 = read_byte(block_offset + 3u);
    return (b0 << 24u) | (b1 << 16u) | (b2 << 8u) | b3;
}

@compute @workgroup_size(64)
fn sha256_jobs(@builtin(global_invocation_id) gid: vec3<u32>) {
    let tid = gid.x;
    if (tid >= arrayLength(&inputs)) {
        return;
    }
    let inp = inputs[tid];
    let offset = inp.offset;
    let len = inp.length;

    // FIPS 180-4 IV (§5.3.3).
    var h: array<u32, 8> = array<u32, 8>(
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
    );

    // Process full 64-byte blocks.
    var absorbed: u32 = 0u;
    var block: array<u32, 64>;
    loop {
        if (len - absorbed < 64u) { break; }
        for (var i = 0u; i < 16u; i = i + 1u) {
            block[i] = be_word(offset + absorbed + i * 4u);
        }
        sha256_block(&block, &h);
        absorbed = absorbed + 64u;
    }

    // Build final-block byte buffer (we use a u32[16] view written
    // big-endian directly).
    var pad_bytes: array<u32, 64>;     // each entry holds one byte (0..255)
    for (var i = 0u; i < 64u; i = i + 1u) {
        pad_bytes[i] = 0u;
    }
    let rem = len - absorbed;
    for (var i = 0u; i < rem; i = i + 1u) {
        pad_bytes[i] = read_byte(offset + absorbed + i);
    }
    pad_bytes[rem] = 0x80u;

    // If the tail spans two final blocks, hash the first now and zero
    // pad_bytes for the second pass.
    if (rem >= 56u) {
        for (var i = 0u; i < 16u; i = i + 1u) {
            block[i] = (pad_bytes[i * 4u + 0u] << 24u)
                     | (pad_bytes[i * 4u + 1u] << 16u)
                     | (pad_bytes[i * 4u + 2u] <<  8u)
                     |  pad_bytes[i * 4u + 3u];
        }
        sha256_block(&block, &h);
        for (var i = 0u; i < 64u; i = i + 1u) {
            pad_bytes[i] = 0u;
        }
    }

    // Append 64-bit big-endian bit length in the trailing 8 bytes.
    let bit_len_lo: u32 = len << 3u;
    let bit_len_hi: u32 = len >> 29u;  // upper 32 bits of (len * 8)
    pad_bytes[56] = (bit_len_hi >> 24u) & 0xFFu;
    pad_bytes[57] = (bit_len_hi >> 16u) & 0xFFu;
    pad_bytes[58] = (bit_len_hi >>  8u) & 0xFFu;
    pad_bytes[59] =  bit_len_hi         & 0xFFu;
    pad_bytes[60] = (bit_len_lo >> 24u) & 0xFFu;
    pad_bytes[61] = (bit_len_lo >> 16u) & 0xFFu;
    pad_bytes[62] = (bit_len_lo >>  8u) & 0xFFu;
    pad_bytes[63] =  bit_len_lo         & 0xFFu;

    for (var i = 0u; i < 16u; i = i + 1u) {
        block[i] = (pad_bytes[i * 4u + 0u] << 24u)
                 | (pad_bytes[i * 4u + 1u] << 16u)
                 | (pad_bytes[i * 4u + 2u] <<  8u)
                 |  pad_bytes[i * 4u + 3u];
    }
    sha256_block(&block, &h);

    // Emit 32-byte big-endian digest. Each lane is one big-endian u32; in the
    // outputs buffer we still store little-endian-packed u32 so the host can
    // read bytes back in canonical order. We pack each big-endian word as
    // bytes and stuff them into outputs[i * 8 .. i * 8 + 8] little-endian.
    let out_base = tid * 8u;
    for (var i = 0u; i < 8u; i = i + 1u) {
        let v = h[i];
        let b0: u32 = (v >> 24u) & 0xFFu;
        let b1: u32 = (v >> 16u) & 0xFFu;
        let b2: u32 = (v >>  8u) & 0xFFu;
        let b3: u32 =  v         & 0xFFu;
        // outputs is a u32 array packed little-endian: byte0 = low byte.
        outputs[out_base + i] = b0 | (b1 << 8u) | (b2 << 16u) | (b3 << 24u);
    }
}
