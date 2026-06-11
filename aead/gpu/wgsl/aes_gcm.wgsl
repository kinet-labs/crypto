// Batched AES-256-GCM (NIST SP 800-38D, 96-bit IV) compute shader.
// One thread per (key, iv, aad, plaintext) message; output is byte-equal
// to kinet::crypto::aead::aes_256_gcm::encrypt() in cpp/aead.cpp and to
// gpu/metal/aes_gcm.metal.
//
// WGSL has no u8: byte arrays are packed into u32 storage buffers
// (LSB-first within each word). Constant-time S-box (Boyar-Peralta) and
// constant-time GHASH (128 iters) are preserved.

struct AeadJob {
    aad_offset:   u32,
    aad_len:      u32,
    pt_offset:    u32,
    pt_len:       u32,
    ct_offset:    u32,
    tag_offset:   u32,
    key_offset:   u32,    // i*32
    nonce_offset: u32,    // i*12
}

struct Params {
    n_jobs: u32,
    _pad0:  u32,
    _pad1:  u32,
    _pad2:  u32,
}

@group(0) @binding(0) var<storage, read>       jobs:    array<AeadJob>;
@group(0) @binding(1) var<storage, read>       keys:    array<u32>;
@group(0) @binding(2) var<storage, read>       nonces:  array<u32>;
@group(0) @binding(3) var<storage, read>       inputs:  array<u32>;
@group(0) @binding(4) var<storage, read_write> outputs: array<u32>;
@group(0) @binding(5) var<uniform>             params:  Params;

// ---- Byte access ---------------------------------------------------------

fn rd_in(byte_off: u32) -> u32 {
    let w = byte_off >> 2u;
    let s = (byte_off & 3u) * 8u;
    return (inputs[w] >> s) & 0xffu;
}
fn rd_out(byte_off: u32) -> u32 {
    let w = byte_off >> 2u;
    let s = (byte_off & 3u) * 8u;
    return (outputs[w] >> s) & 0xffu;
}
fn wr_out(byte_off: u32, v: u32) {
    let w = byte_off >> 2u;
    let s = (byte_off & 3u) * 8u;
    let mask = 0xffu << s;
    outputs[w] = (outputs[w] & ~mask) | ((v & 0xffu) << s);
}
fn rd_msg(arena: u32, byte_off: u32) -> u32 {
    if (arena == 0u) { return rd_in(byte_off); }
    return rd_out(byte_off);
}

fn rd_key_byte(key_byte_off: u32, i: u32) -> u32 {
    let abs = key_byte_off + i;
    let w = abs >> 2u;
    let s = (abs & 3u) * 8u;
    return (keys[w] >> s) & 0xffu;
}
fn rd_iv_byte(nonce_byte_off: u32, i: u32) -> u32 {
    let abs = nonce_byte_off + i;
    let w = abs >> 2u;
    let s = (abs & 3u) * 8u;
    return (nonces[w] >> s) & 0xffu;
}

// ---- AES S-box (Boyar-Peralta circuit, J. Cryptol. 2010) -----------------
// Byte-for-byte port of kinet::crypto::aead::aes::aes_sbox.

fn aes_sbox(x: u32) -> u32 {
    let U0 = (x >> 7u) & 1u;
    let U1 = (x >> 6u) & 1u;
    let U2 = (x >> 5u) & 1u;
    let U3 = (x >> 4u) & 1u;
    let U4 = (x >> 3u) & 1u;
    let U5 = (x >> 2u) & 1u;
    let U6 = (x >> 1u) & 1u;
    let U7 =  x        & 1u;

    let T1  = U0 ^ U3;
    let T2  = U0 ^ U5;
    let T3  = U0 ^ U6;
    let T4  = U3 ^ U5;
    let T5  = U4 ^ U6;
    let T6  = T1 ^ T5;
    let T7  = U1 ^ U2;
    let T8  = U7 ^ T6;
    let T9  = U7 ^ T7;
    let T10 = T6 ^ T7;
    let T11 = U1 ^ U5;
    let T12 = U2 ^ U5;
    let T13 = T3 ^ T4;
    let T14 = T6 ^ T11;
    let T15 = T5 ^ T11;
    let T16 = T5 ^ T12;
    let T17 = T9 ^ T16;
    let T18 = U3 ^ U7;
    let T19 = T7 ^ T18;
    let T20 = T1 ^ T19;
    let T21 = U6 ^ U7;
    let T22 = T7 ^ T21;
    let T23 = T2 ^ T22;
    let T24 = T2 ^ T10;
    let T25 = T20 ^ T17;
    let T26 = T3 ^ T16;
    let T27 = T1 ^ T12;

    let M1  = T13 & T6;
    let M2  = T23 & T8;
    let M3  = T14 ^ M1;
    let M4  = T19 & U7;
    let M5  = M4 ^ M1;
    let M6  = T3 & T16;
    let M7  = T22 & T9;
    let M8  = T26 ^ M6;
    let M9  = T20 & T17;
    let M10 = M9 ^ M6;
    let M11 = T1 & T15;
    let M12 = T4 & T27;
    let M13 = M12 ^ M11;
    let M14 = T2 & T10;
    let M15 = M14 ^ M11;
    let M16 = M3 ^ M2;
    let M17 = M5 ^ T24;
    let M18 = M8 ^ M7;
    let M19 = M10 ^ M15;
    let M20 = M16 ^ M13;
    let M21 = M17 ^ M15;
    let M22 = M18 ^ M13;
    let M23 = M19 ^ T25;
    let M24 = M22 ^ M23;
    let M25 = M22 & M20;
    let M26 = M21 ^ M25;
    let M27 = M20 ^ M21;
    let M28 = M23 ^ M25;
    let M29 = M28 & M27;
    let M30 = M26 & M24;
    let M31 = M20 & M23;
    let M32 = M27 & M31;
    let M33 = M27 ^ M25;
    let M34 = M21 & M22;
    let M35 = M24 & M34;
    let M36 = M24 ^ M25;
    let M37 = M21 ^ M29;
    let M38 = M32 ^ M33;
    let M39 = M23 ^ M30;
    let M40 = M35 ^ M36;
    let M41 = M38 ^ M40;
    let M42 = M37 ^ M39;
    let M43 = M37 ^ M38;
    let M44 = M39 ^ M40;
    let M45 = M42 ^ M41;
    let M46 = M44 & T6;
    let M47 = M40 & T8;
    let M48 = M39 & U7;
    let M49 = M43 & T16;
    let M50 = M38 & T9;
    let M51 = M37 & T17;
    let M52 = M42 & T15;
    let M53 = M45 & T27;
    let M54 = M41 & T10;
    let M55 = M44 & T13;
    let M56 = M40 & T23;
    let M57 = M39 & T19;
    let M58 = M43 & T3;
    let M59 = M38 & T22;
    let M60 = M37 & T20;
    let M61 = M42 & T1;
    let M62 = M45 & T4;
    let M63 = M41 & T2;

    let L0  = M61 ^ M62;
    let L1  = M50 ^ M56;
    let L2  = M46 ^ M48;
    let L3  = M47 ^ M55;
    let L4  = M54 ^ M58;
    let L5  = M49 ^ M61;
    let L6  = M62 ^ L5;
    let L7  = M46 ^ L3;
    let L8  = M51 ^ M59;
    let L9  = M52 ^ M53;
    let L10 = M53 ^ L4;
    let L11 = M60 ^ L2;
    let L12 = M48 ^ M51;
    let L13 = M50 ^ L0;
    let L14 = M52 ^ M61;
    let L15 = M55 ^ L1;
    let L16 = M56 ^ L0;
    let L17 = M57 ^ L1;
    let L18 = M58 ^ L8;
    let L19 = M63 ^ L4;
    let L20 = L0 ^ L1;
    let L21 = L1 ^ L7;
    let L22 = L3 ^ L12;
    let L23 = L18 ^ L2;
    let L24 = L15 ^ L9;
    let L25 = L6 ^ L10;
    let L26 = L7 ^ L9;
    let L27 = L8 ^ L10;
    let L28 = L11 ^ L14;
    let L29 = L11 ^ L17;

    let S0 = L6  ^ L24;
    var S1 = L16 ^ L26;     S1 = S1 ^ 1u;
    var S2 = L19 ^ L28;     S2 = S2 ^ 1u;
    let S3 = L6  ^ L21;
    let S4 = L20 ^ L22;
    let S5 = L25 ^ L29;
    var S6 = L13 ^ L27;     S6 = S6 ^ 1u;
    var S7 = L6  ^ L23;     S7 = S7 ^ 1u;

    return ((S0 & 1u) << 7u)
         | ((S1 & 1u) << 6u)
         | ((S2 & 1u) << 5u)
         | ((S3 & 1u) << 4u)
         | ((S4 & 1u) << 3u)
         | ((S5 & 1u) << 2u)
         | ((S6 & 1u) << 1u)
         |  (S7 & 1u);
}

const RCON: array<u32, 7> = array<u32, 7>(
    0x01u, 0x02u, 0x04u, 0x08u, 0x10u, 0x20u, 0x40u
);

fn xtime(x: u32) -> u32 {
    return ((x << 1u) ^ (((x >> 7u) & 1u) * 0x1bu)) & 0xffu;
}

// ---- AES-256 key expansion (FIPS 197 §5.2) -------------------------------
// 240 bytes of round-key material, stored byte-by-byte.

var<private> rk_state: array<u32, 240>;

fn aes256_expand_key(key_byte_off: u32) {
    for (var i = 0u; i < 32u; i = i + 1u) {
        rk_state[i] = rd_key_byte(key_byte_off, i);
    }
    for (var i = 8u; i < 60u; i = i + 1u) {
        var t0 = rk_state[(i - 1u) * 4u + 0u];
        var t1 = rk_state[(i - 1u) * 4u + 1u];
        var t2 = rk_state[(i - 1u) * 4u + 2u];
        var t3 = rk_state[(i - 1u) * 4u + 3u];

        if ((i & 7u) == 0u) {
            let r0 = t1; let r1 = t2; let r2 = t3; let r3 = t0;
            t0 = aes_sbox(r0) ^ RCON[(i / 8u) - 1u];
            t1 = aes_sbox(r1);
            t2 = aes_sbox(r2);
            t3 = aes_sbox(r3);
        } else if ((i & 7u) == 4u) {
            t0 = aes_sbox(t0);
            t1 = aes_sbox(t1);
            t2 = aes_sbox(t2);
            t3 = aes_sbox(t3);
        }

        rk_state[i * 4u + 0u] = (rk_state[(i - 8u) * 4u + 0u] ^ t0) & 0xffu;
        rk_state[i * 4u + 1u] = (rk_state[(i - 8u) * 4u + 1u] ^ t1) & 0xffu;
        rk_state[i * 4u + 2u] = (rk_state[(i - 8u) * 4u + 2u] ^ t2) & 0xffu;
        rk_state[i * 4u + 3u] = (rk_state[(i - 8u) * 4u + 3u] ^ t3) & 0xffu;
    }
}

// ---- AES-256 encrypt one 16-byte block (FIPS 197 §5.1) -------------------

var<private> aes_state: array<u32, 16>;

fn aes256_encrypt_block(in_buf: array<u32, 16>) -> array<u32, 16> {
    for (var i = 0u; i < 16u; i = i + 1u) {
        aes_state[i] = (in_buf[i] ^ rk_state[i]) & 0xffu;
    }
    for (var round = 1u; round < 14u; round = round + 1u) {
        for (var i = 0u; i < 16u; i = i + 1u) {
            aes_state[i] = aes_sbox(aes_state[i]);
        }
        // ShiftRows.
        var t: u32;
        t = aes_state[1]; aes_state[1] = aes_state[5];  aes_state[5] = aes_state[9];   aes_state[9] = aes_state[13]; aes_state[13] = t;
        t = aes_state[2]; aes_state[2] = aes_state[10]; aes_state[10] = t;
        t = aes_state[6]; aes_state[6] = aes_state[14]; aes_state[14] = t;
        t = aes_state[15]; aes_state[15] = aes_state[11]; aes_state[11] = aes_state[7]; aes_state[7] = aes_state[3]; aes_state[3] = t;
        // MixColumns.
        for (var c = 0u; c < 4u; c = c + 1u) {
            let a0 = aes_state[c*4u + 0u];
            let a1 = aes_state[c*4u + 1u];
            let a2 = aes_state[c*4u + 2u];
            let a3 = aes_state[c*4u + 3u];
            let x  = a0 ^ a1 ^ a2 ^ a3;
            let y0 = a0;
            aes_state[c*4u + 0u] = (a0 ^ x ^ xtime(a0 ^ a1)) & 0xffu;
            aes_state[c*4u + 1u] = (a1 ^ x ^ xtime(a1 ^ a2)) & 0xffu;
            aes_state[c*4u + 2u] = (a2 ^ x ^ xtime(a2 ^ a3)) & 0xffu;
            aes_state[c*4u + 3u] = (a3 ^ x ^ xtime(a3 ^ y0)) & 0xffu;
        }
        for (var i = 0u; i < 16u; i = i + 1u) {
            aes_state[i] = (aes_state[i] ^ rk_state[round * 16u + i]) & 0xffu;
        }
    }
    // Final round.
    for (var i = 0u; i < 16u; i = i + 1u) {
        aes_state[i] = aes_sbox(aes_state[i]);
    }
    var t: u32;
    t = aes_state[1]; aes_state[1] = aes_state[5];  aes_state[5] = aes_state[9];   aes_state[9] = aes_state[13]; aes_state[13] = t;
    t = aes_state[2]; aes_state[2] = aes_state[10]; aes_state[10] = t;
    t = aes_state[6]; aes_state[6] = aes_state[14]; aes_state[14] = t;
    t = aes_state[15]; aes_state[15] = aes_state[11]; aes_state[11] = aes_state[7]; aes_state[7] = aes_state[3]; aes_state[3] = t;

    var out_buf: array<u32, 16>;
    for (var i = 0u; i < 16u; i = i + 1u) {
        out_buf[i] = (aes_state[i] ^ rk_state[14u * 16u + i]) & 0xffu;
    }
    return out_buf;
}

// ---- GHASH (NIST SP 800-38D §6.3, constant-time 128 iterations) ----------

fn ghash_mul(z_in: array<u32, 16>, h_in: array<u32, 16>) -> array<u32, 16> {
    var z = z_in;
    var v = h_in;
    var r: array<u32, 16>;
    for (var i = 0u; i < 16u; i = i + 1u) { r[i] = 0u; }
    for (var i = 0u; i < 128u; i = i + 1u) {
        let zbit = (z[i >> 3u] >> (7u - (i & 7u))) & 1u;
        let mask = (0u - zbit) & 0xffu;
        for (var j = 0u; j < 16u; j = j + 1u) {
            r[j] = (r[j] ^ (v[j] & mask)) & 0xffu;
        }
        let lsb = v[15] & 1u;
        // shift v right by 1 bit.
        for (var j = 15u; j > 0u; j = j - 1u) {
            v[j] = ((v[j] >> 1u) | ((v[j-1u] & 1u) << 7u)) & 0xffu;
        }
        v[0] = (v[0] >> 1u) & 0xffu;
        let rmask = (0u - lsb) & 0xffu;
        v[0] = (v[0] ^ (0xe1u & rmask)) & 0xffu;
    }
    return r;
}

fn inc32(ctr_in: array<u32, 16>) -> array<u32, 16> {
    var ctr = ctr_in;
    var c = (ctr[12] << 24u) | (ctr[13] << 16u) | (ctr[14] << 8u) | ctr[15];
    c = c + 1u;
    ctr[12] = (c >> 24u) & 0xffu;
    ctr[13] = (c >> 16u) & 0xffu;
    ctr[14] = (c >>  8u) & 0xffu;
    ctr[15] =  c         & 0xffu;
    return ctr;
}

fn ghash_update(y_in: array<u32, 16>, h: array<u32, 16>, arena: u32,
                off: u32, len: u32) -> array<u32, 16> {
    var y = y_in;
    var pos: u32 = 0u;
    while (len - pos >= 16u) {
        for (var i = 0u; i < 16u; i = i + 1u) {
            y[i] = (y[i] ^ rd_msg(arena, off + pos + i)) & 0xffu;
        }
        y = ghash_mul(y, h);
        pos = pos + 16u;
    }
    let rem = len - pos;
    if (rem > 0u) {
        var blk: array<u32, 16>;
        for (var i = 0u; i < 16u; i = i + 1u) { blk[i] = 0u; }
        for (var i = 0u; i < rem; i = i + 1u) {
            blk[i] = rd_msg(arena, off + pos + i);
        }
        for (var i = 0u; i < 16u; i = i + 1u) {
            y[i] = (y[i] ^ blk[i]) & 0xffu;
        }
        y = ghash_mul(y, h);
    }
    return y;
}

@compute @workgroup_size(64)
fn aes_gcm_jobs(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x;
    if (i >= params.n_jobs) { return; }

    let job = jobs[i];

    aes256_expand_key(job.key_offset);

    // H = AES_K(0^128).
    var zero: array<u32, 16>;
    for (var k = 0u; k < 16u; k = k + 1u) { zero[k] = 0u; }
    let H = aes256_encrypt_block(zero);

    // J0 = IV || 0x00000001.
    var J0: array<u32, 16>;
    for (var k = 0u; k < 12u; k = k + 1u) {
        J0[k] = rd_iv_byte(job.nonce_offset, k);
    }
    J0[12] = 0u; J0[13] = 0u; J0[14] = 0u; J0[15] = 1u;

    // Encrypt plaintext under counter starting at inc32(J0).
    var ctr = inc32(J0);
    var pos: u32 = 0u;
    while (pos < job.pt_len) {
        let ks = aes256_encrypt_block(ctr);
        var take = job.pt_len - pos;
        if (take > 16u) { take = 16u; }
        for (var k = 0u; k < take; k = k + 1u) {
            let pt_b = rd_in(job.pt_offset + pos + k);
            wr_out(job.ct_offset + pos + k, pt_b ^ ks[k]);
        }
        ctr = inc32(ctr);
        pos = pos + take;
    }

    // GHASH over (aad || pad || ct || pad || lens_in_bits).
    var Y: array<u32, 16>;
    for (var k = 0u; k < 16u; k = k + 1u) { Y[k] = 0u; }
    Y = ghash_update(Y, H, 0u, job.aad_offset, job.aad_len);
    Y = ghash_update(Y, H, 1u, job.ct_offset,  job.pt_len);
    {
        // Lengths block (BE, in bits). aad_len and pt_len are < 2^32, so
        // upper 4 bytes of each 8-byte field are always zero.
        var lens: array<u32, 16>;
        let la_bits = job.aad_len * 8u;
        let lc_bits = job.pt_len  * 8u;
        // Upper 4 bytes of la_bits == 0 (since la_bits < 2^35 here, but we
        // still emit u32 BE for the low 32 bits and zero for the high).
        lens[0] = 0u; lens[1] = 0u; lens[2] = 0u; lens[3] = 0u;
        lens[4] = (la_bits >> 24u) & 0xffu;
        lens[5] = (la_bits >> 16u) & 0xffu;
        lens[6] = (la_bits >>  8u) & 0xffu;
        lens[7] =  la_bits         & 0xffu;
        lens[ 8] = 0u; lens[ 9] = 0u; lens[10] = 0u; lens[11] = 0u;
        lens[12] = (lc_bits >> 24u) & 0xffu;
        lens[13] = (lc_bits >> 16u) & 0xffu;
        lens[14] = (lc_bits >>  8u) & 0xffu;
        lens[15] =  lc_bits         & 0xffu;
        for (var k = 0u; k < 16u; k = k + 1u) {
            Y[k] = (Y[k] ^ lens[k]) & 0xffu;
        }
        Y = ghash_mul(Y, H);
    }

    // Tag = GHASH XOR AES_K(J0).
    let s = aes256_encrypt_block(J0);
    for (var k = 0u; k < 16u; k = k + 1u) {
        wr_out(job.tag_offset + k, Y[k] ^ s[k]);
    }
}
