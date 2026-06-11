// Batched ChaCha20-Poly1305 (RFC 8439) compute shader. One thread per
// (key, nonce, aad, plaintext) message. Output is byte-equal to
// kinet::crypto::aead::chacha20_poly1305::encrypt() in cpp/aead.cpp and to
// gpu/metal/aead_batch.metal.
//
// WGSL has no u8 nor u64. Bytes are packed into u32 storage buffers
// (LSB-first within each word). Poly1305 mirrors the Metal radix-2^26
// limb layout, with all u64 arithmetic emulated via vec2<u32> (lo, hi).

struct AeadJob {
    aad_offset:   u32,
    aad_len:      u32,
    pt_offset:    u32,
    pt_len:       u32,
    ct_offset:    u32,
    tag_offset:   u32,
    key_offset:   u32,
    nonce_offset: u32,
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

// ---- u64 emulation -------------------------------------------------------

fn u64_make(lo: u32) -> vec2<u32> { return vec2<u32>(lo, 0u); }
fn u64_const_lo(lo: u32) -> vec2<u32> { return vec2<u32>(lo, 0u); }
fn u64_add(a: vec2<u32>, b: vec2<u32>) -> vec2<u32> {
    let lo = a.x + b.x;
    var carry: u32 = 0u;
    if (lo < a.x) { carry = 1u; }
    let hi = a.y + b.y + carry;
    return vec2<u32>(lo, hi);
}
fn u64_shr_26(a: vec2<u32>) -> vec2<u32> {
    // a >> 26: lo = (a.x >> 26) | (a.y << 6); hi = a.y >> 26.
    let lo = (a.x >> 26u) | (a.y << 6u);
    let hi = a.y >> 26u;
    return vec2<u32>(lo, hi);
}
fn u64_low26(a: vec2<u32>) -> u32 {
    return a.x & 0x3ffffffu;
}
fn u64_low32(a: vec2<u32>) -> u32 {
    return a.x;
}
fn u64_shr_32(a: vec2<u32>) -> vec2<u32> {
    return vec2<u32>(a.y, 0u);
}

// 32 x 32 -> 64
fn mul32_64(a: u32, b: u32) -> vec2<u32> {
    let al = a & 0xffffu;
    let ah = a >> 16u;
    let bl = b & 0xffffu;
    let bh = b >> 16u;
    let ll = al * bl;
    let lh = al * bh;
    let hl = ah * bl;
    let hh = ah * bh;
    let mid = (ll >> 16u) + (lh & 0xffffu) + (hl & 0xffffu);
    let lo = (mid << 16u) | (ll & 0xffffu);
    let hi = hh + (lh >> 16u) + (hl >> 16u) + (mid >> 16u);
    return vec2<u32>(lo, hi);
}

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

fn rd_key32(key_byte_off: u32, idx: u32) -> u32 {
    let w = (key_byte_off + idx * 4u) >> 2u;
    return keys[w];
}
fn rd_nonce32(nonce_byte_off: u32, idx: u32) -> u32 {
    let w = (nonce_byte_off + idx * 4u) >> 2u;
    return nonces[w];
}

// ---- ChaCha20 ------------------------------------------------------------

fn rotl32(x: u32, n: u32) -> u32 {
    return (x << n) | (x >> (32u - n));
}

var<private> v_state: array<u32, 16>;
var<private> v_init:  array<u32, 16>;

fn quarter(ai: u32, bi: u32, ci: u32, di: u32) {
    var a = v_state[ai]; var b = v_state[bi];
    var c = v_state[ci]; var d = v_state[di];
    a = a + b; d = d ^ a; d = rotl32(d, 16u);
    c = c + d; b = b ^ c; b = rotl32(b, 12u);
    a = a + b; d = d ^ a; d = rotl32(d,  8u);
    c = c + d; b = b ^ c; b = rotl32(b,  7u);
    v_state[ai] = a; v_state[bi] = b;
    v_state[ci] = c; v_state[di] = d;
}

fn chacha20_block(key_off: u32, nonce_off: u32, counter: u32) {
    v_init[ 0] = 0x61707865u; v_init[ 1] = 0x3320646eu;
    v_init[ 2] = 0x79622d32u; v_init[ 3] = 0x6b206574u;
    v_init[ 4] = rd_key32(key_off, 0u); v_init[ 5] = rd_key32(key_off, 1u);
    v_init[ 6] = rd_key32(key_off, 2u); v_init[ 7] = rd_key32(key_off, 3u);
    v_init[ 8] = rd_key32(key_off, 4u); v_init[ 9] = rd_key32(key_off, 5u);
    v_init[10] = rd_key32(key_off, 6u); v_init[11] = rd_key32(key_off, 7u);
    v_init[12] = counter;
    v_init[13] = rd_nonce32(nonce_off, 0u);
    v_init[14] = rd_nonce32(nonce_off, 1u);
    v_init[15] = rd_nonce32(nonce_off, 2u);
    for (var i = 0u; i < 16u; i = i + 1u) { v_state[i] = v_init[i]; }
    for (var r = 0u; r < 10u; r = r + 1u) {
        quarter(0u, 4u,  8u, 12u);
        quarter(1u, 5u,  9u, 13u);
        quarter(2u, 6u, 10u, 14u);
        quarter(3u, 7u, 11u, 15u);
        quarter(0u, 5u, 10u, 15u);
        quarter(1u, 6u, 11u, 12u);
        quarter(2u, 7u,  8u, 13u);
        quarter(3u, 4u,  9u, 14u);
    }
    for (var i = 0u; i < 16u; i = i + 1u) { v_state[i] = v_state[i] + v_init[i]; }
}

fn ks_byte(i: u32) -> u32 {
    let w = i >> 2u;
    let s = (i & 3u) * 8u;
    return (v_state[w] >> s) & 0xffu;
}

// ---- Poly1305 (radix-2^26, mirrors metal/aead_batch.metal) ----------------

var<private> p_r: array<u32, 5>;     // 5 x 26-bit limbs
var<private> p_s: array<u32, 4>;     // 4 x 32-bit s words
var<private> p_h: array<u32, 5>;     // 5 x 26-bit limbs

fn poly_init_from_block0() {
    let c0 = v_state[0] & 0x0fffffffu;
    let c1 = v_state[1] & 0x0ffffffcu;
    let c2 = v_state[2] & 0x0ffffffcu;
    let c3 = v_state[3] & 0x0ffffffcu;
    p_r[0] =  c0                       & 0x3ffffffu;
    p_r[1] = ((c0 >> 26) | (c1 <<  6)) & 0x3ffffffu;
    p_r[2] = ((c1 >> 20) | (c2 << 12)) & 0x3ffffffu;
    p_r[3] = ((c2 >> 14) | (c3 << 18)) & 0x3ffffffu;
    p_r[4] =  (c3 >> 8)                & 0x3ffffffu;
    p_s[0] = v_state[4];
    p_s[1] = v_state[5];
    p_s[2] = v_state[6];
    p_s[3] = v_state[7];
    for (var i = 0u; i < 5u; i = i + 1u) { p_h[i] = 0u; }
}

// Compute one Poly1305 block: h = (h + m) * r mod (2^130 - 5).
// Layout is identical to metal/aead_batch.metal poly_block.
fn poly_block_words(t0: u32, t1: u32, t2: u32, t3: u32, hibit: u32) {
    // h += unpacked m (5 limbs of 26 bits).
    let h0 = p_h[0] +  ( t0                       & 0x3ffffffu);
    let h1 = p_h[1] +  (((t0 >> 26) | (t1 <<  6)) & 0x3ffffffu);
    let h2 = p_h[2] +  (((t1 >> 20) | (t2 << 12)) & 0x3ffffffu);
    let h3 = p_h[3] +  (((t2 >> 14) | (t3 << 18)) & 0x3ffffffu);
    // For the high limb: h4 += ((t3 >> 8) | hibit). hibit is 1u<<24 always.
    let h4 = p_h[4] +  ((t3 >>  8) | hibit);

    let r0 = p_r[0]; let r1 = p_r[1]; let r2 = p_r[2];
    let r3 = p_r[3]; let r4 = p_r[4];
    let s1 = r1 * 5u; let s2 = r2 * 5u;
    let s3 = r3 * 5u; let s4 = r4 * 5u;

    // 64-bit accumulators d_i = sum of (h_j * coeff)
    // Each h_j * coeff is up to 32-bit * 30-bit = 62-bit; sum of 5 fits in 65 bits
    // with a tiny excess; we must use a true 64-bit add chain.
    var d0 = u64_add(u64_add(u64_add(u64_add(
                mul32_64(h0, r0),
                mul32_64(h1, s4)),
                mul32_64(h2, s3)),
                mul32_64(h3, s2)),
                mul32_64(h4, s1));
    var d1 = u64_add(u64_add(u64_add(u64_add(
                mul32_64(h0, r1),
                mul32_64(h1, r0)),
                mul32_64(h2, s4)),
                mul32_64(h3, s3)),
                mul32_64(h4, s2));
    var d2 = u64_add(u64_add(u64_add(u64_add(
                mul32_64(h0, r2),
                mul32_64(h1, r1)),
                mul32_64(h2, r0)),
                mul32_64(h3, s4)),
                mul32_64(h4, s3));
    var d3 = u64_add(u64_add(u64_add(u64_add(
                mul32_64(h0, r3),
                mul32_64(h1, r2)),
                mul32_64(h2, r1)),
                mul32_64(h3, r0)),
                mul32_64(h4, s4));
    var d4 = u64_add(u64_add(u64_add(u64_add(
                mul32_64(h0, r4),
                mul32_64(h1, r3)),
                mul32_64(h2, r2)),
                mul32_64(h3, r1)),
                mul32_64(h4, r0));

    var c: vec2<u32>;
    c = u64_shr_26(d0); d0.x = u64_low26(d0); d0.y = 0u; d1 = u64_add(d1, c);
    c = u64_shr_26(d1); d1.x = u64_low26(d1); d1.y = 0u; d2 = u64_add(d2, c);
    c = u64_shr_26(d2); d2.x = u64_low26(d2); d2.y = 0u; d3 = u64_add(d3, c);
    c = u64_shr_26(d3); d3.x = u64_low26(d3); d3.y = 0u; d4 = u64_add(d4, c);
    // d4_hi -> *5 -> d0
    c = u64_shr_26(d4); d4.x = u64_low26(d4); d4.y = 0u;
    // c may have nonzero hi; multiply by 5 carefully.
    // Since h values were at most ~2^27 (h_i + m_i, where p_h[i] < 2^26 and m_i < 2^26),
    // after mul each d_i is < 5 * 2^27 * 2^27 = 5 * 2^54, comfortably within 64 bits.
    // c after >>26 is < 2^38 (safe). Multiplying by 5 stays < 2^41.
    let c_lo = c.x; let c_hi = c.y;
    // c * 5 in u64.
    let c5_lo_full = mul32_64(c_lo, 5u);
    var c5 = c5_lo_full;
    if (c_hi != 0u) {
        // c_hi * 5 contributes to high.
        c5.y = c5.y + c_hi * 5u;
    }
    d0 = u64_add(d0, c5);
    c = u64_shr_26(d0); d0.x = u64_low26(d0); d0.y = 0u; d1 = u64_add(d1, c);

    p_h[0] = u64_low32(d0);
    p_h[1] = u64_low32(d1);
    p_h[2] = u64_low32(d2);
    p_h[3] = u64_low32(d3);
    p_h[4] = u64_low32(d4);
}

fn poly_block_bytes(arena: u32, byte_off: u32, byte_len: u32, full: bool) {
    var b: array<u32, 16>;
    var consumed = byte_len;
    if (full) { consumed = 16u; }
    for (var i = 0u; i < 16u; i = i + 1u) {
        if (i < consumed) { b[i] = rd_msg(arena, byte_off + i); }
        else              { b[i] = 0u; }
    }
    let t0 = b[ 0] | (b[ 1] << 8u) | (b[ 2] << 16u) | (b[ 3] << 24u);
    let t1 = b[ 4] | (b[ 5] << 8u) | (b[ 6] << 16u) | (b[ 7] << 24u);
    let t2 = b[ 8] | (b[ 9] << 8u) | (b[10] << 16u) | (b[11] << 24u);
    let t3 = b[12] | (b[13] << 8u) | (b[14] << 16u) | (b[15] << 24u);
    poly_block_words(t0, t1, t2, t3, 1u << 24u);
}

fn absorb_padded(arena: u32, off: u32, len: u32) {
    var pos: u32 = 0u;
    while (len - pos >= 16u) {
        poly_block_bytes(arena, off + pos, 16u, true);
        pos = pos + 16u;
    }
    let rem = len - pos;
    if (rem > 0u) {
        poly_block_bytes(arena, off + pos, rem, false);
    }
}

fn poly_finalize_to_tag(out_byte_off: u32) {
    var h0 = p_h[0]; var h1 = p_h[1]; var h2 = p_h[2];
    var h3 = p_h[3]; var h4 = p_h[4];
    var c: u32;
    c = h1 >> 26u; h1 = h1 & 0x3ffffffu; h2 = h2 + c;
    c = h2 >> 26u; h2 = h2 & 0x3ffffffu; h3 = h3 + c;
    c = h3 >> 26u; h3 = h3 & 0x3ffffffu; h4 = h4 + c;
    c = h4 >> 26u; h4 = h4 & 0x3ffffffu; h0 = h0 + c * 5u;
    c = h0 >> 26u; h0 = h0 & 0x3ffffffu; h1 = h1 + c;

    var g0 = h0 + 5u; c = g0 >> 26u; g0 = g0 & 0x3ffffffu;
    var g1 = h1 + c;  c = g1 >> 26u; g1 = g1 & 0x3ffffffu;
    var g2 = h2 + c;  c = g2 >> 26u; g2 = g2 & 0x3ffffffu;
    var g3 = h3 + c;  c = g3 >> 26u; g3 = g3 & 0x3ffffffu;
    let g4 = h4 + c - (1u << 26u);

    let mask = (g4 >> 31u) - 1u;
    let nm   = ~mask;
    h0 = (h0 & nm) | (g0 & mask);
    h1 = (h1 & nm) | (g1 & mask);
    h2 = (h2 & nm) | (g2 & mask);
    h3 = (h3 & nm) | (g3 & mask);
    h4 = (h4 & nm) | (g4 & mask);

    let f0 =  h0        | (h1 << 26u);
    let f1 = (h1 >>  6u) | (h2 << 20u);
    let f2 = (h2 >> 12u) | (h3 << 14u);
    let f3 = (h3 >> 18u) | (h4 <<  8u);

    var t = u64_add(u64_make(f0), u64_make(p_s[0]));
    let w0 = t.x;
    wr_out(out_byte_off +  0u, (w0 >>  0u) & 0xffu);
    wr_out(out_byte_off +  1u, (w0 >>  8u) & 0xffu);
    wr_out(out_byte_off +  2u, (w0 >> 16u) & 0xffu);
    wr_out(out_byte_off +  3u, (w0 >> 24u) & 0xffu);
    t = u64_add(u64_add(u64_shr_32(t), u64_make(f1)), u64_make(p_s[1]));
    let w1 = t.x;
    wr_out(out_byte_off +  4u, (w1 >>  0u) & 0xffu);
    wr_out(out_byte_off +  5u, (w1 >>  8u) & 0xffu);
    wr_out(out_byte_off +  6u, (w1 >> 16u) & 0xffu);
    wr_out(out_byte_off +  7u, (w1 >> 24u) & 0xffu);
    t = u64_add(u64_add(u64_shr_32(t), u64_make(f2)), u64_make(p_s[2]));
    let w2 = t.x;
    wr_out(out_byte_off +  8u, (w2 >>  0u) & 0xffu);
    wr_out(out_byte_off +  9u, (w2 >>  8u) & 0xffu);
    wr_out(out_byte_off + 10u, (w2 >> 16u) & 0xffu);
    wr_out(out_byte_off + 11u, (w2 >> 24u) & 0xffu);
    t = u64_add(u64_add(u64_shr_32(t), u64_make(f3)), u64_make(p_s[3]));
    let w3 = t.x;
    wr_out(out_byte_off + 12u, (w3 >>  0u) & 0xffu);
    wr_out(out_byte_off + 13u, (w3 >>  8u) & 0xffu);
    wr_out(out_byte_off + 14u, (w3 >> 16u) & 0xffu);
    wr_out(out_byte_off + 15u, (w3 >> 24u) & 0xffu);
}

@compute @workgroup_size(64)
fn chacha20_poly1305_jobs(@builtin(global_invocation_id) gid: vec3<u32>) {
    let i = gid.x;
    if (i >= params.n_jobs) { return; }

    let job = jobs[i];

    chacha20_block(job.key_offset, job.nonce_offset, 0u);
    poly_init_from_block0();

    var counter: u32 = 1u;
    var pos: u32 = 0u;
    while (pos < job.pt_len) {
        chacha20_block(job.key_offset, job.nonce_offset, counter);
        var take = job.pt_len - pos;
        if (take > 64u) { take = 64u; }
        for (var k = 0u; k < take; k = k + 1u) {
            let pt_b = rd_in(job.pt_offset + pos + k);
            let ks_b = ks_byte(k);
            wr_out(job.ct_offset + pos + k, pt_b ^ ks_b);
        }
        pos = pos + take;
        counter = counter + 1u;
    }

    absorb_padded(0u, job.aad_offset, job.aad_len);
    absorb_padded(1u, job.ct_offset,  job.pt_len);

    // Lengths block: aad_len LE u64 || pt_len LE u64.
    let la = job.aad_len;
    let lc = job.pt_len;
    poly_block_words(la, 0u, lc, 0u, 1u << 24u);

    poly_finalize_to_tag(job.tag_offset);
}
