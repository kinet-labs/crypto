// BLAKE2b-512 (RFC 7693) compute shader in WGSL. One thread per input.
// Byte-equal to blake2b/c-abi/blake2b_full.cpp::hash() and to
// blake2b/gpu/cuda/blake2b.cu and blake2b/gpu/metal/blake2b_batch.metal.
//
// WGSL has no native u64. Each 64-bit word is emulated as a vec2<u32>
// (.x = lo, .y = hi). All BLAKE2b operations are expressed against this
// pair representation:
//
//   xor64       — lane-wise xor
//   add64       — full 64-bit add (carry from lo via unsigned wrap detect)
//   rotr64(n)   — four cases: n==0 (identity), n==32 (lane swap),
//                 n in (0,32) inner funnel, n in (32,64) outer funnel.
//
// 12 rounds, 128-byte block, little-endian message words, final-block flag
// inverts v[14]. Output is 64 bytes little-endian (8 × u64 lanes packed
// into 16 × u32 entries in the outputs[] storage buffer).

struct HashInput {
    offset: u32,
    length: u32,
}

@group(0) @binding(0) var<storage, read>       inputs:  array<HashInput>;
@group(0) @binding(1) var<storage, read>       data:    array<u32>;
@group(0) @binding(2) var<storage, read_write> outputs: array<u32>;

// =============================================================================
// IV (RFC 7693 sec 2.6) split into (lo, hi) u32 pairs.
// =============================================================================
const IV_LO = array<u32, 8>(
    0xF3BCC908u, 0x84CAA73Bu, 0xFE94F82Bu, 0x5F1D36F1u,
    0xADE682D1u, 0x2B3E6C1Fu, 0xFB41BD6Bu, 0x137E2179u,
);
const IV_HI = array<u32, 8>(
    0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
    0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u,
);

// SIGMA permutation (RFC 7693 sec 2.7).
const SIGMA = array<array<u32, 16>, 10>(
    array<u32, 16>( 0u,  1u,  2u,  3u,  4u,  5u,  6u,  7u,  8u,  9u, 10u, 11u, 12u, 13u, 14u, 15u),
    array<u32, 16>(14u, 10u,  4u,  8u,  9u, 15u, 13u,  6u,  1u, 12u,  0u,  2u, 11u,  7u,  5u,  3u),
    array<u32, 16>(11u,  8u, 12u,  0u,  5u,  2u, 15u, 13u, 10u, 14u,  3u,  6u,  7u,  1u,  9u,  4u),
    array<u32, 16>( 7u,  9u,  3u,  1u, 13u, 12u, 11u, 14u,  2u,  6u,  5u, 10u,  4u,  0u, 15u,  8u),
    array<u32, 16>( 9u,  0u,  5u,  7u,  2u,  4u, 10u, 15u, 14u,  1u, 11u, 12u,  6u,  8u,  3u, 13u),
    array<u32, 16>( 2u, 12u,  6u, 10u,  0u, 11u,  8u,  3u,  4u, 13u,  7u,  5u, 15u, 14u,  1u,  9u),
    array<u32, 16>(12u,  5u,  1u, 15u, 14u, 13u,  4u, 10u,  0u,  7u,  6u,  3u,  9u,  2u,  8u, 11u),
    array<u32, 16>(13u, 11u,  7u, 14u, 12u,  1u,  3u,  9u,  5u,  0u, 15u,  4u,  8u,  6u,  2u, 10u),
    array<u32, 16>( 6u, 15u, 14u,  9u, 11u,  3u,  0u,  8u, 12u,  2u, 13u,  7u,  1u,  4u, 10u,  5u),
    array<u32, 16>(10u,  2u,  8u,  4u,  7u,  6u,  1u,  5u, 15u, 11u,  9u, 14u,  3u, 12u, 13u,  0u),
);

// =============================================================================
// 64-bit emulation. Each "u64" lives in a vec2<u32> (lo, hi).
// =============================================================================

fn xor64(a: vec2<u32>, b: vec2<u32>) -> vec2<u32> {
    return vec2<u32>(a.x ^ b.x, a.y ^ b.y);
}

fn add64(a: vec2<u32>, b: vec2<u32>) -> vec2<u32> {
    let lo = a.x + b.x;
    let carry = select(0u, 1u, lo < a.x);   // unsigned wrap detect
    let hi = a.y + b.y + carry;
    return vec2<u32>(lo, hi);
}

fn rotr64(v: vec2<u32>, n: u32) -> vec2<u32> {
    if (n == 0u) { return v; }
    if (n == 32u) { return vec2<u32>(v.y, v.x); }
    if (n < 32u) {
        let lo = (v.x >> n) | (v.y << (32u - n));
        let hi = (v.y >> n) | (v.x << (32u - n));
        return vec2<u32>(lo, hi);
    }
    let m = n - 32u;
    let lo = (v.y >> m) | (v.x << (32u - m));
    let hi = (v.x >> m) | (v.y << (32u - m));
    return vec2<u32>(lo, hi);
}

fn not64(a: vec2<u32>) -> vec2<u32> {
    return vec2<u32>(~a.x, ~a.y);
}

// =============================================================================
// Working state — kept in private storage so dynamic indexing is legal.
// =============================================================================
var<private> v_lo: array<u32, 16>;
var<private> v_hi: array<u32, 16>;
var<private> h_lo: array<u32, 8>;
var<private> h_hi: array<u32, 8>;
var<private> m_lo: array<u32, 16>;
var<private> m_hi: array<u32, 16>;

fn g_mix(a: u32, b: u32, c: u32, d: u32, mx: u32, my: u32) {
    var va = vec2<u32>(v_lo[a], v_hi[a]);
    var vb = vec2<u32>(v_lo[b], v_hi[b]);
    var vc = vec2<u32>(v_lo[c], v_hi[c]);
    var vd = vec2<u32>(v_lo[d], v_hi[d]);
    let mxv = vec2<u32>(m_lo[mx], m_hi[mx]);
    let myv = vec2<u32>(m_lo[my], m_hi[my]);

    va = add64(add64(va, vb), mxv);
    vd = rotr64(xor64(vd, va), 32u);
    vc = add64(vc, vd);
    vb = rotr64(xor64(vb, vc), 24u);
    va = add64(add64(va, vb), myv);
    vd = rotr64(xor64(vd, va), 16u);
    vc = add64(vc, vd);
    vb = rotr64(xor64(vb, vc), 63u);

    v_lo[a] = va.x; v_hi[a] = va.y;
    v_lo[b] = vb.x; v_hi[b] = vb.y;
    v_lo[c] = vc.x; v_hi[c] = vc.y;
    v_lo[d] = vd.x; v_hi[d] = vd.y;
}

fn compress(t0: vec2<u32>, t1: vec2<u32>, last_block: bool) {
    for (var i = 0u; i < 8u; i = i + 1u) {
        v_lo[i] = h_lo[i];
        v_hi[i] = h_hi[i];
    }
    for (var i = 0u; i < 8u; i = i + 1u) {
        v_lo[i + 8u] = IV_LO[i];
        v_hi[i + 8u] = IV_HI[i];
    }
    v_lo[12] = v_lo[12] ^ t0.x; v_hi[12] = v_hi[12] ^ t0.y;
    v_lo[13] = v_lo[13] ^ t1.x; v_hi[13] = v_hi[13] ^ t1.y;
    if (last_block) {
        v_lo[14] = ~v_lo[14];
        v_hi[14] = ~v_hi[14];
    }

    for (var r = 0u; r < 12u; r = r + 1u) {
        let s = SIGMA[r % 10u];
        g_mix(0u, 4u,  8u, 12u, s[0u],  s[1u]);
        g_mix(1u, 5u,  9u, 13u, s[2u],  s[3u]);
        g_mix(2u, 6u, 10u, 14u, s[4u],  s[5u]);
        g_mix(3u, 7u, 11u, 15u, s[6u],  s[7u]);
        g_mix(0u, 5u, 10u, 15u, s[8u],  s[9u]);
        g_mix(1u, 6u, 11u, 12u, s[10u], s[11u]);
        g_mix(2u, 7u,  8u, 13u, s[12u], s[13u]);
        g_mix(3u, 4u,  9u, 14u, s[14u], s[15u]);
    }

    for (var i = 0u; i < 8u; i = i + 1u) {
        h_lo[i] = h_lo[i] ^ v_lo[i] ^ v_lo[i + 8u];
        h_hi[i] = h_hi[i] ^ v_hi[i] ^ v_hi[i + 8u];
    }
}

// Read a single byte from the packed-u32 input arena (little-endian).
fn read_byte(byte_offset: u32) -> u32 {
    let word_idx = byte_offset >> 2u;
    let byte_pos = byte_offset & 3u;
    return (data[word_idx] >> (byte_pos * 8u)) & 0xFFu;
}

@compute @workgroup_size(64)
fn blake2b_jobs(@builtin(global_invocation_id) gid: vec3<u32>) {
    let tid = gid.x;
    if (tid >= arrayLength(&inputs)) { return; }

    let inp = inputs[tid];
    let offset = inp.offset;
    let len = inp.length;

    // Param block (sec 2.5): digest_len=64, key_len=0, fanout=1, depth=1.
    // h[0] ^= 0x0000000001010040.
    for (var i = 0u; i < 8u; i = i + 1u) {
        h_lo[i] = IV_LO[i];
        h_hi[i] = IV_HI[i];
    }
    h_lo[0] = h_lo[0] ^ 0x01010040u;

    var t0 = vec2<u32>(0u, 0u);
    var t1 = vec2<u32>(0u, 0u);
    var pos = 0u;

    // Stream all but the final block as non-last.
    loop {
        if (len - pos <= 128u) { break; }

        for (var w = 0u; w < 16u; w = w + 1u) {
            var lo = 0u;
            var hi = 0u;
            for (var b = 0u; b < 4u; b = b + 1u) {
                lo = lo | (read_byte(offset + pos + w * 8u + b) << (b * 8u));
            }
            for (var b = 0u; b < 4u; b = b + 1u) {
                hi = hi | (read_byte(offset + pos + w * 8u + 4u + b) << (b * 8u));
            }
            m_lo[w] = lo;
            m_hi[w] = hi;
        }

        pos = pos + 128u;
        let t0_new = add64(t0, vec2<u32>(128u, 0u));
        if (t0_new.y < t0.y) { t1 = add64(t1, vec2<u32>(1u, 0u)); }
        t0 = t0_new;
        compress(t0, t1, false);
    }

    // Final (possibly partial) block, zero-padded.
    let rem = len - pos;
    for (var w = 0u; w < 16u; w = w + 1u) {
        m_lo[w] = 0u;
        m_hi[w] = 0u;
    }
    for (var i = 0u; i < rem; i = i + 1u) {
        let byte_val = read_byte(offset + pos + i);
        let word_idx = i >> 3u;
        let byte_in_word = i & 7u;
        if (byte_in_word < 4u) {
            m_lo[word_idx] = m_lo[word_idx] | (byte_val << (byte_in_word * 8u));
        } else {
            m_hi[word_idx] = m_hi[word_idx] | (byte_val << ((byte_in_word - 4u) * 8u));
        }
    }
    let t0_new = add64(t0, vec2<u32>(rem, 0u));
    if (t0_new.y < t0.y) { t1 = add64(t1, vec2<u32>(1u, 0u)); }
    t0 = t0_new;
    compress(t0, t1, true);

    // Output 64 bytes little-endian. outputs[] is u32-packed: each h[i]
    // becomes 2 consecutive u32 lanes (lo, hi).
    let out_base = tid * 16u;
    for (var i = 0u; i < 8u; i = i + 1u) {
        outputs[out_base + i * 2u]      = h_lo[i];
        outputs[out_base + i * 2u + 1u] = h_hi[i];
    }
}
