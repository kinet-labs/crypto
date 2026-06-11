// GPU-batched Poseidon2 over BN254 scalar field, t=2 default parameters.
// One thread per state (left, right). Byte-equal to
// poseidon/cpp/poseidon.cpp::permutation_t2().
//
// Field arithmetic is implemented as 256-bit big-integer ops on 4 little-
// endian uint64_t limbs. Multiplications use the schoolbook 4x4 -> 8 limb
// multiply followed by bit-by-bit shift-and-subtract reduction. This is
// slower than Montgomery multiplication but keeps the kernel arithmetic
// trivially auditable against the CPU body.

#include <metal_stdlib>
using namespace metal;

// BN254 scalar modulus r (LE limbs).
constant ulong MOD0 = 0x43e1f593f0000001ul;
constant ulong MOD1 = 0x2833e84879b97091ul;
constant ulong MOD2 = 0xb85045b68181585dul;
constant ulong MOD3 = 0x30644e72e131a029ul;

inline bool ge_mod(thread const ulong* a) {
    if (a[3] != MOD3) return a[3] > MOD3;
    if (a[2] != MOD2) return a[2] > MOD2;
    if (a[1] != MOD1) return a[1] > MOD1;
    if (a[0] != MOD0) return a[0] >= MOD0;
    return true;
}

inline bool ge(thread const ulong* a, thread const ulong* b) {
    if (a[3] != b[3]) return a[3] > b[3];
    if (a[2] != b[2]) return a[2] > b[2];
    if (a[1] != b[1]) return a[1] > b[1];
    return a[0] >= b[0];
}

// Subtract MOD in-place from a (assumes a >= MOD).
inline void sub_mod_inplace(thread ulong* a) {
    ulong borrow = 0u;
    ulong b[4] = { MOD0, MOD1, MOD2, MOD3 };
    for (int i = 0; i < 4; ++i) {
        ulong x = a[i];
        ulong y = b[i];
        ulong sub = x - y - borrow;
        // Set borrow if (x < y + borrow). Use bit trick.
        ulong new_borrow = ((y > x) || (y == x && borrow)) ? 1u : 0u;
        // Refined: borrow if y+borrow > x, with possible y+borrow overflow.
        ulong yb_lo = y + borrow;
        ulong yb_overflow = (yb_lo < y) ? 1u : 0u;
        new_borrow = (yb_overflow || (x < yb_lo)) ? 1u : 0u;
        a[i] = sub;
        borrow = new_borrow;
    }
}

// 4-limb add with carry out.
inline ulong add_carry(thread ulong* r, thread const ulong* a, thread const ulong* b) {
    ulong carry = 0u;
    for (int i = 0; i < 4; ++i) {
        ulong x = a[i];
        ulong y = b[i];
        ulong sum = x + y;
        ulong c1 = (sum < x) ? 1u : 0u;
        ulong sum2 = sum + carry;
        ulong c2 = (sum2 < sum) ? 1u : 0u;
        r[i] = sum2;
        carry = c1 + c2;
    }
    return carry;
}

// r = (a + b) mod MOD.
inline void add_mod(thread ulong* r, thread const ulong* a, thread const ulong* b) {
    ulong c = add_carry(r, a, b);
    if (c != 0u || ge_mod(r)) {
        sub_mod_inplace(r);
    }
}

inline void double_mod(thread ulong* r, thread const ulong* a) {
    add_mod(r, a, a);
}

// Subtract b from a (assumes a >= b). No borrow handling beyond limb 3.
inline void sub_unchecked(thread ulong* r, thread const ulong* a, thread const ulong* b) {
    ulong borrow = 0u;
    for (int i = 0; i < 4; ++i) {
        ulong x = a[i];
        ulong y = b[i];
        ulong yb_lo = y + borrow;
        ulong yb_overflow = (yb_lo < y) ? 1u : 0u;
        ulong new_borrow = (yb_overflow || (x < yb_lo)) ? 1u : 0u;
        r[i] = x - yb_lo;
        borrow = new_borrow;
    }
}

// r = (a - b) mod MOD.
inline void sub_mod(thread ulong* r, thread const ulong* a, thread const ulong* b) {
    if (ge(a, b)) {
        sub_unchecked(r, a, b);
    } else {
        ulong tmp[4];
        ulong m[4] = { MOD0, MOD1, MOD2, MOD3 };
        sub_unchecked(tmp, m, b);
        ulong c = add_carry(r, tmp, a);
        if (c != 0u || ge_mod(r)) sub_mod_inplace(r);
    }
}

// 64x64 -> 128 multiply, returning the low and high words.
inline void mul64_128(ulong x, ulong y, thread ulong& lo, thread ulong& hi) {
    // Metal does not have a native 128-bit type. Decompose into 32-bit halves.
    ulong x_lo = x & 0xFFFFFFFFul;
    ulong x_hi = x >> 32;
    ulong y_lo = y & 0xFFFFFFFFul;
    ulong y_hi = y >> 32;

    ulong p_ll = x_lo * y_lo;
    ulong p_lh = x_lo * y_hi;
    ulong p_hl = x_hi * y_lo;
    ulong p_hh = x_hi * y_hi;

    ulong mid = (p_ll >> 32) + (p_lh & 0xFFFFFFFFul) + (p_hl & 0xFFFFFFFFul);
    lo = (p_ll & 0xFFFFFFFFul) | (mid << 32);
    hi = p_hh + (p_lh >> 32) + (p_hl >> 32) + (mid >> 32);
}

// 4x4 -> 8 limb schoolbook multiply.
inline void mul_512(thread ulong* out, thread const ulong* a, thread const ulong* b) {
    for (int k = 0; k < 8; ++k) out[k] = 0u;
    for (int i = 0; i < 4; ++i) {
        ulong carry = 0u;
        for (int j = 0; j < 4; ++j) {
            ulong p_lo, p_hi;
            mul64_128(a[i], b[j], p_lo, p_hi);

            // out[i+j] += p_lo + carry
            ulong s = out[i + j] + p_lo;
            ulong c1 = (s < out[i + j]) ? 1u : 0u;
            ulong s2 = s + carry;
            ulong c2 = (s2 < s) ? 1u : 0u;
            out[i + j] = s2;

            // carry for next iteration = p_hi + c1 + c2
            carry = p_hi + c1 + c2;
        }
        out[i + 4] = carry;
    }
}

// Bit-serial reduction: r = (wide mod MOD).
inline void reduce_512(thread ulong* r, thread const ulong* wide) {
    ulong acc[4] = { 0u, 0u, 0u, 0u };

    for (int word = 7; word >= 0; --word) {
        ulong w = wide[word];
        for (int bit = 63; bit >= 0; --bit) {
            ulong b = (w >> bit) & 1ul;
            // shift acc left by 1, or-in b
            ulong c0 = b;
            ulong c1 = (acc[0] >> 63) & 1ul;
            ulong c2 = (acc[1] >> 63) & 1ul;
            ulong c3 = (acc[2] >> 63) & 1ul;
            ulong c4 = (acc[3] >> 63) & 1ul;
            acc[0] = (acc[0] << 1) | c0;
            acc[1] = (acc[1] << 1) | c1;
            acc[2] = (acc[2] << 1) | c2;
            acc[3] = (acc[3] << 1) | c3;
            ulong overflow = c4;

            if (overflow != 0u || ge_mod(acc)) {
                sub_mod_inplace(acc);
            }
        }
    }
    r[0] = acc[0]; r[1] = acc[1]; r[2] = acc[2]; r[3] = acc[3];
}

inline void mul_mod(thread ulong* r, thread const ulong* a, thread const ulong* b) {
    ulong wide[8];
    mul_512(wide, a, b);
    reduce_512(r, wide);
}

inline void square_mod(thread ulong* r, thread const ulong* a) {
    mul_mod(r, a, a);
}

// x^5 = x^2 * x^2 * x.
inline void pow5_mod(thread ulong* r, thread const ulong* a) {
    ulong a2[4], a4[4];
    square_mod(a2, a);
    square_mod(a4, a2);
    mul_mod(r, a4, a);
}

// Big-endian 32 bytes -> 4 LE limbs.
inline void from_bytes_be(thread ulong* r, device const uchar* bytes) {
    for (int i = 0; i < 4; ++i) {
        device const uchar* p = bytes + (3 - i) * 8;
        r[i] = (ulong(p[0]) << 56) | (ulong(p[1]) << 48) |
               (ulong(p[2]) << 40) | (ulong(p[3]) << 32) |
               (ulong(p[4]) << 24) | (ulong(p[5]) << 16) |
               (ulong(p[6]) <<  8) | (ulong(p[7]));
    }
}

inline void to_bytes_be(device uchar* out, thread const ulong* a) {
    for (int i = 0; i < 4; ++i) {
        ulong w = a[3 - i];
        device uchar* p = out + i * 8;
        p[0] = uchar(w >> 56);
        p[1] = uchar(w >> 48);
        p[2] = uchar(w >> 40);
        p[3] = uchar(w >> 32);
        p[4] = uchar(w >> 24);
        p[5] = uchar(w >> 16);
        p[6] = uchar(w >> 8);
        p[7] = uchar(w);
    }
}

// External matrix [[2,1],[1,2]] times state.
inline void mat_external(thread ulong* s0, thread ulong* s1) {
    ulong tmp[4], old_s0[4], old_s1[4];
    add_mod(tmp, s0, s1);
    for (int i = 0; i < 4; ++i) old_s0[i] = s0[i];
    for (int i = 0; i < 4; ++i) old_s1[i] = s1[i];
    add_mod(s0, tmp, old_s0);
    add_mod(s1, tmp, old_s1);
}

// Internal matrix [[2,1],[1,3]] times state.
inline void mat_internal(thread ulong* s0, thread ulong* s1) {
    ulong sum[4], old_s0[4], two_s1[4];
    add_mod(sum, s0, s1);
    for (int i = 0; i < 4; ++i) old_s0[i] = s0[i];
    add_mod(s0, old_s0, sum);
    double_mod(two_s1, s1);
    add_mod(s1, two_s1, sum);
}

inline void add_rk_full(thread ulong* s0, thread ulong* s1,
                        constant const ulong* k0, constant const ulong* k1) {
    ulong tk0[4] = { k0[0], k0[1], k0[2], k0[3] };
    ulong tk1[4] = { k1[0], k1[1], k1[2], k1[3] };
    ulong tmp0[4], tmp1[4];
    add_mod(tmp0, s0, tk0);
    add_mod(tmp1, s1, tk1);
    for (int i = 0; i < 4; ++i) s0[i] = tmp0[i];
    for (int i = 0; i < 4; ++i) s1[i] = tmp1[i];
}

inline void add_rk_partial(thread ulong* s0, constant const ulong* k0) {
    ulong tk0[4] = { k0[0], k0[1], k0[2], k0[3] };
    ulong tmp[4];
    add_mod(tmp, s0, tk0);
    for (int i = 0; i < 4; ++i) s0[i] = tmp[i];
}

inline void sbox(thread ulong* s) {
    ulong t[4];
    pow5_mod(t, s);
    for (int i = 0; i < 4; ++i) s[i] = t[i];
}

// Round constants (LE limbs of 256-bit values). Generated from
// gnark-crypto v0.20.1 NewParameters(2,6,50). DO NOT EDIT.
constant ulong RC_FULL_PRE[3][2][4] = {
    { { 0x8b9b8d31770fac4ful, 0x08580a5f5e295e16ul, 0x4584f763db50a819ul, 0x1da4d6adfb0d0b49ul },
      { 0x51fab2a59acc074cul, 0xab80d0a0c7a0c634ul, 0x19707a56a3b3790eul, 0x0946129a2e33b4e8ul } },
    { { 0x68794dad4b8f82eaul, 0x867b87303b071402ul, 0x580abd6952986570ul, 0x2a39b9d5376afd35ul },
      { 0x32448eea5e3069b2ul, 0xe4a70e66ecd6de5dul, 0xc546b3c7014e5fa3ul, 0x27605717d1245c20ul } },
    { { 0x8e50809c03773632ul, 0xe771ebb09a228d63ul, 0x973653193a470ed7ul, 0x24c896cb2594e17bul },
      { 0xd8042e1b7d597a49ul, 0x6d8701c7869a919aul, 0x0d61d783957003dbul, 0x0911096c45dd9cdaul } },
};

constant ulong RC_PARTIAL[50][4] = {
    { 0xf11f38a70603afdcul, 0xf1daba01aad28021ul, 0x27eee6d352a8ce26ul, 0x26ff6166f1e4b99eul },
    { 0x4d5b89437bf64b7eul, 0x79bcb5e18cfb7d95ul, 0xad6591ff90e50feaul, 0x008e2faedcf76d08ul },
    { 0x32f98820eb353d78ul, 0xf6184a3cec71eeb6ul, 0xe3ad4d1872470830ul, 0x19c9da2379b598acul },
    { 0xa459a40583dfe96bul, 0xab3dfcdb57e2539aul, 0xa8f6a090ec9610a2ul, 0x0f7c4eb15d8b0b62ul },
    { 0x9171588b08ac3983ul, 0xd46900b47dd5ff80ul, 0x79750eba282362d1ul, 0x18b99417dc26b5e0ul },
    { 0x8848af08a8d91a26ul, 0xc73f1c054b76320aul, 0xe2d4493feab82141ul, 0x1ee044081160b3eeul },
    { 0x9122220366c258dcul, 0x0455b6d7a14780d1ul, 0x0e87f5df12ee8a15ul, 0x29bb95c8763efd3eul },
    { 0x067b4705e9a5c9fbul, 0x215e8991f7f9ec12ul, 0xa3ee9a363d740653ul, 0x22c23eec9cb13ff8ul },
    { 0xc7deefc1690b42dcul, 0x9115c7644c4f905cul, 0x680c8b18926c3be0ul, 0x23589e033a31a667ul },
    { 0xdd64ec938a6a247cul, 0x64f60b98a219f1f0ul, 0x2c9c0cde5f2bdd47ul, 0x304e99b887f2e1e9ul },
    { 0xa493b2de7f7d8b4cul, 0xe792f326271d53a3ul, 0x76fbe88bbdf31fcaul, 0x22e817865236ad3aul },
    { 0x26b77c881dc8b1c9ul, 0x02bc7dcfcc4878e0ul, 0xb238a3f5c70a00bful, 0x10c9efe573e86fa5ul },
    { 0x3ea283c72b89bbb6ul, 0xc084f309edffef02ul, 0x4d6f80e745c6bddbul, 0x0a94f16be920d85ful },
    { 0xdf3da0ebcd69101aul, 0xbc2c1ea81d6465b5ul, 0xc7888fedb770494aul, 0x23ed72b4d01d14e3ul },
    { 0xe8d8f1022eb6bb74ul, 0x98df815a77cb162dul, 0xed0e6cbb511ac384ul, 0x17c5115640e4cebeul },
    { 0xb99680a82772e4fcul, 0x73e09e1fc813959ful, 0xcf765245750eb047ul, 0x2e507fcca290d0d9ul },
    { 0xfc8803013292bbbful, 0x2433f055cb71d70dul, 0x6af6cce65c8d1216ul, 0x0d4a98999f5b3917ul },
    { 0xa1bd3c335eccfa21ul, 0x321d829e22a7a3b7ul, 0xb3c01261a03dc125ul, 0x238d8022cc09c21aul },
    { 0x70e454ed9f4ae165ul, 0x43ce365613d5b397ul, 0xb81dc8292e35d8e9ul, 0x010cd8e4c2b7051cul },
    { 0x8e03539590ecc027ul, 0x861173a90fb23123ul, 0xb11178cf0ea3c6aaul, 0x088027e54f2a3604ul },
    { 0x8302b73e464819dbul, 0x61165468daa93810ul, 0xb4cd7aa7e5a9a6d1ul, 0x1b840f5311a2b1d4ul },
    { 0xcb366fcd8db78dc1ul, 0x9a3a346e44198ea0ul, 0xf9b764b1e16c1592ul, 0x2bf51a5da1828a1cul },
    { 0xd56a3a50f6f23827ul, 0x26b8872f9c7beef9ul, 0xe68a6a86767a7fe7ul, 0x206ad089d8d296fful },
    { 0x9fc07ff88eac550cul, 0xeaec4b6d617c7c19ul, 0x1a54e0a99ac16d05ul, 0x24d19193171494faul },
    { 0x95d9f9fbaf152138ul, 0x2c40662278b9c0b9ul, 0xf33d88246a40dfb3ul, 0x1dd654a2ca9d9f24ul },
    { 0x8acf57f3789785e4ul, 0x8c85f05b0fe7793bul, 0x59d20ecbd3a60110ul, 0x0d171025c925f6e2ul },
    { 0x98b9908fed877d55ul, 0x1d9e8cf2b80d95ddul, 0x45cd99ccb0f7c879ul, 0x055bef435a43aec2ul },
    { 0x3b75765d0e595f0eul, 0xbe63d0ad4cfd9f20ul, 0x8a2a3f42d9359a14ul, 0x10d2ac8c61c8a2e8ul },
    { 0x296e3d0790dcfa56ul, 0x254d7966ddc41e85ul, 0x82a84057ec3ba6b2ul, 0x103479710e709969ul },
    { 0x8225f8372921807bul, 0xde96f9aa340db163ul, 0x5914ffb48c765da8ul, 0x2a366f0448fda3c0ul },
    { 0x04626b63285837a4ul, 0x153bb8899aeb686cul, 0x919b6e0378d00594ul, 0x16be0fb8ef62da17ul },
    { 0x2cfd8c78a15bc370ul, 0x2dec8a0b2aa5a4d5ul, 0x60abbc7f0d0d24c3ul, 0x0417038500e9d06cul },
    { 0xe5a0308fdd013812ul, 0x4f4d76480bc486a3ul, 0xf66ec6f4493ff9b5ul, 0x26a6873b43ffd2ccul },
    { 0x391922d36278c498ul, 0x2f3db9b2aa8aa9f7ul, 0xa96251914fe5ad26ul, 0x0a3314a838f32630ul },
    { 0x44f4b59399027da4ul, 0xaeadb46a090b15a0ul, 0x7f462d4821f48f86ul, 0x0fde0c5429a6beb0ul },
    { 0xf11a1c89cda2c8a9ul, 0xb517e1eb535a984dul, 0x9b357e4163793b0bul, 0x0abc2d5049972a6bul },
    { 0x735205dbb77c464eul, 0x1b427a5f173f7f17ul, 0x1d21722fb21e5505ul, 0x0dab51d6e3ebfa66ul },
    { 0xe9b92e70a8c1ae03ul, 0xb21be5c2d68fb8eful, 0x51af6cc37123652ful, 0x29c36622598b511dul },
    { 0x0d6bbe7ea2fbc85cul, 0xc41c4096e53ac699ul, 0xae846bc0b700d0bcul, 0x2c03ec80adac2a33ul },
    { 0xb8b521e3cebe1e0dul, 0x317303116017d893ul, 0xbdb4c6852d065105ul, 0x0918fdbe9cf3a59ful },
    { 0xa9d2135acabe2359ul, 0x176a79df4f7acf79ul, 0x599dd13cd7e495a8ul, 0x1f19ec22e69ca33ful },
    { 0x46447b2911080704ul, 0x8c4c76b29ceb0013ul, 0xeb32b872eb7f7692ul, 0x1c4b037c8ae85ee1ul },
    { 0xaf0a69c534efd8dbul, 0xba3131e04d420de5ul, 0x6c826d0bde341766ul, 0x2b68900ed906616dul },
    { 0x723d4f0c782bc7f0ul, 0xa180ff6dfb397ceful, 0x448f8dac653c8daaul, 0x20ca92aa222fcc69ul },
    { 0x1f6186289b66b2b6ul, 0x7045a5ab7ac05394ul, 0x75276fc82057db33ul, 0x10d22d05bdff6bb3ul },
    { 0xe5ca79e88bdd6cd9ul, 0x5aa910b4a00636d1ul, 0x98f32ba45784cb43ul, 0x0b1ffdbb529367bbul },
    { 0x6f89bcc33022ce9ful, 0x82c7b4f82e5e515ful, 0xed757ec705eccf82ul, 0x2da32b38e7984bc2ul },
    { 0xd292cecc6abed1bbul, 0xb87eb33958031e94ul, 0x2674b8b55a886725ul, 0x042593ad87403f6dul },
    { 0x9308fbd6e7d419f1ul, 0x051faedab463a6deul, 0x19d7367bf49b3f01ul, 0x181fa1b4d067783aul },
    { 0x34927188c60de660ul, 0xa8e35b00ed8a815cul, 0x5683c95515c26028ul, 0x15aaa6cc9b7900b1ul },
};

constant ulong RC_FULL_POST[3][2][4] = {
    { { 0x6787320212f75a7aul, 0x80b1a636f5a0ecedul, 0xbc63234f057254c2ul, 0x1bf28a93209084bbul },
      { 0x6f8c9d81a620cb6ful, 0x56273b312f805c8eul, 0x2cd9e229776118f1ul, 0x1cdb8c8bee5426f0ul } },
    { { 0xf8ea0e8760d5ca7eul, 0x516df2505cc387a0ul, 0x162e0facb5f1876ful, 0x08299c0abf196d53ul },
      { 0x4117269d7c710b8aul, 0x2d76c0072cabd112ul, 0x8a7b7b58cb65c496ul, 0x221643d205fe8277ul } },
    { { 0x487920d43343dbfful, 0xf6bd10c3f74b22dbul, 0xb7a0143a28c88767ul, 0x2d036a95f81cf49bul },
      { 0x6d5d1bb7a172ebd2ul, 0x7cd4a39486729fbcul, 0xea414fb1bceca226ul, 0x08a50897c06aafe6ul } },
};

kernel void poseidon2_t2_jobs(
    device const uchar* states_in  [[buffer(0)]],
    device       uchar* states_out [[buffer(1)]],
    constant uint&      n           [[buffer(2)]],
    uint tid [[thread_position_in_grid]])
{
    if (tid >= n) return;

    ulong s0[4], s1[4];
    from_bytes_be(s0, states_in + tid * 64);
    from_bytes_be(s1, states_in + tid * 64 + 32);

    if (ge_mod(s0) || ge_mod(s1)) {
        // Non-canonical input: write zeros to flag failure.
        for (int k = 0; k < 64; ++k) states_out[tid * 64 + k] = 0u;
        return;
    }

    mat_external(s0, s1);

    for (int i = 0; i < 3; ++i) {
        add_rk_full(s0, s1, RC_FULL_PRE[i][0], RC_FULL_PRE[i][1]);
        sbox(s0); sbox(s1);
        mat_external(s0, s1);
    }
    for (int i = 0; i < 50; ++i) {
        add_rk_partial(s0, RC_PARTIAL[i]);
        sbox(s0);
        mat_internal(s0, s1);
    }
    for (int i = 0; i < 3; ++i) {
        add_rk_full(s0, s1, RC_FULL_POST[i][0], RC_FULL_POST[i][1]);
        sbox(s0); sbox(s1);
        mat_external(s0, s1);
    }

    to_bytes_be(states_out + tid * 64,        s0);
    to_bytes_be(states_out + tid * 64 + 32,   s1);
}
