// Poseidon2-Goldilocks-t=8 KAT (CPU + C-ABI Merkle-Damgard).
//
// Vectors generated from horizen-labs/poseidon2 @ main with the
// POSEIDON2_GOLDILOCKS_8_PARAMS instance:
//   https://github.com/HorizenLabs/poseidon2
//   plain_implementations/src/poseidon2/poseidon2_instance_goldilocks.rs
//   plain_implementations/src/poseidon2/poseidon2.rs
//
// Generator harness: poseidon/scripts/p2g_kat_gen/ (Rust crate that imports
// the upstream `zkhash` crate and dumps inputs+outputs as C++ literals).
//
// Two layers are checked:
//   (a) Raw t=8 permutation byte-equality vs upstream `permutation()`.
//   (b) C-ABI poseidon_goldilocks() byte-equality against an independently
//       computed Merkle-Damgard reference (4-lane absorb into top half of an
//       8-lane state, all-zero IV, 32-byte big-endian I/O).

#include "../cpp/poseidon_goldilocks.hpp"
#include "../cpp/goldilocks.hpp"
#include "crypto.h"

#include <cstdio>
#include <cstdint>
#include <cstring>

extern "C" int poseidon_goldilocks(const uint8_t* in, size_t in_len, uint8_t out[32]);

namespace {

int g_failures = 0;

struct PermKAT {
    const char* name;
    uint64_t in[8];
    uint64_t expected[8];
};

struct MdKAT {
    const char* name;
    int         block_count;
    uint64_t    blocks[8][4];      // up to 8 blocks of 4 lanes
    uint64_t    expected[4];
};

// 10 raw-permutation KATs from upstream `Poseidon2::permutation` on
// POSEIDON2_GOLDILOCKS_8_PARAMS.
const PermKAT PERM_KATS[] = {
    { "perm_0",
      {UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000)},
      {UINT64_C(0x3a7def562f511210), UINT64_C(0xab0afaf9756476a0), UINT64_C(0x8faf5cc269ff0a14), UINT64_C(0xd6818fc87ccd41ba), UINT64_C(0x8baed826fea3ff62), UINT64_C(0xe133a5f5d18335c6), UINT64_C(0x291171699652ccaa), UINT64_C(0xc63ff85a9e199a0d)} },
    { "perm_1",
      {UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000001), UINT64_C(0x0000000000000002), UINT64_C(0x0000000000000003), UINT64_C(0x0000000000000004), UINT64_C(0x0000000000000005), UINT64_C(0x0000000000000006), UINT64_C(0x0000000000000007)},
      {UINT64_C(0xc5fb1cfe0b4697bb), UINT64_C(0x4a4a32ff849af473), UINT64_C(0xd2fd266077f8efba), UINT64_C(0xf4ad9b74e833916d), UINT64_C(0xe6648eb0acc11463), UINT64_C(0x8d5529a930d75194), UINT64_C(0xe8c993aa10da6c90), UINT64_C(0xa73104a95b68031c)} },
    { "perm_2",
      {UINT64_C(0x0000000000000001), UINT64_C(0x0000000000000001), UINT64_C(0x0000000000000001), UINT64_C(0x0000000000000001), UINT64_C(0x0000000000000001), UINT64_C(0x0000000000000001), UINT64_C(0x0000000000000001), UINT64_C(0x0000000000000001)},
      {UINT64_C(0x9b6288c71fbc848d), UINT64_C(0x97c7344774824164), UINT64_C(0x6cddc663e35c94e5), UINT64_C(0x021389c1115bb7ae), UINT64_C(0x9ab02fccd4112d00), UINT64_C(0xdd3d0456019a3fd7), UINT64_C(0x078bc0bbf6232017), UINT64_C(0xf8d5b0a7c6d7622f)} },
    { "perm_3",
      {UINT64_C(0xffffffff00000000), UINT64_C(0xffffffff00000000), UINT64_C(0xffffffff00000000), UINT64_C(0xffffffff00000000), UINT64_C(0xffffffff00000000), UINT64_C(0xffffffff00000000), UINT64_C(0xffffffff00000000), UINT64_C(0xffffffff00000000)},
      {UINT64_C(0x5caed410a9fd6849), UINT64_C(0x31151f18cf2b97fb), UINT64_C(0x0edda42264f38cda), UINT64_C(0xff14843277766957), UINT64_C(0x6421bfe1b7a30c8d), UINT64_C(0xe64b19fa554471ad), UINT64_C(0x2da3087bf1b4a9ec), UINT64_C(0xbd4766960009480e)} },
    { "perm_4",
      {UINT64_C(0xfffffffeffffffff), UINT64_C(0x0000000000000001), UINT64_C(0x0000000000000002), UINT64_C(0x0000000000000003), UINT64_C(0x0000000000000004), UINT64_C(0x0000000000000005), UINT64_C(0x0000000000000006), UINT64_C(0x0000000000000007)},
      {UINT64_C(0xa69569790220d110), UINT64_C(0x6d18a83a8e341dc5), UINT64_C(0xc4e0402391f89fb4), UINT64_C(0x4bb0cf88f859a6c4), UINT64_C(0x3fd4dbccdafb4e30), UINT64_C(0x8c6e03f9d835cd39), UINT64_C(0xeb8636fa9acf1235), UINT64_C(0x4c2f415295e129a3)} },
    { "perm_5",
      {UINT64_C(0xdeadbeefdeadbeef), UINT64_C(0xcafebabecafebabe), UINT64_C(0xfeedfacefeedface), UINT64_C(0x0123456789abcdef), UINT64_C(0x1111111111111111), UINT64_C(0x2222222222222222), UINT64_C(0x3333333333333333), UINT64_C(0x4444444444444444)},
      {UINT64_C(0x2054c370dedefb8e), UINT64_C(0x29cc0b28335ec3c0), UINT64_C(0xe84150fccf75c1e7), UINT64_C(0xde67c9dbb51f972e), UINT64_C(0x964a83e3f38145f0), UINT64_C(0x7f6c37a417fa793c), UINT64_C(0x6d8cf157cdfb46ec), UINT64_C(0x16c9327d972b59b4)} },
    { "perm_6",
      {UINT64_C(0xfeedfacefeedface), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000)},
      {UINT64_C(0xc43a3c576935d8b5), UINT64_C(0x02fd43b7c145bc52), UINT64_C(0x8fbdeafb25286d73), UINT64_C(0x8417bd5414681c7d), UINT64_C(0xf0aa012edde330e4), UINT64_C(0x51c0bb09073d93eb), UINT64_C(0x169783ceda86af53), UINT64_C(0xf7a42640575bf554)} },
    { "perm_7",
      {UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000001)},
      {UINT64_C(0xeb260447aea1d1fa), UINT64_C(0xfef7cbf287b61287), UINT64_C(0xb85ab4a66bba93c5), UINT64_C(0x7383fe0739be2f3f), UINT64_C(0xd63ebbb0140ae8bc), UINT64_C(0x2c3880f03f95edb5), UINT64_C(0x9387ac6c2538e1ec), UINT64_C(0xd203fd47916f4beb)} },
    { "perm_8",
      {UINT64_C(0x00000000000000a0), UINT64_C(0x00000000000000a1), UINT64_C(0x00000000000000a2), UINT64_C(0x00000000000000a3), UINT64_C(0x00000000000000a4), UINT64_C(0x00000000000000a5), UINT64_C(0x00000000000000a6), UINT64_C(0x00000000000000a7)},
      {UINT64_C(0xef2c2386d4aebd3b), UINT64_C(0x1f5843c1753dbb14), UINT64_C(0x632cb5d2f7ea4655), UINT64_C(0x15776b4afe10b49e), UINT64_C(0x2fadb0ddf51d21d0), UINT64_C(0xc41d9f41b7881d7e), UINT64_C(0xf76bf6761eef5738), UINT64_C(0x234471d8a69471cc)} },
    { "perm_9",
      {UINT64_C(0xfffffffefffffffe), UINT64_C(0xfffffffefffffffe), UINT64_C(0xfffffffefffffffe), UINT64_C(0xfffffffefffffffe), UINT64_C(0xfffffffefffffffe), UINT64_C(0xfffffffefffffffe), UINT64_C(0xfffffffefffffffe), UINT64_C(0xfffffffefffffffe)},
      {UINT64_C(0xdcc3b6718dc75ee6), UINT64_C(0x63cf8f3df976510a), UINT64_C(0x40ff832c8949d6c7), UINT64_C(0x30a4013223e61332), UINT64_C(0x58b9a44de5f16e53), UINT64_C(0x6867efbb083da584), UINT64_C(0xe722a5e2076c8683), UINT64_C(0x1f5cc61c4d941da6)} },
};
constexpr int N_PERM_KATS = sizeof(PERM_KATS) / sizeof(PERM_KATS[0]);

// 8 Merkle-Damgard KATs computed by feeding the *same* upstream Rust
// permutation in a 4-lane sponge. Asserts:
//   poseidon_goldilocks(input_bytes, 32 * block_count, out)
// produces the expected first 32 bytes (top 4 lanes) of the final state.
const MdKAT MD_KATS[] = {
    { "md_0", 1, {{UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000)}},
      {UINT64_C(0x3a7def562f511210), UINT64_C(0xab0afaf9756476a0), UINT64_C(0x8faf5cc269ff0a14), UINT64_C(0xd6818fc87ccd41ba)} },
    { "md_1", 1, {{UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000001), UINT64_C(0x0000000000000002), UINT64_C(0x0000000000000003)}},
      {UINT64_C(0x65ea097f86ef088d), UINT64_C(0x1fa93a79dfba07b8), UINT64_C(0xf6f2442e0ea16c55), UINT64_C(0x41234125676442b6)} },
    { "md_2", 2, {
        {UINT64_C(0x0000000000000001), UINT64_C(0x0000000000000002), UINT64_C(0x0000000000000003), UINT64_C(0x0000000000000004)},
        {UINT64_C(0x0000000000000005), UINT64_C(0x0000000000000006), UINT64_C(0x0000000000000007), UINT64_C(0x0000000000000008)} },
      {UINT64_C(0x2468d9f8b8421ada), UINT64_C(0x6e56a90ae021624f), UINT64_C(0xe2e76fddbc4a2c05), UINT64_C(0x2f3e207b561da899)} },
    { "md_3", 1, {{UINT64_C(0xfffffffeffffffff), UINT64_C(0x0000000000000001), UINT64_C(0x0000000000000002), UINT64_C(0x0000000000000003)}},
      {UINT64_C(0xbf0d2d95c6413f3b), UINT64_C(0x100b1c62d64863a4), UINT64_C(0x86686be2bbcc37b7), UINT64_C(0x6c1ddb6c27073b8b)} },
    { "md_4", 3, {
        {UINT64_C(0x0000000000000001), UINT64_C(0x0000000000000001), UINT64_C(0x0000000000000001), UINT64_C(0x0000000000000001)},
        {UINT64_C(0x0000000000000002), UINT64_C(0x0000000000000002), UINT64_C(0x0000000000000002), UINT64_C(0x0000000000000002)},
        {UINT64_C(0x0000000000000003), UINT64_C(0x0000000000000003), UINT64_C(0x0000000000000003), UINT64_C(0x0000000000000003)} },
      {UINT64_C(0xdb7e8ff901d891a9), UINT64_C(0x0fd75591da14813f), UINT64_C(0x7ee0375aaa70d98b), UINT64_C(0x72dc94d20b43e39e)} },
    { "md_5", 1, {{UINT64_C(0xdeadbeefdeadbeef), UINT64_C(0xcafebabecafebabe), UINT64_C(0xfeedfacefeedface), UINT64_C(0x0123456789abcdef)}},
      {UINT64_C(0x931f8bd7927aa8e1), UINT64_C(0xfce1715a3490a344), UINT64_C(0xf454b71ed18ae72b), UINT64_C(0x2521b614838e6c5e)} },
    { "md_6", 4, {
        {UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000001)},
        {UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000002)},
        {UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000003)},
        {UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000000), UINT64_C(0x0000000000000004)} },
      {UINT64_C(0x4e4f9bdb3b97b78d), UINT64_C(0x7c2bed441032757b), UINT64_C(0xfdb34a7358290506), UINT64_C(0xb4e973df6ad85ae3)} },
    { "md_7", 2, {
        {UINT64_C(0x00000000000000a0), UINT64_C(0x00000000000000a1), UINT64_C(0x00000000000000a2), UINT64_C(0x00000000000000a3)},
        {UINT64_C(0x00000000000000b0), UINT64_C(0x00000000000000b1), UINT64_C(0x00000000000000b2), UINT64_C(0x00000000000000b3)} },
      {UINT64_C(0x78435d10c2a3f06a), UINT64_C(0x9d39ae6738e9f0d3), UINT64_C(0x23b7f935e605757e), UINT64_C(0x17bc604e3365cb1c)} },
};
constexpr int N_MD_KATS = sizeof(MD_KATS) / sizeof(MD_KATS[0]);

void be_pack(uint64_t v, uint8_t out[8]) {
    for (int i = 7; i >= 0; --i) {
        out[i] = (uint8_t)(v & 0xFFu);
        v >>= 8;
    }
}

uint64_t be_unpack(const uint8_t in[8]) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | (uint64_t)in[i];
    return v;
}

void check_perm() {
    using namespace kinet::crypto::poseidon;
    for (int i = 0; i < N_PERM_KATS; ++i) {
        const auto& k = PERM_KATS[i];
        uint64_t s[8];
        std::memcpy(s, k.in, sizeof(s));
        p2g::permutation_t8(s);
        for (int j = 0; j < 8; ++j) {
            if (s[j] != k.expected[j]) {
                ++g_failures;
                std::fprintf(stderr,
                    "FAIL %s lane %d: got 0x%016llx want 0x%016llx\n",
                    k.name, j,
                    (unsigned long long)s[j],
                    (unsigned long long)k.expected[j]);
                break;
            }
        }
    }
}

void check_md() {
    for (int i = 0; i < N_MD_KATS; ++i) {
        const auto& k = MD_KATS[i];
        uint8_t in[8 * 32] = {0};  // up to 8 blocks
        for (int b = 0; b < k.block_count; ++b) {
            for (int j = 0; j < 4; ++j) {
                be_pack(k.blocks[b][j], in + b * 32 + j * 8);
            }
        }
        uint8_t out[32];
        int rc = poseidon_goldilocks(in, (size_t)k.block_count * 32, out);
        if (rc != CRYPTO_OK) {
            ++g_failures;
            std::fprintf(stderr, "FAIL %s: poseidon_goldilocks rc=%d\n", k.name, rc);
            continue;
        }
        for (int j = 0; j < 4; ++j) {
            uint64_t got = be_unpack(out + j * 8);
            if (got != k.expected[j]) {
                ++g_failures;
                std::fprintf(stderr,
                    "FAIL %s lane %d: got 0x%016llx want 0x%016llx\n",
                    k.name, j,
                    (unsigned long long)got,
                    (unsigned long long)k.expected[j]);
                break;
            }
        }
    }
}

void check_argument_validation() {
    // Empty input: legal (zero blocks → all-zero IV → emit IV's top 4 bytes
    // which is just zeros — no permutation runs).
    uint8_t out[32];
    int rc = poseidon_goldilocks(nullptr, 0, out);
    if (rc != CRYPTO_OK) {
        ++g_failures;
        std::fprintf(stderr, "FAIL empty input rc=%d\n", rc);
    } else {
        for (int i = 0; i < 32; ++i) {
            if (out[i] != 0) {
                ++g_failures;
                std::fprintf(stderr, "FAIL empty input: byte %d != 0 (%02x)\n", i, out[i]);
                break;
            }
        }
    }

    // null out
    uint8_t in_block[32] = {0};
    if (poseidon_goldilocks(in_block, 32, nullptr) != CRYPTO_ERR_INPUT) {
        ++g_failures;
        std::fprintf(stderr, "FAIL null out: expected CRYPTO_ERR_INPUT\n");
    }

    // bad length
    if (poseidon_goldilocks(in_block, 31, out) != CRYPTO_ERR_LENGTH) {
        ++g_failures;
        std::fprintf(stderr, "FAIL len=31: expected CRYPTO_ERR_LENGTH\n");
    }

    // non-canonical lane (>= p): set first 8 bytes to 0xFFFFFFFF00000001 (== p).
    uint8_t bad[32] = {0};
    bad[0] = 0xff; bad[1] = 0xff; bad[2] = 0xff; bad[3] = 0xff;
    bad[4] = 0x00; bad[5] = 0x00; bad[6] = 0x00; bad[7] = 0x01;
    if (poseidon_goldilocks(bad, 32, out) != CRYPTO_ERR_INPUT) {
        ++g_failures;
        std::fprintf(stderr, "FAIL non-canonical: expected CRYPTO_ERR_INPUT\n");
    }
}

void check_status_bit() {
    if (crypto_alg_status(CRYPTO_ALG_POSEIDON_GLDLKS) != 1) {
        ++g_failures;
        std::fprintf(stderr,
            "FAIL crypto_alg_status(POSEIDON_GLDLKS)=0; expected 1\n");
    }
}

void check_field_self_consistency() {
    using namespace kinet::crypto::poseidon::gf;
    // p - 1 + 1 = 0 (mod p)
    uint64_t a = MOD - 1;
    if (add(a, 1) != 0) { ++g_failures; std::fprintf(stderr, "FAIL field add wrap\n"); }
    // (2^32-1) * (2^32-1) mod p
    uint64_t r = mul(0xFFFFFFFFULL, 0xFFFFFFFFULL);
    // (2^32-1)^2 = 2^64 - 2*2^32 + 1 = (2^32 - 1) - 2*2^32 + 1 + p
    //            = 2^32 - 2*2^32 = -2^32 mod p = p - 2^32 = 0xFFFFFFFEFFFFFFFE + 1
    // Compute the same with an independent method:
    unsigned __int128 t = (unsigned __int128)0xFFFFFFFFULL * 0xFFFFFFFFULL;
    uint64_t lo = (uint64_t)t;
    uint64_t expect_canon = lo;  // hi == 0 here
    if (expect_canon >= MOD) expect_canon -= MOD;
    if (r != expect_canon) {
        ++g_failures;
        std::fprintf(stderr, "FAIL field mul small: got 0x%016llx want 0x%016llx\n",
            (unsigned long long)r, (unsigned long long)expect_canon);
    }
    // pow7(2) = 128
    if (pow7(2ULL) != 128ULL) {
        ++g_failures; std::fprintf(stderr, "FAIL pow7(2) != 128\n");
    }
    // pow7(p-1) = (p-1)^7 mod p. (p-1)^2 = 1, so (p-1)^7 = p-1.
    if (pow7(MOD - 1) != MOD - 1) {
        ++g_failures; std::fprintf(stderr, "FAIL pow7(p-1) != p-1\n");
    }
}

}  // namespace

int main() {
    check_field_self_consistency();
    check_perm();
    check_md();
    check_argument_validation();
    check_status_bit();

    if (g_failures == 0) {
        std::printf("PASS poseidon_goldilocks_test (perm=%d md=%d field+abi=ok)\n",
            N_PERM_KATS, N_MD_KATS);
        return 0;
    }
    std::fprintf(stderr, "FAIL poseidon_goldilocks_test (%d failures)\n", g_failures);
    return 1;
}
