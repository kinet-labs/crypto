// =============================================================================
// pedersen vector-commitment KAT vectors (auto-generated; DO NOT EDIT BY HAND).
// Source: gnark-crypto bn254.HashToG1 + Pedersen-vector reference impl.
// Suite : BN254 G1, DST = "PEDERSEN_SEEDED_GEN_V1"
// Tool  : pedersen/test/tools/gen_pedersen_kat.go
// =============================================================================
//
// Encoding: every affine coordinate is 32-byte big-endian raw Fp (no compression
//           flag), identical to gnark-crypto's bn254.G1Affine.X.Bytes().
//           Every Fr scalar is 32-byte big-endian, already reduced.
//
// === BEGIN PEDERSEN_GENS_KAT ===
static constexpr unsigned PEDERSEN_KAT_N = 8;
static const char PEDERSEN_KAT_SEED_HEX[] = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
static const char* const PEDERSEN_KAT_GENS_X_HEX[] = {
    "0563aa8a283f268b65b4210a0a78ee1341f76b59d94c1ac626effe1a5aa0c6b7", // G[0].x
    "29ebf4392683dcb418584dd8ecd1e1dd16b486147e676dbf4b62779a340f3186", // G[1].x
    "1e99431ac6e3e12778e5f3757219575820a57d9792652323ab1a7fc353683214", // G[2].x
    "25033390a5b7b8ab8915bc1567af3f9502d100bf015ce420c0881935e2c25767", // G[3].x
    "18601a4a12b2250f8bc13effd442bf33fc0be460fa4b6541006f0de2a60c1d44", // G[4].x
    "0929ae1d590423ed44b1cb7b7fcc7975f4c09273507c6fcfbd20b3278d9b12ff", // G[5].x
    "2867dba91f493bdaec39fb1c9651ae553022425fa94dcdd06e5b41a250247892", // G[6].x
    "07b8efc1362432de028a960251b26157533eb42f08c617192db68eff5538e133", // G[7].x
};
static const char* const PEDERSEN_KAT_GENS_Y_HEX[] = {
    "185c1e42d1c069d596e98873aa62b6bd87d8a0bc8dc095b3b8333c3084091167", // G[0].y
    "1cbd69c9b9ea08bc9aef5a1e1a9af5436ad33533ee7a63d51b66e13281b71de1", // G[1].y
    "1c58f524479ac635e86d38583bf2591965b67c746790b5bf5af013cbb7c36360", // G[2].y
    "09b546a3268b7cdd67b34a8aa4ab3494ca1de072ffcd0d5e90304a95ebbdb84d", // G[3].y
    "13c7c480c5c12274329401777d78977b780b65bdf577e99f8b2766b76e3d7a6c", // G[4].y
    "1193185de72f0fc8cd01537e0c07740f920078a169355bc1d7a67b26265aee50", // G[5].y
    "001bc28e3a6435c0c41b170d1f2b341f7b8d975b92213fb5696af33fd8c2607f", // G[6].y
    "05f93cf68a97f4840d117822082e2aaf2fdbe79b14957c23b420136f4370884c", // G[7].y
};
static const char PEDERSEN_KAT_H_X_HEX[] = "19c0bbd406deeb6226fcb5d8bcea1b0c99a65f6bfe27b752df150c68a65707ef";
static const char PEDERSEN_KAT_H_Y_HEX[] = "1bc7aa4ab5e2edee20e5c3f7aea2a55f61f0a92d96946c309d6e7503079524a1";
// === END PEDERSEN_GENS_KAT ===

// === BEGIN PEDERSEN_ROUNDTRIP_KAT ===
static constexpr unsigned PEDERSEN_KAT_ROUNDS = 5;
struct PedersenRoundKAT {
    const char* scalars_hex[8]; // N=8 scalars
    const char* blinding_hex;
    const char* commitment_x_hex;
    const char* commitment_y_hex;
};
static const PedersenRoundKAT PEDERSEN_KAT_ROUNDTRIPS[] = {
    {
        { "13cb0f7d1aaa55d7a966e8c87a51a657f4ac6c8655d1bf1da04abeb0509d9db8", "1c778148f8219fa0728ba27c986dd048a0c4ba0cd40655d751ea694f439f7450", "1ff5f144851e3ddc96c948ad38489a1cea45e00aafa7bf39b98fedb3d1c2740a", "0541475e72e52c069e43ed6057efeef9e292c323fe6caa61ce85e3418801807b", "25f8a1f2160146fdba53b761e5fec86fc0a68cb97f97332c0102f77ab0a43ea4", "17e0fb810986f2a514bbeb297492b5aeb9611dcac80045600f970a33ccabd410", "227a8a01f199d5bc7e25d0665f0b62ed388f7120e512bdb708b52b5d35657d55", "19b380bc6744a7f6364eb912c85c4e355e638430944acd2837c97219fa604c07" },
        "07366a312cf964243d845b65109fa14db4580e389ba7e3141d3948ea05a32a6f",
        "301fa59af8ec6c2e5a37e8a3bb3f90fcf911f5404f24c66786decb943cbb12d9",
        "18eb569aabd6b20fdcea7ca2207f267c7d80575e3ce00eec3b1d34fbe39d9bc2",
    },
    {
        { "199050684a4433c771a69c491f21167e521a5536d55bed7810e18718e676e1e3", "1a98ac3fba9addea1f63c7469b214d168c7a6cc14dc0e7dc13d5eb2abbf620df", "21430ce9f8825312a4f238e4df51a0480812a66eae8552e51659bf37de91e0d5", "0e71b47174441bbe49468ea375ad1a99a2b385caff8f053b653e3ec77023433c", "0e8d16d17d1e304a6793edf0b822bed25f92afcaabcb9627a11350a1e404d690", "12c4e5d7f8f7eaa993bcddddc9d5f1fd4db34896559f0ba320b1804c0ad0481c", "0a25bd6477133cc8e69073ed5be91beee7ee869c14253027391231ae0d3c69a4", "2ec059338b3279f25bfc03cbed6259b13d97ab39181078f86462a369f028ef7e" },
        "03d763a90d4bfea9e0eb17844b67e66f4d9457fba10a5f13d2c61d38dbf1912f",
        "26633c138a084482ea4a51a7ccd56c917219653b67dec4a82397c05f384a5a86",
        "2c8bf8e97ad27ba56d4acbb2c249fec792a4c147d706f754b6c8b2a9763404a5",
    },
    {
        { "2bd1fbac2a92f1d6376d58d00d14880d8cf783492bc9eda3d2c090b8d26116a9", "05ef4eef347dabca886374d379df4d199f86cf6b0f9edef841544ba6f576ee36", "150226e70948e0b41abc663788079445f8bdd3cad58b7b9a3738a53d1ac0ee37", "038ed143eac59289423dafc0e6e56d1d0f6f3d8b42bab9f782046855a9915213", "296a39757b72af175295e2ee22bde76608455ac2327fe933f242e52300cd134d", "026c51f51e4be6a0e9937f62e2456c0e237acf9faa4e992225b7bb275bf96fa0", "058e754c4b068d05ab694cc6673ce385112e0eeba65af92b7e0aca1d0baced3d", "210030faf51e439086e02f017c7238c0c3c7832767344ce6665b45fd0e9bfd27" },
        "0c3885f5411514f9f1f6aed8201116b7078736785fdc6cca142dcb8e060c15f1",
        "283f6ab3400d87b428b528a5b3258230371f55601f6ebfde1ceb1599fa7e2745",
        "075125622335f6376d87e1798ca9a3005912b4169067e16eeb70aed0ebfefdd9",
    },
    {
        { "2b6b9691a240dec59e4e616335605a9848219e4a481ecb471829e807e8b0e418", "1610945f584ed2acd048afbbcfeba56046c63babfbc3c7646509195bda9c0772", "132847c15807e19e268b7e0ac1f11ad739fe18c0d165c0cdcee8162b5e4ffbd9", "004278a3da3390bd440b3c943243da81b0faf9fd9d787e7aa2687b897d833e5e", "2ee115d2687a3f272484519a761460dc9747a63d3731851ae6b9fec13d204dd6", "01ddefa3608e61af5e0a01ed3bb8c2614da98d6569fb0fb9c15e42d460e682d0", "2e0bf651a3e739e3db55e9a20ff21098e12d4605a39f41a3d08b80722b4b344d", "15ce6933f0dc37c3395e3731d773ee32293d2123487654cc55ea54e7cd202133" },
        "2df10e6745e3d318d56e7b1cd1cca08b93ce2c12ba5ebb2b605ba058a4c9d54c",
        "234573620bd3690654c5afa59ffb8203f0c5405babcdeeaa08d41aa7b3c6332f",
        "2c07f81dce94b2887659b7d77dac1fc3f12f40ff78f8743119311ab34b337670",
    },
    {
        { "232d5cfa0ee4f7cf37b1f2ec0b3a74c2709610917bc3d4269fd179feefaeaf34", "1f94abe3e26a46d1248de4476ca8666962dc6c0d417a581f801c04cfe60571e9", "27c254d769b68672b7059188886fdd91b6409cfbcff555373cb0a8b6fffdfada", "1039aa47488bf1954289356d4384342928f28668aa20d847d3a722f7bc3d47a7", "1614fa301bdb7eb217af515951beaa0fe552ece75e04be00bcf9a8e3459d89a9", "190eca27c9bf8fe07af8e547aaa0cece3b26d98b2f9ddec14f77b8c8d02b268c", "13746d6bfd6880c8cf9cb8b788e0b5b34a280058c8f69118ca8373c487974735", "0c19c22f892df7c300da3aeb0b84f1f87b89ef5c2b02aed3c11b4f5df8836658" },
        "0a41a9eb9aa8cd9b005558174235f5e560c3303d9ca634cf2d43b3eb645e6da2",
        "2b356121e3680605d3cb2ba9f78aa064226d92cdac861e280df360a4a28d9ae9",
        "122739562e5b65c5aa457a0c589a5ed1929e013dc2fced74acf22f4df3657a80",
    },
};
// === END PEDERSEN_ROUNDTRIP_KAT ===
