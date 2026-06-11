// WGSL compute shader for Lamport-SHA256 OTS — one thread per 32-byte
// preimage. Byte-equal to lamport/cpp/lamport.cpp. Mirrors
// lamport/gpu/metal/lamport_batch.metal and lamport/gpu/cuda/lamport.cu.
//
// Buffers:
//   slots   : array<u32>   (8 u32 = 32 bytes per slot, big-endian-packed)
//   digests : array<u32>   (8 u32 = 32 bytes per slot, big-endian-packed)
//   params  : Params       (uniform { num_slots: u32 })

struct Params { num_slots: u32 };

@group(0) @binding(0) var<storage, read>       slots:    array<u32>;
@group(0) @binding(1) var<storage, read_write> digests:  array<u32>;
@group(0) @binding(2) var<uniform>             params:   Params;

const K: array<u32, 64> = array<u32, 64>(
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
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
);

fn rotr32(x: u32, n: u32) -> u32 {
    return (x >> n) | (x << (32u - n));
}

fn ch (x: u32, y: u32, z: u32) -> u32 { return (x & y) ^ ((~x) & z); }
fn maj(x: u32, y: u32, z: u32) -> u32 { return (x & y) ^ (x & z) ^ (y & z); }
fn S0 (x: u32) -> u32 { return rotr32(x,  2u) ^ rotr32(x, 13u) ^ rotr32(x, 22u); }
fn S1 (x: u32) -> u32 { return rotr32(x,  6u) ^ rotr32(x, 11u) ^ rotr32(x, 25u); }
fn s0 (x: u32) -> u32 { return rotr32(x,  7u) ^ rotr32(x, 18u) ^ (x >>  3u); }
fn s1 (x: u32) -> u32 { return rotr32(x, 17u) ^ rotr32(x, 19u) ^ (x >> 10u); }

@compute @workgroup_size(64)
fn lamport_hash_jobs(@builtin(global_invocation_id) gid: vec3<u32>) {
    let tid = gid.x;
    if (tid >= params.num_slots) { return; }

    var w: array<u32, 64>;
    let in_base = tid * 8u;
    for (var i = 0u; i < 8u; i = i + 1u) {
        w[i] = slots[in_base + i];
    }
    w[ 8] = 0x80000000u;
    w[ 9] = 0u; w[10] = 0u; w[11] = 0u;
    w[12] = 0u; w[13] = 0u; w[14] = 0u;
    w[15] = 256u;
    for (var i = 16u; i < 64u; i = i + 1u) {
        w[i] = s1(w[i - 2u]) + w[i - 7u] + s0(w[i - 15u]) + w[i - 16u];
    }

    var a: u32 = 0x6a09e667u;
    var b: u32 = 0xbb67ae85u;
    var c: u32 = 0x3c6ef372u;
    var d: u32 = 0xa54ff53au;
    var e: u32 = 0x510e527fu;
    var f: u32 = 0x9b05688cu;
    var g: u32 = 0x1f83d9abu;
    var h: u32 = 0x5be0cd19u;

    for (var i = 0u; i < 64u; i = i + 1u) {
        let t1 = h + S1(e) + ch(e, f, g) + K[i] + w[i];
        let t2 = S0(a) + maj(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    a = a + 0x6a09e667u;
    b = b + 0xbb67ae85u;
    c = c + 0x3c6ef372u;
    d = d + 0xa54ff53au;
    e = e + 0x510e527fu;
    f = f + 0x9b05688cu;
    g = g + 0x1f83d9abu;
    h = h + 0x5be0cd19u;

    let out_base = tid * 8u;
    digests[out_base + 0u] = a;
    digests[out_base + 1u] = b;
    digests[out_base + 2u] = c;
    digests[out_base + 3u] = d;
    digests[out_base + 4u] = e;
    digests[out_base + 5u] = f;
    digests[out_base + 6u] = g;
    digests[out_base + 7u] = h;
}
