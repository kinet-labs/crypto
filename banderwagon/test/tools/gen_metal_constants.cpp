// Codegen for the Metal Banderwagon constant table.
//
// Pulls the Bandersnatch base-field modulus q, scalar-field modulus r,
// Montgomery R, R^2, qInvNeg/rInvNeg, the curve constants a and d, and the
// generator coordinates X/Y from the CPU body itself (banderwagon/cpp/{fp,fr,
// element}.cpp) and emits a Metal header at the path given on argv[1]. The
// kernel includes that file so the GPU kernel and the CPU canonical share
// exactly one source of truth -- drift is impossible by construction.
//
// Same generator pattern as poseidon_gen_metal_constants.

#include "../../cpp/fp.hpp"
#include "../../cpp/fr.hpp"
#include "../../cpp/element.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstdint>

using kinet::banderwagon::Fp;
using kinet::banderwagon::Fr;
using kinet::banderwagon::Element;
using kinet::banderwagon::curve_a;
using kinet::banderwagon::curve_d;

namespace {

// Get the Montgomery one for Fp.
//   Fp::one() returns R mod q in 4 LE limbs.
void dump_fp_one(std::uint64_t out[4]) {
    Fp one = Fp::one();
    out[0] = one.limbs[0];
    out[1] = one.limbs[1];
    out[2] = one.limbs[2];
    out[3] = one.limbs[3];
}

void dump_fr_one(std::uint64_t out[4]) {
    Fr one = Fr::one();
    out[0] = one.limbs[0];
    out[1] = one.limbs[1];
    out[2] = one.limbs[2];
    out[3] = one.limbs[3];
}

// Get R^2 mod q for Fp by computing it via from_bytes_le of canonical 1 and
// observing that to_mont(1) = R, then R*R = R^2 in canonical, but easier:
// we already know that Fp::from_bytes_le(canonical_1, out) yields out = R.
// To get R^2 we encode R *as canonical bytes* and run from_bytes_le again.
// Simpler approach: hard-code from the CPU constants by reading the four
// limbs of a controlled call. Since both R and R^2 are *defined* identically
// across CPU and GPU, we expose them by mul-pattern: R^2 = ((1 * R^2 / R) * R^2)
// but that requires R^2 already.
//
// Direct path: invoke the same CIOS call. The CPU body has R^2 as a private
// constant. We work around by: encode the canonical integer 1 (limb0 = 1,
// rest = 0) using from_bytes_le -> this produces R (which is Fp::one() in
// Montgomery form). To get R^2 we compute Fp::mul(Fp::one(), Fp::one()) which
// yields 1*1*R^{-1} = R^{-1} — wrong.
//
// Right path: R^2 = R * R in canonical. CPU body offers Fp::mul(a, b) =
// a * b * R^{-1}. So Fp::mul(Fp::one(), Fp::one()) = R * R * R^{-1} = R.
// That's R, not R^2.
//
// To extract R^2 from the CPU body, we treat the *canonical* integer 1 as
// already-Montgomery and convert it to canonical via Fp::to_bytes_le, getting
// the canonical integer R^{-1}. Then we re-encode R^{-1} via from_bytes_le
// -> Mont(R^{-1}) = R^{-1} * R = 1 in Mont form, which is Fp::one() — round trip.
//
// Cleanest: encode the canonical integer R (i.e., the bytes of Fp::one() after
// to_bytes_le applied to a Fp built from the *raw limbs* {1,0,0,0}). Recall
// Fp::to_bytes_le treats input as Montgomery and emits canonical = input *
// 1 (= input * R^{-1}). So Fp({1,0,0,0}).to_bytes_le emits R^{-1} as canonical
// bytes. Then from_bytes_le(those bytes) yields R^{-1} * R^2 / R = R^{-1} * R
// = 1. Round trip again.
//
// Pragmatic approach: just hardcode R^2 here by reading them out of the CPU
// body. Since the CPU body is the canonical, we use a pattern-matching probe:
// from_bytes_le on the canonical integer 0x1 yields R (= Fp::one() = R mod q).
// Then to compute R^2, we encode R itself (Fp::one()'s bytes are *Montgomery*
// limbs, but we want the canonical encoding of R). We get this by raw-LE
// encoding of the four constants R0..R3 (these are the canonical limbs of
// R mod q because Mont(R) := R * R^{-1} * R = R, so the Montgomery rep of
// R is R^2, *not* R).
//
// Wait — that's the answer. R^2 mod q in canonical is the same 4 limbs as
// "what from_bytes_le returns when given the canonical bytes of R". And the
// canonical bytes of R are simply the four LE limbs of R0..R3 written out.
// Since Fp::one() returns the Montgomery form of 1, which is R mod q, its
// limbs are exactly the canonical representation of R (the limbs of R, as
// integers in [0, q)). So:
//
//   Encode Fp::one().limbs as canonical 32 bytes via raw memcpy (treating
//   limbs as the canonical integer R mod q).
//   from_bytes_le on those bytes yields R * R = R^2 in Montgomery form, but
//   from_bytes_le actually multiplies by R^2 internally giving "input * R^2
//   * R^{-1}" = input * R. So feeding R as canonical gives R * R = R^2 in
//   Montgomery, which is *R^3 in canonical*. Wrong.
//
// ---------------------------------------------------------------------------
//
// Final clean answer: R^2 is itself a CPU constant (RSQ_0..RSQ_3 / R2_0..R2_3).
// The cleanest way is to expose those constants via small accessors in the
// CPU body — but the assignment says no extra headers / surface noise. So
// the codegen below recovers R^2 by computing it via the public arithmetic:
//
//   Let M(x, y) = x * y * R^{-1}  (Montgomery multiply).
//   We want R^2 (canonical).
//   M(R, R) = R * R / R = R  (Montgomery mul of R*R in canonical sense, but
//                              both inputs are Montgomery values of 1, so
//                              this is M(Mont(1), Mont(1)) = Mont(1) = R.)
//   What we *really* need: an Fp value whose limbs equal the canonical
//   integer R^2 mod q.
//   M(canonical_x, canonical_y) where x, y are *not* already Montgomery
//   would work if the public API let us pass canonical limbs raw — and it
//   does: Fp({a, b, c, d}) constructs from raw limbs.
//   But M is defined for Montgomery inputs; if we feed canonical inputs the
//   output is x*y/R in canonical. So M(R, R) on canonical inputs = R*R/R = R.
//   Still gives R. Wrong.
//
//   The trick: M(R^2, 1) where 1 is canonical = R^2 * 1 / R = R, also wrong.
//
// Best: read R^2 from the same place the CPU body does — namely, expose it
// via a tiny `internal` accessor in fp.cpp / fr.cpp. Since the prompt says
// "codegen pattern: write gen_banderwagon_constants.cpp that exports
// modulus / R² / Mont_one / d / generator from CPU body to a .metalh header",
// the natural approach is: the CPU body already has these constants as
// internal constexprs; we add a tiny accessor that returns them (analogous
// to poseidon::internal::dump_round_keys).
//
// We do that below. Implementation: expose the raw moduli + Montgomery
// constants via banderwagon::internal::fp_constants() and fr_constants().

}  // namespace

// Forward declarations of internal accessors we add in fp.cpp / fr.cpp.
// Returns the canonical 4 limbs of the named constant.
namespace kinet::banderwagon::internal {
void fp_modulus(std::uint64_t out[4]);
void fp_r_squared(std::uint64_t out[4]);
void fp_r_mod_q(std::uint64_t out[4]);   // == Fp::one() limbs
std::uint64_t fp_qinv_neg();

void fr_modulus(std::uint64_t out[4]);
void fr_r_squared(std::uint64_t out[4]);
void fr_r_mod_r(std::uint64_t out[4]);   // == Fr::one() limbs
std::uint64_t fr_rinv_neg();
}  // namespace kinet::banderwagon::internal

namespace {

void emit_u64x4(std::FILE* fp, const char* name, const std::uint64_t v[4]) {
    std::fprintf(fp,
        "constant ulong %s_0 = 0x%016llxUL;\n"
        "constant ulong %s_1 = 0x%016llxUL;\n"
        "constant ulong %s_2 = 0x%016llxUL;\n"
        "constant ulong %s_3 = 0x%016llxUL;\n\n",
        name, (unsigned long long)v[0],
        name, (unsigned long long)v[1],
        name, (unsigned long long)v[2],
        name, (unsigned long long)v[3]);
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::fprintf(stderr, "usage: %s <output.metalh>\n", argv[0]);
        return 2;
    }

    std::FILE* fp = std::fopen(argv[1], "w");
    if (!fp) {
        std::fprintf(stderr, "cannot open %s for write\n", argv[1]);
        return 1;
    }

    std::fprintf(fp,
        "// Auto-generated by banderwagon_gen_metal_constants. Do not edit.\n"
        "// Source: banderwagon/cpp/{fp,fr,element}.cpp via internal accessors.\n"
        "// Single producer of the GPU constant table -- the CPU body is the\n"
        "// source of truth. Any drift fails the determinism test by construction.\n"
        "\n"
        "// =============================================================================\n"
        "// Bandersnatch base field Fp (= BLS12-381 scalar field).\n"
        "//   q (256-bit prime, 255-bit), Montgomery R = 2^256 mod q.\n"
        "// =============================================================================\n\n");

    std::uint64_t buf[4];

    kinet::banderwagon::internal::fp_modulus(buf);
    emit_u64x4(fp, "FP_Q", buf);
    kinet::banderwagon::internal::fp_r_squared(buf);
    emit_u64x4(fp, "FP_R2", buf);
    kinet::banderwagon::internal::fp_r_mod_q(buf);
    emit_u64x4(fp, "FP_R", buf);
    std::fprintf(fp,
        "constant ulong FP_QINV_NEG = 0x%016llxUL;\n\n",
        (unsigned long long)kinet::banderwagon::internal::fp_qinv_neg());

    std::fprintf(fp,
        "// =============================================================================\n"
        "// Bandersnatch scalar field Fr (252-bit prime).\n"
        "// =============================================================================\n\n");

    kinet::banderwagon::internal::fr_modulus(buf);
    emit_u64x4(fp, "FR_R_MOD", buf);   // 'modulus r'
    kinet::banderwagon::internal::fr_r_squared(buf);
    emit_u64x4(fp, "FR_R2", buf);
    kinet::banderwagon::internal::fr_r_mod_r(buf);
    emit_u64x4(fp, "FR_R", buf);
    std::fprintf(fp,
        "constant ulong FR_QINV_NEG = 0x%016llxUL;\n\n",
        (unsigned long long)kinet::banderwagon::internal::fr_rinv_neg());

    std::fprintf(fp,
        "// =============================================================================\n"
        "// Curve constants (Montgomery form). a = -5, d gnark canonical.\n"
        "// =============================================================================\n\n");

    Fp a = curve_a();
    buf[0] = a.limbs[0]; buf[1] = a.limbs[1]; buf[2] = a.limbs[2]; buf[3] = a.limbs[3];
    emit_u64x4(fp, "CURVE_A", buf);

    Fp d = curve_d();
    buf[0] = d.limbs[0]; buf[1] = d.limbs[1]; buf[2] = d.limbs[2]; buf[3] = d.limbs[3];
    emit_u64x4(fp, "CURVE_D", buf);

    std::fprintf(fp,
        "// =============================================================================\n"
        "// Generator (Bandersnatch base) X, Y in Montgomery form.\n"
        "// =============================================================================\n\n");

    Element g = Element::generator();
    buf[0] = g.X.limbs[0]; buf[1] = g.X.limbs[1]; buf[2] = g.X.limbs[2]; buf[3] = g.X.limbs[3];
    emit_u64x4(fp, "GEN_X", buf);
    buf[0] = g.Y.limbs[0]; buf[1] = g.Y.limbs[1]; buf[2] = g.Y.limbs[2]; buf[3] = g.Y.limbs[3];
    emit_u64x4(fp, "GEN_Y", buf);

    std::fclose(fp);
    return 0;
}
