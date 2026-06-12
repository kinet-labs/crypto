// secp256k1 curve traits for the multi_pippenger Metal kernel.
//
//   p = 2^256 - 2^32 - 977
//   y^2 = x^3 + 7
//
// Constants mirror cpp/secp256k1/cpp/field.hpp.

#pragma once

constant uint64_t MP_P[4] = {
    0xFFFFFFFEFFFFFC2FUL, 0xFFFFFFFFFFFFFFFFUL,
    0xFFFFFFFFFFFFFFFFUL, 0xFFFFFFFFFFFFFFFFUL
};
constant uint64_t MP_P_INV = 0xD838091DD2253531UL;
constant uint64_t MP_R2[4] = {
    0x000007A2000E90A1UL, 0x0000000000000001UL,
    0x0000000000000000UL, 0x0000000000000000UL
};
constant int MP_FIELD_LIMBS = 4;
constant int MP_BITS = 256;
