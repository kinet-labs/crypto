// Banderwagon curve traits for the multi_pippenger Metal kernel.
//
//   q = BLS12-381 scalar field (Bandersnatch base field)
//   twisted Edwards (a = -5):  -5 * x^2 + y^2 = 1 + d * x^2 * y^2
//
// Constants mirror cpp/banderwagon/cpp/fp.cpp.

#pragma once

constant uint64_t MP_P[4] = {
    0xFFFFFFFF00000001UL, 0x53BDA402FFFE5BFEUL,
    0x3339D80809A1D805UL, 0x73EDA753299D7D48UL
};
constant uint64_t MP_P_INV = 0xFFFFFFFEFFFFFFFFUL;
constant uint64_t MP_R2[4] = {
    0xC999E990F3F29C6DUL, 0x2B6CEDCB87925C23UL,
    0x05D314967254398FUL, 0x0748D9D99F59FF11UL
};
constant int MP_FIELD_LIMBS = 4;
constant int MP_BITS = 255;
