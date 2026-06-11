// SPDX-License-Identifier: Apache-2.0
//
// c_banderwagon.cpp -- C-ABI surface for the banderwagon algorithm.
//
// The full C-ABI for Fp_*, Fr_*, and Element_* is emitted from
// cpp/fp.cpp, cpp/fr.cpp, and cpp/element.cpp respectively. This
// translation unit lives in the algorithm's c-abi directory to satisfy
// the KinetAlgorithm umbrella convention and supplies the trivial
// `_copy` helpers that are not worth a dedicated header.

#include "../cpp/element.hpp"
#include "../cpp/fp.hpp"
#include "../cpp/fr.hpp"

extern "C" {

void Fp_copy(kinet::banderwagon::Fp* dst, const kinet::banderwagon::Fp* src) {
    *dst = *src;
}

void Fr_copy(kinet::banderwagon::Fr* dst, const kinet::banderwagon::Fr* src) {
    *dst = *src;
}

void Element_copy(kinet::banderwagon::Element* dst,
                  const kinet::banderwagon::Element* src) {
    *dst = *src;
}

}  // extern "C"
