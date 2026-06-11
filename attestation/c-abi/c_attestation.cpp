// C-ABI shim for the attestation algorithm. Symbols are declared in the
// per-algorithm headers and implemented in cpp/*.cpp; this file exists so
// the umbrella `attestation` library has a single TU to anchor the linker
// against, mirroring the layout of the other 28 algorithms.

#include "c_attestation.h"
