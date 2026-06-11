# attestation/testdata

Vendor-published reference attestation evidence used by `attestation_test`.
Every file in this directory comes from an upstream vendor's public test-vector
repository. Nothing here is synthesized.

These bytes are loaded verbatim by the parser tests; the expected output is
hard-coded as a `constexpr` byte array in the test file. The parser must
reproduce the expected output exactly or the test fails.

## Files

### sev_snp_milan_sample.bin (1184 bytes)
A real AMD SEV-SNP attestation report (PSP-signed, version 2) for an AMD Milan
processor. Used to exercise `attestation_parse_sev_snp` against a layout that
real hardware actually emits.

* Source: https://github.com/virtee/sev
* File: `tests/certs_data/report_milan.hex` (decoded from hex)
* License: Apache-2.0
* Copyright: VirTEE Project Developers

### sev_snp_milan_vcek.pem (4602 bytes)
The matching VCEK -> ASK -> ARK certificate chain for the Milan report above.
Used by the signature-verification path (which lands in PR #190).

* Source: https://github.com/virtee/sev
* File: `tests/certs_data/cert_chain_milan`
* License: Apache-2.0

### tdx_sample_quote.bin (3696 bytes)
A real Intel TDX TD Quote (version 4, attestation key type 2, tee_type 0x81).
Used to exercise `attestation_parse_tdx` against the on-the-wire quote format
emitted by Intel's QGS.

* Source: https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary
* File: `Src/AttestationApp/sampleData/tdx/quote.dat`
* License: BSD-3-Clause
* Copyright: 2011-2024 Intel Corporation

### tdx_pck_chain.pem (1888 bytes)
The matching PCK-leaf -> Intel SGX Platform CA -> Intel SGX Root CA chain for
the TDX quote above. Used by the signature-verification path.

* Source: https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary
* File: `Src/AttestationApp/sampleData/tdx/pckSignChain.pem`
* License: BSD-3-Clause

### nras_h100_evidence.bin (4117 bytes)
A real NVIDIA H100 (Hopper) GPU attestation report - the binary
DMTF SPDM measurement block returned by an H100 in confidential-compute mode,
suitable for the NRAS verifier.

* Source: https://github.com/NVIDIA/nvtrust
* File:
  `guest_tools/gpu_verifiers/local_gpu_verifier/src/verifier/samples/hopperAttestationReport.txt`
  (decoded from hex)
* License: Apache-2.0
* Copyright: NVIDIA Corporation

### nras_root.pem (4825 bytes)
The matching NVIDIA Hopper attestation certificate chain (device cert ->
NVIDIA GPU CA -> NVIDIA Root CA). Used by the signature-verification path.

* Source: https://github.com/NVIDIA/nvtrust
* File:
  `guest_tools/gpu_verifiers/local_gpu_verifier/src/verifier/samples/hopperCertChain.txt`
* License: Apache-2.0

## Vendors not represented

* AMD SEV-SNP Genoa / Turin: vendor's published cert-chain repos
  (https://github.com/virtee/sev) ship root CAs but no full sample
  attestation report. Skipped per instruction (no public sample report
  available outside a real Genoa/Turin host).

If a Genoa or Turin sample report is later published, drop the binary into
this directory as `sev_snp_genoa_sample.bin` (or `sev_snp_turin_sample.bin`)
and add a `TEST_CASE` entry to `attestation_test.cpp` mirroring the Milan one.

## How to regenerate the expected constants

The parser hashes a known sub-range of the fixture bytes with
`keccak256` (Ethereum padding, delimiter 0x01). To recompute the
hard-coded expected values in `attestation_test.cpp`:

1. Build `keccak_test` once so `libkeccak_cpu.a` is available.
2. Run a 5-line C++ program that calls `keccak256(...)` on the relevant
   slice of each fixture and prints the 32-byte hex.

The `expected_*` constants in the test must match what
`keccak256(<slice>)` returns. Any mismatch is a parser bug or a fixture
swap; investigate before "fixing" the expected value.
