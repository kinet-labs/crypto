# bn254 KAT generation

The C++ test fixtures in this directory are **auto-generated** byte
artefacts. Editing them by hand is not supported.

## Two-oracle policy (Red O2/O4)

Every committed KAT entry must be byte-equal across two independent
implementations. This stops a single-codebase bug (e.g. a quirk in
gnark-crypto) from passing the C++ port vacuously: if both sides
transliterate the same algorithm and the algorithm is wrong, byte-equality
proves nothing.

| KAT file                  | Generator                               | Primary oracle                   | Secondary oracle                                  |
| ------------------------- | --------------------------------------- | -------------------------------- | ------------------------------------------------- |
| `bn254_pairing_kat.h`     | `tools/gen_pairing_kat.go`              | gnark-crypto `ecc/bn254`         | `ark-bn254` (arkworks-rs) via `tools/ark_oracle/` |
| `bn254_h2c_kat.h`         | `tools/gen_hashtocurve_kat.go`          | gnark-crypto `ecc/bn254.HashToG1` | **deferred** — see below                          |

The pairing KAT is committed only after the verifier in
`tools/verify_kat/verify_pairing_kat.go` confirms three-way agreement
(stored predicate, gnark-crypto re-run, arkworks oracle). On any divergence
the verifier exits non-zero and the KAT must NOT be committed.

### Why h2c has only one oracle

`ark-bn254` ships the curve + Miller loop + final exponentiation, but does
not include the IETF RFC 9380 SVDW hash-to-curve suite (`BN254G1_XMD:SHA-256_SVDW_RO_`).
Adding a true second oracle for h2c would require porting the SVDW map and
isogenies ourselves, which defeats the purpose of using a divergent
codebase.

The current state is the same as banderwagon's `gen_element_kat.go`: a
single-oracle KAT explicitly flagged for upgrade once a second open-source
implementation of the same suite becomes available (e.g. zkcrypto's `bn`
crate adding `hash_to_curve` would qualify).

## Regenerating

```bash
cd bn254/test/tools
(cd ark_oracle && cargo build --release)
go run gen_pairing_kat.go      > ../bn254_pairing_kat.h
go run gen_hashtocurve_kat.go  > ../bn254_h2c_kat.h
# Mandatory cross-oracle check before committing pairing KAT updates:
(cd verify_kat && go run verify_pairing_kat.go ../../bn254_pairing_kat.h)
```

The verifier prints
`bn254/pairing: 3/3 gnark <-> arkworks <-> stored byte-equal (Red O2/O4 PASS)`
to stderr on success. Any divergence aborts with the divergent rows
dumped side-by-side.
