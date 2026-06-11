# banderwagon KAT generation

The C++ test fixtures in this directory are **auto-generated** byte
artefacts. Editing them by hand is not supported.

## Two-oracle policy (Red O2/O4)

Every committed KAT entry must be byte-equal across two independent
implementations. This stops a single-codebase bug (e.g. a quirk in
gnark-crypto's Bandersnatch) from passing the C++ port vacuously: if both
sides transliterate the same algorithm and the algorithm is wrong,
byte-equality proves nothing.

| KAT file               | Generator                       | Primary oracle                                                    | Secondary oracle                                                             |
| ---------------------- | ------------------------------- | ----------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| `fp_kat.h`             | `tools/gen_fp_kat.go`           | gnark-crypto `ecc/bls12-381/fr` (== Banderwagon Fp)               | `ark-bls12-381::Fr` (arkworks-rs) via `tools/ark_oracle/`                    |
| `fr_kat.h`             | `tools/gen_fr_kat.go`           | kinet-labs/crypto Bandersnatch scalar field (gnark-derived)            | `ark-ed-on-bls12-381-bandersnatch::Fr` (arkworks-rs) via `tools/ark_oracle/` |
| `element_kat.h`        | `tools/gen_element_kat.go`      | kinet-labs/crypto/ipa/banderwagon (Element / 2-torsion quotient)       | **deferred** — see below                                                     |
| `multiexp_kat.h`       | `tools/gen_multiexp_kat.go`     | kinet-labs/crypto/ipa/banderwagon Pippenger MSM                        | **deferred** — see below                                                     |

For the cross-checked KATs the verifier in
`tools/verify_kat/verify_fp_fr_kat.go` re-reads each committed header and
asserts three-way agreement (stored bytes, primary re-run, arkworks oracle)
on every (a, b, op) tuple. On any disagreement the verifier exits non-zero
with both sides dumped — this is a precondition for committing any change
to either generator or stored KAT.

### Why element/multiexp have only one oracle

`arkworks-rs` ships the bare Bandersnatch curve
(`ark-ed-on-bls12-381-bandersnatch`) but does not ship the **Banderwagon**
group, which is the 2-torsion quotient of Bandersnatch (Caulk et al.).
Element compression + bad-subgroup rejection + multi-scalar-multiplication
on the quotient group all live above arkworks's primitives — so a true
second oracle would require porting Banderwagon ourselves, which defeats
the purpose of using a divergent codebase.

The Element + multiexp KATs are therefore single-oracle today, explicitly
flagged for upgrade once a second open-source implementation of the
Banderwagon group becomes available (e.g. crate-haskell's `banderwagon`
package gaining a Rust port, or upstream arkworks adding the quotient).

## Regenerating

```bash
cd banderwagon/test/tools
(cd ark_oracle && cargo build --release)
go run gen_fp_kat.go        > ../fp_kat.h
go run gen_fr_kat.go        > ../fr_kat.h
go run gen_element_kat.go   > ../element_kat.h
go run gen_multiexp_kat.go  > ../multiexp_kat.h
# Mandatory cross-oracle check before committing any fp/fr KAT update:
(cd verify_kat && go run verify_fp_fr_kat.go ../../fp_kat.h ../../fr_kat.h)
```

The verifier prints

```
banderwagon/fp: 10/10 gnark <-> arkworks <-> stored byte-equal (Red O2/O4 PASS)
banderwagon/fr: 10/10 gnark <-> arkworks <-> stored byte-equal (Red O2/O4 PASS)
```

to stderr on success. Any divergence aborts with the divergent rows dumped
side-by-side.
