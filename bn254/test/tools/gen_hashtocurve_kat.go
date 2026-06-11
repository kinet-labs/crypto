// Generator for bn254 RFC 9380 hash-to-curve KAT vectors.
//
// Suite: BN254G1_XMD:SHA-256_SVDW_RO_
//
// For each (msg, dst) pair we capture the expected G1 affine output emitted
// by gnark-crypto's bn254.HashToG1, dumping (msg_hex, dst_hex, x_be32_hex,
// y_be32_hex) into the C++ test fixture.
//
// Run:   cd bn254/test/tools && go run gen_hashtocurve_kat.go > ../bn254_h2c_kat.h

package main

import (
	"encoding/hex"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254"
)

const dst = "BN254G1_XMD:SHA-256_SVDW_RO_"

var msgs = []string{
	"",
	"abc",
	"abcdef0123456789",
	"q128_qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
	"a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
}

func main() {
	fmt.Println("// =============================================================================")
	fmt.Println("// bn254 hash-to-curve KAT vectors (auto-generated; DO NOT EDIT BY HAND).")
	fmt.Println("// Source: gnark-crypto v0.19.2 ecc/bn254.HashToG1")
	fmt.Println("// Suite : BN254G1_XMD:SHA-256_SVDW_RO_")
	fmt.Println("// Tool  : bn254/test/tools/gen_hashtocurve_kat.go")
	fmt.Println("// =============================================================================")
	fmt.Println("//")
	fmt.Println("// Each entry: { msg_hex, dst_hex, expected_x_be32_hex, expected_y_be32_hex }.")
	fmt.Println("//")
	fmt.Println("// === BEGIN BN254_H2C_KAT ===")

	for _, m := range msgs {
		p, err := bn254.HashToG1([]byte(m), []byte(dst))
		if err != nil {
			panic(err)
		}
		xb := p.X.Bytes() // 32-byte big-endian, already canonical
		yb := p.Y.Bytes()
		fmt.Printf("    {%q, %q, %q, %q},\n",
			hex.EncodeToString([]byte(m)),
			hex.EncodeToString([]byte(dst)),
			hex.EncodeToString(xb[:]),
			hex.EncodeToString(yb[:]),
		)
	}

	fmt.Println("// === END BN254_H2C_KAT ===")
}
