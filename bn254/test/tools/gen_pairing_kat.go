// Generator for bn254 EIP-197 pairing KAT vectors.
//
// Each vector is dumped as the EIP-197 ABI byte string (192 bytes per pair)
// alongside the expected boolean predicate. The C++ KAT test consumes this
// directly via the embedded fixture header bn254_pairing_kat.h.
//
// Run:   cd bn254/test/tools && go run gen_pairing_kat.go > ../bn254_pairing_kat.h

package main

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
)

// be32 returns a big-endian 32-byte encoding of a fp.Element.
func be32(e fp.Element) []byte {
	b := e.Bytes() // big-endian, 32 bytes
	return b[:]
}

// pair encodes one (G1, G2) pair into the 192-byte EIP-197 layout.
//
//	[G1.x | G1.y | G2.x.imag | G2.x.real | G2.y.imag | G2.y.real]
//	 32     32    32          32          32          32
func pair(P bn254.G1Affine, Q bn254.G2Affine) []byte {
	out := make([]byte, 192)
	copy(out[0:32], be32(P.X))
	copy(out[32:64], be32(P.Y))
	copy(out[64:96], be32(Q.X.A1))   // imag
	copy(out[96:128], be32(Q.X.A0))  // real
	copy(out[128:160], be32(Q.Y.A1)) // imag
	copy(out[160:192], be32(Q.Y.A0)) // real
	return out
}

func emit(name string, pairs [][]byte, expected bool) {
	cat := []byte{}
	for _, p := range pairs {
		cat = append(cat, p...)
	}
	exp := 0
	if expected {
		exp = 1
	}
	fmt.Printf("    {%q, %d, %d, \"%s\"},\n",
		name, len(pairs), exp, hex.EncodeToString(cat))
}

func main() {
	_, _, g1, g2 := bn254.Generators()

	// Pre-compute the canonical points used across the KATs.
	var negG2 bn254.G2Affine
	negG2.Neg(&g2)

	// 2*G1, 3*G2, 6*G1
	var g1_2 bn254.G1Affine
	g1_2.ScalarMultiplication(&g1, big.NewInt(2))
	var g2_3 bn254.G2Affine
	g2_3.ScalarMultiplication(&g2, big.NewInt(3))
	var g1_6 bn254.G1Affine
	g1_6.ScalarMultiplication(&g1, big.NewInt(6))

	fmt.Println("// =============================================================================")
	fmt.Println("// bn254 pairing KAT vectors (auto-generated; DO NOT EDIT BY HAND).")
	fmt.Println("// Source: gnark-crypto v0.19.2 ecc/bn254 — see bn254/test/tools/gen_pairing_kat.go")
	fmt.Println("// =============================================================================")
	fmt.Println("//")
	fmt.Println("// Each entry is { name, n_pairs, expected_predicate, hex(concat(pairs)) }.")
	fmt.Println("// Expected predicate: 1 = pairing product is one in GT, 0 = not one.")
	fmt.Println("//")
	fmt.Println("// === BEGIN BN254_PAIRING_KAT ===")

	// 1) Empty input -> identity in GT, predicate is true.
	emit("empty", nil, true)

	// 2) e(G1, -G2) * e(G1, G2) == 1   (bilinearity, well-known true case)
	emit("g1_negg2__g1_g2",
		[][]byte{pair(g1, negG2), pair(g1, g2)},
		true)

	// 3) e(G1, G2) != 1   (single non-trivial pair must fail predicate)
	emit("g1_g2", [][]byte{pair(g1, g2)}, false)

	fmt.Println("// === END BN254_PAIRING_KAT ===")

	// Bonus: bilinearity sanity (printed as commentary, not used as a KAT).
	// e([2]G1, [3]G2) * e(-G1, [6]G2) ?= 1 since 2*3 - 1*6 = 0.
	var g2_6 bn254.G2Affine
	g2_6.ScalarMultiplication(&g2, big.NewInt(6))
	var negG1 bn254.G1Affine
	negG1.Neg(&g1)
	ok, err := bn254.PairingCheck(
		[]bn254.G1Affine{g1_2, negG1},
		[]bn254.G2Affine{g2_3, g2_6})
	if err != nil {
		panic(err)
	}
	fmt.Printf("// (sanity) bilinearity 2*3 - 1*6 = 0: PairingCheck = %v\n", ok)
	_ = g1_6
}
