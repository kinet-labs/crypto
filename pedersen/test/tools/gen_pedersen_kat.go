// Generator for pedersen vector-commitment KAT vectors.
//
// Scheme (replicate exactly in C++ / Rust ports):
//
//   G_i = HashToG1( seed || u64_le(i)  , DST = "PEDERSEN_SEEDED_GEN_V1" )
//   H   = HashToG1( seed || u64_le(n)  , DST = "PEDERSEN_SEEDED_GEN_V1" )
//   C   = sum_i s_i * G_i  +  r * H
//
// Encoding for the C++ test fixture:
//
//   Each affine G1 coordinate is emitted as 32 bytes big-endian, raw value
//   (NOT gnark's compressed Bytes() form). Identical to gnark-crypto's
//   bn254.G1Affine.X.Bytes() / .Y.Bytes() output.
//
// Run:
//   cd pedersen/test/tools && go run gen_pedersen_kat.go > ../pedersen_kat.h

package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

const dst = "PEDERSEN_SEEDED_GEN_V1"

// fixedSeed = {0, 1, ..., 31}.
func fixedSeed() [32]byte {
	var s [32]byte
	for i := range s {
		s[i] = byte(i)
	}
	return s
}

// hashIndexedG1 = HashToG1(seed || u64_le(index), DST). Cofactor of BN254 G1
// is 1, so the gnark output is already in the prime-order subgroup.
func hashIndexedG1(seed [32]byte, index uint64) bn254.G1Affine {
	var msg [40]byte
	copy(msg[:32], seed[:])
	binary.LittleEndian.PutUint64(msg[32:], index)
	p, err := bn254.HashToG1(msg[:], []byte(dst))
	if err != nil {
		panic(err)
	}
	return p
}

func gensFromSeed(seed [32]byte, n int) ([]bn254.G1Affine, bn254.G1Affine) {
	G := make([]bn254.G1Affine, n)
	for i := 0; i < n; i++ {
		G[i] = hashIndexedG1(seed, uint64(i))
	}
	H := hashIndexedG1(seed, uint64(n))
	return G, H
}

// commit returns sum_i scalars[i]*G[i] + r*H.
func commit(scalars []fr.Element, r fr.Element, G []bn254.G1Affine, H bn254.G1Affine) bn254.G1Affine {
	var acc bn254.G1Jac
	for i := range scalars {
		var term bn254.G1Jac
		var bi big.Int
		scalars[i].BigInt(&bi)
		term.FromAffine(&G[i])
		term.ScalarMultiplication(&term, &bi)
		acc.AddAssign(&term)
	}
	{
		var term bn254.G1Jac
		var bi big.Int
		r.BigInt(&bi)
		term.FromAffine(&H)
		term.ScalarMultiplication(&term, &bi)
		acc.AddAssign(&term)
	}
	var out bn254.G1Affine
	out.FromJacobian(&acc)
	return out
}

// rngScalar deterministically derives an Fr scalar from a counter (separate
// from the seed used for generators) so the C++ test can replicate it.
func rngScalar(salt string, idx int) fr.Element {
	h := sha256.New()
	h.Write([]byte(salt))
	h.Write([]byte{byte(idx)})
	d := h.Sum(nil)
	var f fr.Element
	f.SetBytes(d)
	return f
}

func main() {
	seed := fixedSeed()

	const N = 8 // basis size for KAT roundtrips

	G, H := gensFromSeed(seed, N)

	fmt.Println("// =============================================================================")
	fmt.Println("// pedersen vector-commitment KAT vectors (auto-generated; DO NOT EDIT BY HAND).")
	fmt.Println("// Source: gnark-crypto bn254.HashToG1 + Pedersen-vector reference impl.")
	fmt.Println("// Suite : BN254 G1, DST = \"PEDERSEN_SEEDED_GEN_V1\"")
	fmt.Println("// Tool  : pedersen/test/tools/gen_pedersen_kat.go")
	fmt.Println("// =============================================================================")
	fmt.Println("//")
	fmt.Println("// Encoding: every affine coordinate is 32-byte big-endian raw Fp (no compression")
	fmt.Println("//           flag), identical to gnark-crypto's bn254.G1Affine.X.Bytes().")
	fmt.Println("//           Every Fr scalar is 32-byte big-endian, already reduced.")
	fmt.Println("//")
	fmt.Println("// === BEGIN PEDERSEN_GENS_KAT ===")
	fmt.Printf("static constexpr unsigned PEDERSEN_KAT_N = %d;\n", N)
	fmt.Print("static const char PEDERSEN_KAT_SEED_HEX[] = \"")
	for _, b := range seed {
		fmt.Printf("%02x", b)
	}
	fmt.Println("\";")

	fmt.Println("static const char* const PEDERSEN_KAT_GENS_X_HEX[] = {")
	for i := 0; i < N; i++ {
		xb := G[i].X.Bytes()
		fmt.Printf("    \"%s\", // G[%d].x\n", hex.EncodeToString(xb[:]), i)
	}
	fmt.Println("};")
	fmt.Println("static const char* const PEDERSEN_KAT_GENS_Y_HEX[] = {")
	for i := 0; i < N; i++ {
		yb := G[i].Y.Bytes()
		fmt.Printf("    \"%s\", // G[%d].y\n", hex.EncodeToString(yb[:]), i)
	}
	fmt.Println("};")
	{
		xb := H.X.Bytes()
		yb := H.Y.Bytes()
		fmt.Printf("static const char PEDERSEN_KAT_H_X_HEX[] = \"%s\";\n", hex.EncodeToString(xb[:]))
		fmt.Printf("static const char PEDERSEN_KAT_H_Y_HEX[] = \"%s\";\n", hex.EncodeToString(yb[:]))
	}
	fmt.Println("// === END PEDERSEN_GENS_KAT ===")
	fmt.Println()

	// 5 commit-verify roundtrips.
	const ROUNDS = 5
	fmt.Println("// === BEGIN PEDERSEN_ROUNDTRIP_KAT ===")
	fmt.Printf("static constexpr unsigned PEDERSEN_KAT_ROUNDS = %d;\n", ROUNDS)
	fmt.Println("struct PedersenRoundKAT {")
	fmt.Println("    const char* scalars_hex[8]; // N=8 scalars")
	fmt.Println("    const char* blinding_hex;")
	fmt.Println("    const char* commitment_x_hex;")
	fmt.Println("    const char* commitment_y_hex;")
	fmt.Println("};")
	fmt.Println("static const PedersenRoundKAT PEDERSEN_KAT_ROUNDTRIPS[] = {")
	for round := 0; round < ROUNDS; round++ {
		scalars := make([]fr.Element, N)
		for i := 0; i < N; i++ {
			scalars[i] = rngScalar(fmt.Sprintf("pedersen-kat-scalars-r%d", round), i)
		}
		r := rngScalar(fmt.Sprintf("pedersen-kat-blinding-r%d", round), 0)

		C := commit(scalars, r, G, H)

		fmt.Println("    {")
		fmt.Print("        { ")
		for i := 0; i < N; i++ {
			b := scalars[i].Bytes()
			if i > 0 {
				fmt.Print(", ")
			}
			fmt.Printf("\"%s\"", hex.EncodeToString(b[:]))
		}
		fmt.Println(" },")
		{
			b := r.Bytes()
			fmt.Printf("        \"%s\",\n", hex.EncodeToString(b[:]))
		}
		{
			xb := C.X.Bytes()
			yb := C.Y.Bytes()
			fmt.Printf("        \"%s\",\n", hex.EncodeToString(xb[:]))
			fmt.Printf("        \"%s\",\n", hex.EncodeToString(yb[:]))
		}
		fmt.Println("    },")
	}
	fmt.Println("};")
	fmt.Println("// === END PEDERSEN_ROUNDTRIP_KAT ===")
}
