// Generator for the batched Pedersen Metal-determinism KAT fixture.
//
// Emits a single binary file consumed by pedersen/test/pedersen_metal_determinism_test.mm.
//
// Layout (little-endian counts; raw big-endian field elements):
//
//   header (16 bytes):
//     u32 N                            -- basis size                    (=256)
//     u32 M                            -- per-batch commitments         (=8)
//     u32 ROUNDS                       -- number of test rounds         (=100)
//     u32 _pad                         -- 0
//
//   generators block:
//     (N + 1) * 64 bytes               -- G_basis[0..N-1] || H, each (X||Y) BE
//
//   each round (ROUNDS times):
//     M * N * 32 bytes                 -- scalars     (BE Fr)
//     M * 32     bytes                 -- blindings   (BE Fr)
//     M * 64     bytes                 -- expected commitments (BE X||Y affine)
//
// Determinism: all randomness is derived from a fixed master seed via SHA-256
// counters, so the fixture is identical across hosts and runs.
//
// Run:
//   cd pedersen/test/tools
//   go run gen_pedersen_metal_kat.go -out ../../../build/pedersen_metal.kat

package main

import (
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"log"
	"math/big"
	"os"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

const (
	dst    = "PEDERSEN_SEEDED_GEN_V1"
	N      = 256
	M      = 8
	ROUNDS = 100
)

// fixedMasterSeed: 32 fixed bytes used to derive everything.
var fixedMasterSeed = func() [32]byte {
	var s [32]byte
	for i := range s {
		s[i] = byte(0xA0 + i) // arbitrary but stable pattern
	}
	return s
}()

// hashIndexedG1 = HashToG1(seed || u64_le(index), DST = SeededGenDST).
func hashIndexedG1(seed [32]byte, index uint64) bn254.G1Affine {
	var msg [40]byte
	copy(msg[:32], seed[:])
	binary.LittleEndian.PutUint64(msg[32:], index)
	p, err := bn254.HashToG1(msg[:], []byte(dst))
	if err != nil {
		log.Fatalf("HashToG1 failed: %v", err)
	}
	return p
}

// gensFromSeed -- (G_0..G_{N-1}, H).
func gensFromSeed(seed [32]byte, n int) ([]bn254.G1Affine, bn254.G1Affine) {
	G := make([]bn254.G1Affine, n)
	for i := 0; i < n; i++ {
		G[i] = hashIndexedG1(seed, uint64(i))
	}
	H := hashIndexedG1(seed, uint64(n))
	return G, H
}

// rngScalar derives an Fr from sha256("salt" || labelbytes).
func rngScalar(salt string, label []byte) fr.Element {
	h := sha256.New()
	h.Write([]byte(salt))
	h.Write(label)
	d := h.Sum(nil)
	var f fr.Element
	f.SetBytes(d)
	return f
}

// commit -- sum_i scalars[i]*G[i] + r*H.
func commit(scalars []fr.Element, r fr.Element, G []bn254.G1Affine, H bn254.G1Affine) bn254.G1Affine {
	var acc bn254.G1Jac
	for i := range scalars {
		var term bn254.G1Jac
		bi := new(big.Int)
		scalars[i].BigInt(bi)
		term.FromAffine(&G[i])
		term.ScalarMultiplication(&term, bi)
		acc.AddAssign(&term)
	}
	{
		var term bn254.G1Jac
		bi := new(big.Int)
		r.BigInt(bi)
		term.FromAffine(&H)
		term.ScalarMultiplication(&term, bi)
		acc.AddAssign(&term)
	}
	var out bn254.G1Affine
	out.FromJacobian(&acc)
	return out
}

func writeBE(out *os.File, p bn254.G1Affine) {
	xb := p.X.Bytes()
	yb := p.Y.Bytes()
	if _, err := out.Write(xb[:]); err != nil {
		log.Fatalf("write: %v", err)
	}
	if _, err := out.Write(yb[:]); err != nil {
		log.Fatalf("write: %v", err)
	}
}

func main() {
	outPath := flag.String("out", "", "output binary fixture path")
	flag.Parse()
	if *outPath == "" {
		log.Fatalf("missing -out")
	}

	seed := fixedMasterSeed
	G, H := gensFromSeed(seed, N)

	out, err := os.Create(*outPath)
	if err != nil {
		log.Fatalf("create %s: %v", *outPath, err)
	}
	defer out.Close()

	// Header.
	hdr := make([]byte, 16)
	binary.LittleEndian.PutUint32(hdr[0:4], uint32(N))
	binary.LittleEndian.PutUint32(hdr[4:8], uint32(M))
	binary.LittleEndian.PutUint32(hdr[8:12], uint32(ROUNDS))
	binary.LittleEndian.PutUint32(hdr[12:16], 0)
	if _, err := out.Write(hdr); err != nil {
		log.Fatalf("write header: %v", err)
	}

	// Generators (G[0..N-1] || H), each X||Y BE.
	for i := 0; i < N; i++ {
		writeBE(out, G[i])
	}
	writeBE(out, H)

	// Rounds.
	for r := 0; r < ROUNDS; r++ {
		scalarsAll := make([][]fr.Element, M)
		blindings := make([]fr.Element, M)
		for m := 0; m < M; m++ {
			row := make([]fr.Element, N)
			for i := 0; i < N; i++ {
				lbl := []byte{byte(r), byte(r >> 8), byte(m), byte(i), byte(i >> 8)}
				row[i] = rngScalar("pedersen-metal-kat-scalars", lbl)
			}
			scalarsAll[m] = row
			lblB := []byte{byte(r), byte(r >> 8), byte(m)}
			blindings[m] = rngScalar("pedersen-metal-kat-blinding", lblB)
		}

		// Write scalars block: M rows of N BE-32.
		for m := 0; m < M; m++ {
			for i := 0; i < N; i++ {
				b := scalarsAll[m][i].Bytes()
				if _, err := out.Write(b[:]); err != nil {
					log.Fatalf("write scalars: %v", err)
				}
			}
		}
		// Write blindings: M BE-32.
		for m := 0; m < M; m++ {
			b := blindings[m].Bytes()
			if _, err := out.Write(b[:]); err != nil {
				log.Fatalf("write blinding: %v", err)
			}
		}
		// Write commitments: M (X||Y) BE.
		for m := 0; m < M; m++ {
			c := commit(scalarsAll[m], blindings[m], G, H)
			writeBE(out, c)
		}
	}
}
