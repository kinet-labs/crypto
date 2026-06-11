// SPDX-License-Identifier: Apache-2.0
//
// gen_multiexp_kat.go -- emit Banderwagon Pippenger MSM KAT vectors for the
// C++ implementation in kinet-labs/crypto/banderwagon.
//
// Source of truth: github.com/kinet-labs/crypto/ipa/banderwagon (Element.MultiExp)
// which itself wraps gnark-crypto bls12-381/bandersnatch.
//
// Usage:
//   cd /Users/z/work/kinet-labs/crypto/banderwagon/test/tools
//   go run gen_multiexp_kat.go > ../multiexp_kat.h
//
// Layout: 1000 random MSM iterations spread across the sizes
// {1, 2, 8, 64, 256, 1024} (≥ 1000 total) plus three explicit edge cases:
//   * N=0  → identity (encoded as 32 zero bytes per Banderwagon convention)
//   * N=1  → equivalent to scalar_mul(P, s)
//   * N=2  → small-N path
//
// The C++ test reproduces (points, scalars) from the same xorshift64* PRG
// seeded with the same 64-bit seed and asserts the compressed-encoding bytes
// of its MSM result equal the stored expected bytes.

package main

import (
	"fmt"
	"math/big"
	"os"

	"github.com/kinet-labs/crypto/ipa/banderwagon"
	"github.com/kinet-labs/crypto/ipa/bandersnatch/fr"
)

// xorshift64* matching the C++ PRG used in the test; deterministic across
// platforms (operates on uint64 only).
type detRng struct{ s uint64 }

func newDetRng(seed uint64) *detRng { return &detRng{s: seed} }

func (r *detRng) next() uint64 {
	x := r.s
	x ^= x << 13
	x ^= x >> 7
	x ^= x << 17
	r.s = x
	return x * 2685821657736338717
}

// Fill 32 LE bytes from 4 PRG calls. Caller may mask the top byte for
// fr-safety as needed.
func (r *detRng) fill32(buf *[32]byte) {
	for i := 0; i < 4; i++ {
		v := r.next()
		buf[8*i+0] = byte(v)
		buf[8*i+1] = byte(v >> 8)
		buf[8*i+2] = byte(v >> 16)
		buf[8*i+3] = byte(v >> 24)
		buf[8*i+4] = byte(v >> 32)
		buf[8*i+5] = byte(v >> 40)
		buf[8*i+6] = byte(v >> 48)
		buf[8*i+7] = byte(v >> 56)
	}
}

// genScalar produces a deterministic Fr scalar from the PRG. The C++ test
// uses the same xorshift64* PRG and the same per-byte mask (top byte & 0x07
// to keep the value safely below r ≈ 2^253), so both sides see identical
// scalar bytes.
func genScalar(r *detRng) fr.Element {
	var buf [32]byte
	r.fill32(&buf)
	buf[31] &= 0x07
	var s fr.Element
	s.SetBytesLE(buf[:])
	return s
}

// genPoint produces a deterministic Banderwagon Element by computing
// [k+1] * Generator with k drawn from the PRG (range constrained to a
// 32-bit value to keep scalar_mul cheap when the test reproduces it on the
// C++ side).
func genPoint(r *detRng) banderwagon.Element {
	v := r.next()
	k := big.NewInt(int64(v & 0xFFFFFFFF))
	k.Add(k, big.NewInt(1)) // never zero

	var s fr.Element
	s.SetBigInt(k)

	var p banderwagon.Element = banderwagon.Generator
	p.ScalarMul(&p, &s)
	return p
}

type kat struct {
	name        string
	seed        uint64
	n           int
	expectedEnc [32]byte // compressed encoding of MSM result
}

func runMSM(seed uint64, n int) (banderwagon.Element, [32]byte) {
	r := newDetRng(seed)

	points := make([]banderwagon.Element, n)
	scalars := make([]fr.Element, n)
	for i := 0; i < n; i++ {
		points[i] = genPoint(r)
	}
	for i := 0; i < n; i++ {
		scalars[i] = genScalar(r)
	}

	var result banderwagon.Element
	if n == 0 {
		result = banderwagon.Identity
	} else {
		// IMPORTANT: ScalarsMont must be true here because fr.Element stores
		// values internally in Montgomery form (after SetBytesLE). The
		// `ScalarsMont` flag tells gnark whether to call FromMont() before
		// partitioning into windows. Setting it false would cause the MSM to
		// effectively compute  [mont(s_i)] * P_i  instead of  s_i * P_i,
		// which mismatches every other path (Element.ScalarMul, custom MSM,
		// etc.). The C++ implementation operates on canonical scalars, so the
		// reference must too.
		_, err := result.MultiExp(points, scalars, banderwagon.MultiExpConfig{NbTasks: 1, ScalarsMont: true})
		if err != nil {
			panic(fmt.Sprintf("MultiExp failed for n=%d seed=%x: %v", n, seed, err))
		}
	}

	enc := result.Bytes()
	return result, enc
}

func cBytes32(b [32]byte) string {
	out := ""
	for i, x := range b {
		if i > 0 {
			out += ", "
		}
		out += fmt.Sprintf("0x%02x", x)
	}
	return out
}

func main() {
	out := os.Stdout

	type sizeSpec struct {
		size  int
		iters int
	}

	// 1000 total iterations distributed across sizes:
	//   N=1     -> 200
	//   N=2     -> 200
	//   N=8     -> 200
	//   N=64    -> 200
	//   N=256   -> 100
	//   N=1024  -> 100
	specs := []sizeSpec{
		{1, 200},
		{2, 200},
		{8, 200},
		{64, 200},
		{256, 100},
		{1024, 100},
	}

	var kats []kat
	// Seed counter; each (size, iter) gets a unique seed.
	seedBase := uint64(0xb1ff_b1ff_b1ff_b1ff)
	for _, sp := range specs {
		for it := 0; it < sp.iters; it++ {
			seed := seedBase
			seedBase += 0x9E3779B97F4A7C15
			_, enc := runMSM(seed, sp.size)
			kats = append(kats, kat{
				name:        fmt.Sprintf("msm_n%d_i%d", sp.size, it),
				seed:        seed,
				n:           sp.size,
				expectedEnc: enc,
			})
		}
	}

	// Emit C++ header.
	fmt.Fprintln(out, "// SPDX-License-Identifier: Apache-2.0")
	fmt.Fprintln(out, "// multiexp_kat.h -- generated by banderwagon/test/tools/gen_multiexp_kat.go")
	fmt.Fprintln(out, "// Source: github.com/kinet-labs/crypto/ipa/banderwagon Element.MultiExp.")
	fmt.Fprintln(out, "// DO NOT EDIT.")
	fmt.Fprintln(out, "#pragma once")
	fmt.Fprintln(out, "#include <cstdint>")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "namespace kinet::banderwagon::kat {")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "struct MsmKat {")
	fmt.Fprintln(out, "    const char*    name;")
	fmt.Fprintln(out, "    std::uint64_t  seed;        // xorshift64* seed used to generate (points, scalars)")
	fmt.Fprintln(out, "    std::size_t    n;           // number of (point, scalar) pairs")
	fmt.Fprintln(out, "    std::uint8_t   enc_be[32];  // expected compressed encoding of result (32-byte BE)")
	fmt.Fprintln(out, "};")
	fmt.Fprintln(out, "")
	fmt.Fprintf(out, "constexpr int kMsmKatCount = %d;\n", len(kats))
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "inline const MsmKat kMsmKats[] = {")
	for _, k := range kats {
		fmt.Fprintf(out, "    {\"%s\", 0x%016x, %d, {%s}},\n",
			k.name, k.seed, k.n, cBytes32(k.expectedEnc))
	}
	fmt.Fprintln(out, "};")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "}  // namespace kinet::banderwagon::kat")
}
