package main

import (
	"encoding/hex"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
)

// hash2 mirrors Compress(L, R) using the canonical default (t=2, rF=6, rP=50).
func hash2(left, right [32]byte) []byte {
	p := poseidon2.NewDefaultPermutation()
	out, err := p.Compress(left[:], right[:])
	if err != nil {
		panic(err)
	}
	return out
}

func mustBE(hexStr string) [32]byte {
	b, err := hex.DecodeString(hexStr)
	if err != nil { panic(err) }
	if len(b) != 32 { panic("len") }
	var r [32]byte
	copy(r[:], b)
	return r
}

func main() {
	// Print parameter info
	p := poseidon2.NewDefaultPermutation()
	_ = p
	fmt.Printf("// gnark-crypto v0.20.1 BN254 Poseidon2 default params: t=2, rF=6, rP=50, d=5\n")

	// 14 KAT cases.
	cases := []struct {
		name string
		l, r [32]byte
	}{
		{"zero_zero", mustBE("0000000000000000000000000000000000000000000000000000000000000000"), mustBE("0000000000000000000000000000000000000000000000000000000000000000")},
		{"one_zero", mustBE("0000000000000000000000000000000000000000000000000000000000000001"), mustBE("0000000000000000000000000000000000000000000000000000000000000000")},
		{"zero_one", mustBE("0000000000000000000000000000000000000000000000000000000000000000"), mustBE("0000000000000000000000000000000000000000000000000000000000000001")},
		{"one_one", mustBE("0000000000000000000000000000000000000000000000000000000000000001"), mustBE("0000000000000000000000000000000000000000000000000000000000000001")},
		{"two_three", mustBE("0000000000000000000000000000000000000000000000000000000000000002"), mustBE("0000000000000000000000000000000000000000000000000000000000000003")},
		{"alpha_beta", mustBE("0a0b0c0d0e0f1011121314151617181920212223242526272829303132333435"), mustBE("01b2c3d4e5f60718293a4b5c6d7e8f9012345678901234567890abcdef012345")},
		{"max_minus_one", mustBE("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000"), mustBE("0000000000000000000000000000000000000000000000000000000000000001")},
		{"q_minus_one_both", mustBE("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000"), mustBE("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000")},
		{"interleaved", mustBE("0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), mustBE("0555555555555555555555555555555555555555555555555555555555555555")},
		{"deadbeef_cafebabe",
			mustBE("00000000000000000000000000000000000000000000000000000000deadbeef"),
			mustBE("00000000000000000000000000000000000000000000000000000000cafebabe")},
		{"high_low",
			mustBE("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"),
			mustBE("0edcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210")},
		{"merkle_l0",
			mustBE("17b0761f87b081d5cf10757ccc89f12be355c70e2e29df288b65b30710dcbcd1"),
			mustBE("00ce0a73ad9c8da6c5af0f3aaeebbed5b3c45e92dc6cb24f3a5d8d18d4234d52")},
		{"merkle_l1",
			mustBE("13b8da37bf68d9c1c19c4f8a4f2e7e3a4b8c5b22b6e1a8b6f5e7c8a3a1c5e6f7"),
			mustBE("0a000000000000000000000000000000000000000000000000000000000000ff")},
		{"reversed_pair",
			mustBE("01b2c3d4e5f60718293a4b5c6d7e8f9012345678901234567890abcdef012345"),
			mustBE("0a0b0c0d0e0f1011121314151617181920212223242526272829303132333435")},
	}

	// Print a single derived round-key sample to cross-check initRC: first round-key element of the very first full round, when seed = "Poseidon2-BN254[t=2,rF=6,rP=50,d=5]".
	// Internal access: we just call NewParameters identically and Marshal RK[0][0].
	pp := poseidon2.NewParameters(2, 6, 50)
	rk0 := pp.RoundKeys[0][0]
	rk0Bytes := rk0.Bytes()
	fmt.Printf("// initRC[0][0] = %x\n", rk0Bytes[:])
	rk1 := pp.RoundKeys[0][1]
	rk1Bytes := rk1.Bytes()
	fmt.Printf("// initRC[0][1] = %x\n", rk1Bytes[:])
	// Last round key (full round, 2 elements at index rF/2 + rP + (rF/2-1)).
	rkLast := pp.RoundKeys[len(pp.RoundKeys)-1][1]
	rkLastBytes := rkLast.Bytes()
	fmt.Printf("// initRC[%d][1] = %x\n", len(pp.RoundKeys)-1, rkLastBytes[:])

	// Print KATs as a C++ array body.
	fmt.Println("// === BEGIN POSEIDON2_KAT ===")
	for i, c := range cases {
		out := hash2(c.l, c.r)
		fmt.Printf("// %d %s\n", i, c.name)
		fmt.Printf("    {\"%s\",\n", c.name)
		fmt.Printf("     \"%x\",\n", c.l[:])
		fmt.Printf("     \"%x\",\n", c.r[:])
		fmt.Printf("     \"%x\"},\n", out)
	}
	fmt.Println("// === END POSEIDON2_KAT ===")

	// Sanity: hash a 4-element preimage via MerkleDamgard for hash_n confirmation.
	// MerkleDamgard with iv=zeros and Compress(state, block) chain.
	a := mustBE("0000000000000000000000000000000000000000000000000000000000000001")
	b := mustBE("0000000000000000000000000000000000000000000000000000000000000002")
	c0 := mustBE("0000000000000000000000000000000000000000000000000000000000000003")
	d := mustBE("0000000000000000000000000000000000000000000000000000000000000004")
	mdInputs := [][]byte{a[:], b[:], c0[:], d[:]}
	// The natural hash_n is: state=zero; for each x in xs: state = Compress(state, x.bytes).
	state := make([]byte, 32)
	pp2 := poseidon2.NewDefaultPermutation()
	for _, x := range mdInputs {
		var l, r [32]byte
		copy(l[:], state)
		copy(r[:], x)
		out, err := pp2.Compress(l[:], r[:])
		if err != nil { panic(err) }
		state = out
	}
	fmt.Printf("// hash_n([1,2,3,4]) merkle-damgard with iv=0: %x\n", state)

	// And the hasher's Sum() with .Write(concat) behavior, for cross-check via NewMerkleDamgardHasher
	h := poseidon2.NewMerkleDamgardHasher()
	for _, x := range mdInputs {
		_, _ = h.Write(x)
	}
	digest := h.Sum(nil)
	fmt.Printf("// hash_n via NewMerkleDamgardHasher.Sum: %x\n", digest)

	// Touch fr to silence unused
	var fe fr.Element
	_ = fe
}
