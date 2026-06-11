// SPDX-License-Identifier: Apache-2.0
//
// verify_pairing_kat.go -- second-oracle verifier for bn254_pairing_kat.h.
//
// Per Red O2/O4: byte-equality across two independent implementations is
// required before any KAT vector can be considered trusted. The primary
// generator (../gen_pairing_kat.go) emits vectors using gnark-crypto's
// PairingCheck; this verifier re-reads the committed header file and replays
// every pair concatenation against the arkworks-rs oracle in ../ark_oracle/,
// asserting that:
//
//   1. arkworks decodes the EIP-197 input identically (curve + subgroup OK)
//   2. arkworks's pairing predicate matches the stored expected value
//   3. gnark-crypto's PairingCheck (re-run here) also matches
//
// On any disagreement, the verifier exits with a loud error and a side-by-side
// dump. This is a precondition for committing any change to either the
// generator or the KAT header.
//
// Run:
//   cd bn254/test/tools/verify_kat
//   (cd ../ark_oracle && cargo build --release)
//   go run verify_pairing_kat.go ../../bn254_pairing_kat.h
//
// Exit code 0: all entries agree across both oracles + stored predicate.
// Exit code != 0: divergence; KAT must NOT be committed.

package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
)

// arkOracle runs the Rust binary as a long-lived subprocess and answers
// "pair <hex>" -> "ok 0" | "ok 1" | "err <message>".
type arkOracle struct {
	cmd  *exec.Cmd
	in   io.WriteCloser
	out  *bufio.Reader
	errs *bytes.Buffer
}

func startArkOracle() (*arkOracle, error) {
	_, thisFile, _, _ := runtime.Caller(0)
	root := filepath.Dir(thisFile)
	bin := filepath.Join(root, "..", "ark_oracle", "target", "release", "ark_oracle")
	abs, err := filepath.Abs(bin)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(abs); err != nil {
		return nil, fmt.Errorf("ark_oracle binary not found at %s: %w (run `cargo build --release` in ../ark_oracle/ first)", abs, err)
	}
	cmd := exec.Command(abs)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	var errs bytes.Buffer
	cmd.Stderr = &errs
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &arkOracle{cmd: cmd, in: stdin, out: bufio.NewReader(stdout), errs: &errs}, nil
}

func (o *arkOracle) queryPair(pairsHex string) (bool, error) {
	if _, err := io.WriteString(o.in, "pair "+pairsHex+"\n"); err != nil {
		return false, fmt.Errorf("ark_oracle write: %w", err)
	}
	resp, err := o.out.ReadString('\n')
	if err != nil {
		return false, fmt.Errorf("ark_oracle read: %w (stderr: %q)", err, o.errs.String())
	}
	switch strings.TrimRight(resp, "\n") {
	case "ok 0":
		return false, nil
	case "ok 1":
		return true, nil
	}
	return false, fmt.Errorf("ark_oracle rejected: %s", strings.TrimRight(resp, "\n"))
}

func (o *arkOracle) close() {
	_ = o.in.Close()
	_ = o.cmd.Wait()
}

// One row from the KAT header. Lines look like:
//
//	{"empty", 0, 1, ""},
//	{"g1_negg2__g1_g2", 2, 1, "00...AA"},
type katRow struct {
	name     string
	nPairs   int
	expected bool
	hexBytes string
}

var rowRe = regexp.MustCompile(`^\s*\{"([^"]+)",\s*(\d+),\s*([01]),\s*"([0-9a-fA-F]*)"\}\s*,?\s*$`)

func parseHeader(path string) ([]katRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var rows []katRow
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<23)
	inside := false
	for sc.Scan() {
		line := sc.Text()
		if strings.Contains(line, "BEGIN BN254_PAIRING_KAT") {
			inside = true
			continue
		}
		if strings.Contains(line, "END BN254_PAIRING_KAT") {
			break
		}
		if !inside {
			continue
		}
		m := rowRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		nPairs, err := strconv.Atoi(m[2])
		if err != nil {
			return nil, fmt.Errorf("bad n_pairs in line %q: %w", line, err)
		}
		rows = append(rows, katRow{
			name: m[1], nPairs: nPairs, expected: m[3] == "1", hexBytes: m[4],
		})
	}
	return rows, sc.Err()
}

func decodeGnark(raw []byte, n int) ([]bn254.G1Affine, []bn254.G2Affine, error) {
	if len(raw) != 192*n {
		return nil, nil, fmt.Errorf("expected %d bytes, got %d", 192*n, len(raw))
	}
	g1s := make([]bn254.G1Affine, 0, n)
	g2s := make([]bn254.G2Affine, 0, n)
	for i := 0; i < n; i++ {
		p := raw[192*i : 192*(i+1)]
		var P bn254.G1Affine
		var Q bn254.G2Affine
		var fx, fy fp.Element
		fx.SetBytes(p[0:32])
		fy.SetBytes(p[32:64])
		P.X = fx
		P.Y = fy
		var x1, x0, y1, y0 fp.Element
		x1.SetBytes(p[64:96])
		x0.SetBytes(p[96:128])
		y1.SetBytes(p[128:160])
		y0.SetBytes(p[160:192])
		Q.X.A1 = x1
		Q.X.A0 = x0
		Q.Y.A1 = y1
		Q.Y.A0 = y0
		g1s = append(g1s, P)
		g2s = append(g2s, Q)
	}
	return g1s, g2s, nil
}

func main() {
	headerPath := "../../bn254_pairing_kat.h"
	if len(os.Args) > 1 {
		headerPath = os.Args[len(os.Args)-1]
	}

	rows, err := parseHeader(headerPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse %s: %v\n", headerPath, err)
		os.Exit(2)
	}
	if len(rows) == 0 {
		fmt.Fprintf(os.Stderr, "no KAT rows parsed from %s\n", headerPath)
		os.Exit(2)
	}

	oracle, err := startArkOracle()
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(2)
	}
	defer oracle.close()

	agree := 0
	for _, r := range rows {
		raw, err := hex.DecodeString(r.hexBytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "row %s: bad hex: %v\n", r.name, err)
			os.Exit(2)
		}
		g1s, g2s, err := decodeGnark(raw, r.nPairs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "row %s: gnark decode: %v\n", r.name, err)
			os.Exit(2)
		}
		gnarkOK := true
		if r.nPairs > 0 {
			gnarkOK, err = bn254.PairingCheck(g1s, g2s)
			if err != nil {
				fmt.Fprintf(os.Stderr, "row %s: gnark PairingCheck: %v\n", r.name, err)
				os.Exit(2)
			}
		}
		arkOK, err := oracle.queryPair(r.hexBytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "row %s: arkworks query: %v\n", r.name, err)
			os.Exit(2)
		}
		if gnarkOK != r.expected || arkOK != r.expected || gnarkOK != arkOK {
			fmt.Fprintf(os.Stderr,
				"ORACLE DIVERGENCE (%s):\n  pairs    = %s\n  expected = %v\n  gnark    = %v\n  arkworks = %v\nABORTING.\n",
				r.name, r.hexBytes, r.expected, gnarkOK, arkOK)
			os.Exit(3)
		}
		agree++
	}
	fmt.Fprintf(os.Stderr, "bn254/pairing: %d/%d gnark <-> arkworks <-> stored byte-equal (Red O2/O4 PASS)\n", agree, len(rows))
}
