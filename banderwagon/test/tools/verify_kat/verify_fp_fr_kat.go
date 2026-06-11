// SPDX-License-Identifier: Apache-2.0
//
// verify_fp_fr_kat.go -- second-oracle verifier for banderwagon fp_kat.h /
// fr_kat.h.
//
// Per Red O2/O4: byte-equality across two independent implementations is
// required before any KAT vector can be considered trusted. The primary
// generators (../gen_fp_kat.go, ../gen_fr_kat.go) emit vectors using
// gnark-crypto's bls12-381/fr (== Bandersnatch Fp) and gnark's Bandersnatch
// scalar field. This verifier re-reads each committed header and replays
// every (a, b, op) tuple against the arkworks-rs oracle in ../ark_oracle/,
// asserting:
//
//   1. arkworks decodes the LE input identically (canonicality OK)
//   2. arkworks's add / mul output matches the stored result byte-for-byte
//   3. gnark-crypto re-run also matches the stored result
//
// On any disagreement the verifier exits non-zero with both sides dumped.
//
// Run:
//   cd banderwagon/test/tools/verify_kat
//   (cd ../ark_oracle && cargo build --release)
//   go run verify_fp_fr_kat.go ../../fp_kat.h ../../fr_kat.h
//
// Exit code 0: every entry agrees across stored / gnark / arkworks.
// Exit code != 0: divergence; KAT must NOT be committed.

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	gnarkfp "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	kinetfr "github.com/kinet-labs/crypto/ipa/bandersnatch/fr"
)

// arkOracle wraps the long-lived Rust subprocess that answers
// "<field> <op> <a_le_hex> <b_le_hex>" -> "ok <r_le_hex>".
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

func (o *arkOracle) query(field, op string, a, b [32]byte) ([32]byte, error) {
	var zero [32]byte
	line := fmt.Sprintf("%s %s %s %s\n", field, op, hex32(a), hex32(b))
	if _, err := io.WriteString(o.in, line); err != nil {
		return zero, fmt.Errorf("ark_oracle write: %w", err)
	}
	resp, err := o.out.ReadString('\n')
	if err != nil {
		return zero, fmt.Errorf("ark_oracle read: %w (stderr: %q)", err, o.errs.String())
	}
	resp = strings.TrimRight(resp, "\n")
	if !strings.HasPrefix(resp, "ok ") {
		return zero, fmt.Errorf("ark_oracle rejected query %q: %s", strings.TrimSpace(line), resp)
	}
	hexStr := strings.TrimPrefix(resp, "ok ")
	if len(hexStr) != 64 {
		return zero, fmt.Errorf("ark_oracle returned non-32-byte hex (%d chars): %s", len(hexStr), hexStr)
	}
	var out [32]byte
	for i := 0; i < 32; i++ {
		hi, err1 := hexNibble(hexStr[2*i])
		lo, err2 := hexNibble(hexStr[2*i+1])
		if err1 != nil || err2 != nil {
			return zero, fmt.Errorf("bad hex byte at %d", i)
		}
		out[i] = (hi << 4) | lo
	}
	return out, nil
}

func (o *arkOracle) close() {
	_ = o.in.Close()
	_ = o.cmd.Wait()
}

func hex32(b [32]byte) string {
	const hexd = "0123456789abcdef"
	out := make([]byte, 64)
	for i, x := range b {
		out[2*i] = hexd[x>>4]
		out[2*i+1] = hexd[x&0xf]
	}
	return string(out)
}

func hexNibble(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	}
	return 0, fmt.Errorf("invalid hex byte %q", c)
}

// One row from a committed fp_kat.h / fr_kat.h. The C++ initialiser is
//
//	{"name", "add",
//	 {0x..., 0x..., ...},   // a (32 bytes LE)
//	 {0x..., 0x..., ...},   // b
//	 {0x..., 0x..., ...}},  // r
type katRow struct {
	name    string
	op      string
	a, b, r [32]byte
}

// regex pieces
var headerRe = regexp.MustCompile(`^\s*\{"([^"]+)",\s*"(add|mul)",\s*$`)
var arrayRe = regexp.MustCompile(`\{((?:0x[0-9a-fA-F]{2}(?:,\s*)?)+)\}`)

func parseHeader(path string) ([]katRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<23)

	var rows []katRow
	var cur *katRow
	var arrIdx int

	for sc.Scan() {
		line := sc.Text()
		if cur == nil {
			m := headerRe.FindStringSubmatch(line)
			if m != nil {
				cur = &katRow{name: m[1], op: m[2]}
				arrIdx = 0
			}
			continue
		}
		// Look for one or more {0x..} on this line.
		matches := arrayRe.FindAllStringSubmatch(line, -1)
		for _, m := range matches {
			arr, err := parseByteArray(m[1])
			if err != nil {
				return nil, fmt.Errorf("row %s: %w", cur.name, err)
			}
			switch arrIdx {
			case 0:
				cur.a = arr
			case 1:
				cur.b = arr
			case 2:
				cur.r = arr
				rows = append(rows, *cur)
				cur = nil
			default:
				return nil, fmt.Errorf("row %s: too many arrays", cur.name)
			}
			arrIdx++
			if cur == nil {
				break
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return rows, nil
}

func parseByteArray(s string) ([32]byte, error) {
	var out [32]byte
	parts := strings.Split(s, ",")
	if len(parts) != 32 {
		return out, fmt.Errorf("expected 32 bytes, got %d", len(parts))
	}
	for i, p := range parts {
		p = strings.TrimSpace(p)
		if !strings.HasPrefix(p, "0x") {
			return out, fmt.Errorf("byte %d: missing 0x: %q", i, p)
		}
		hi, err1 := hexNibble(p[2])
		lo, err2 := hexNibble(p[3])
		if err1 != nil || err2 != nil {
			return out, fmt.Errorf("byte %d: bad hex: %q", i, p)
		}
		out[i] = (hi << 4) | lo
	}
	return out, nil
}

func gnarkFpRun(op string, a, b [32]byte) [32]byte {
	var ae, be, re gnarkfp.Element
	_, _ = gnarkfp.LittleEndian.Element(&a)
	_, _ = gnarkfp.LittleEndian.Element(&b)
	ae, _ = gnarkfp.LittleEndian.Element(&a)
	be, _ = gnarkfp.LittleEndian.Element(&b)
	switch op {
	case "add":
		re.Add(&ae, &be)
	case "mul":
		re.Mul(&ae, &be)
	}
	var out [32]byte
	gnarkfp.LittleEndian.PutElement(&out, re)
	return out
}

func gnarkFrRun(op string, a, b [32]byte) [32]byte {
	var ae, be, re kinetfr.Element
	if _, err := ae.SetBytesLECanonical(a[:]); err != nil {
		// Should never happen for canonical KAT inputs.
		return [32]byte{}
	}
	if _, err := be.SetBytesLECanonical(b[:]); err != nil {
		return [32]byte{}
	}
	switch op {
	case "add":
		re.Add(&ae, &be)
	case "mul":
		re.Mul(&ae, &be)
	}
	return re.BytesLE()
}

func verifyFile(o *arkOracle, path, field string, gnarkRun func(string, [32]byte, [32]byte) [32]byte) (int, error) {
	rows, err := parseHeader(path)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(rows) == 0 {
		return 0, fmt.Errorf("no rows parsed from %s", path)
	}
	agree := 0
	for _, r := range rows {
		gnarkR := gnarkRun(r.op, r.a, r.b)
		arkR, err := o.query(field, r.op, r.a, r.b)
		if err != nil {
			return agree, fmt.Errorf("row %s: %w", r.name, err)
		}
		if gnarkR != r.r || arkR != r.r || gnarkR != arkR {
			fmt.Fprintf(os.Stderr,
				"ORACLE DIVERGENCE (%s/%s/%s):\n  a       = %x\n  b       = %x\n  stored  = %x\n  gnark   = %x\n  arkwork = %x\nABORTING.\n",
				field, r.op, r.name, r.a, r.b, r.r, gnarkR, arkR)
			return agree, fmt.Errorf("divergence in %s", r.name)
		}
		agree++
	}
	return agree, nil
}

func main() {
	fpPath := "../../fp_kat.h"
	frPath := "../../fr_kat.h"
	if len(os.Args) >= 3 {
		fpPath = os.Args[len(os.Args)-2]
		frPath = os.Args[len(os.Args)-1]
	}

	oracle, err := startArkOracle()
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(2)
	}
	defer oracle.close()

	fpAgree, err := verifyFile(oracle, fpPath, "fp", gnarkFpRun)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fp verify failed: %v\n", err)
		os.Exit(3)
	}
	frAgree, err := verifyFile(oracle, frPath, "fr", gnarkFrRun)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fr verify failed: %v\n", err)
		os.Exit(3)
	}
	fmt.Fprintf(os.Stderr, "banderwagon/fp: %d/%d gnark <-> arkworks <-> stored byte-equal (Red O2/O4 PASS)\n", fpAgree, fpAgree)
	fmt.Fprintf(os.Stderr, "banderwagon/fr: %d/%d gnark <-> arkworks <-> stored byte-equal (Red O2/O4 PASS)\n", frAgree, frAgree)
}
