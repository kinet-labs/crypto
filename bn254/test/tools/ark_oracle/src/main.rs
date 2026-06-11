// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// ark_oracle -- second oracle for bn254 pairing KAT generation.
//
// Reads a tiny line-protocol on stdin and writes one line per request to
// stdout. The Go KAT generator (gen_pairing_kat.go) uses this binary to
// cross-verify gnark-crypto's PairingCheck against arkworks before any KAT
// entry is emitted to the C++ test fixture. (Red O2/O4.)
//
// Protocol (one request per line, ASCII; big-endian hex):
//   pair <hex>
//
// where <hex> is 384*N hex chars (192*N bytes) of N concatenated EIP-197
// pairs. Each pair is laid out as:
//
//   [   0 ..  32 ]  G1.x   (32-byte big-endian Fp)
//   [  32 ..  64 ]  G1.y
//   [  64 ..  96 ]  G2.x.c1   (imaginary part — first per EIP-197)
//   [  96 .. 128 ]  G2.x.c0   (real part)
//   [ 128 .. 160 ]  G2.y.c1
//   [ 160 .. 192 ]  G2.y.c0
//
// Special case: zero G1 or zero G2 (all-zero coordinates) are accepted as
// the point at infinity, matching EIP-197.
//
// Response: "ok 1" (pairing product == 1 in GT) or "ok 0", or "err <msg>".

use std::io::{self, BufRead, Write};

use ark_bn254::{Bn254, Fq, Fq2, Fq12, Fr, G1Affine, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::{BigInteger, Field, PrimeField, Zero};

fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err(format!("odd hex length: {}", s.len()));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        out.push((hex_nibble(bytes[i])? << 4) | hex_nibble(bytes[i + 1])?);
        i += 2;
    }
    Ok(out)
}

fn hex_nibble(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(format!("invalid hex byte: {}", c as char)),
    }
}

// Decode a 32-byte big-endian slice as canonical Fq (rejects >= modulus).
fn fq_from_be(b: &[u8]) -> Result<Fq, String> {
    if b.len() != 32 {
        return Err(format!("Fq input length {} (expected 32)", b.len()));
    }
    let f = Fq::from_be_bytes_mod_order(b);
    // Re-encode and reject if it differs (i.e. input was >= modulus).
    let canon = f.into_bigint().to_bytes_be();
    let mut padded = vec![0u8; 32];
    let off = 32 - canon.len();
    padded[off..].copy_from_slice(&canon);
    if padded != b {
        return Err("Fq non-canonical: >= modulus".into());
    }
    Ok(f)
}

fn fq2_from_be(c1: &[u8], c0: &[u8]) -> Result<Fq2, String> {
    Ok(Fq2::new(fq_from_be(c0)?, fq_from_be(c1)?))
}

// Decode one 192-byte EIP-197 pair into (G1Affine, G2Affine).
//
// All-zero G1 coordinates -> point at infinity.
// All-zero G2 coordinates -> point at infinity.
// Otherwise: must lie on the curve and in the correct prime-order subgroup.
fn decode_pair(p: &[u8]) -> Result<(G1Affine, G2Affine), String> {
    if p.len() != 192 {
        return Err(format!("pair length {} (expected 192)", p.len()));
    }
    let g1_x_bytes = &p[0..32];
    let g1_y_bytes = &p[32..64];
    let g2_x_c1 = &p[64..96];
    let g2_x_c0 = &p[96..128];
    let g2_y_c1 = &p[128..160];
    let g2_y_c0 = &p[160..192];

    let g1 = if g1_x_bytes.iter().all(|&b| b == 0) && g1_y_bytes.iter().all(|&b| b == 0) {
        G1Affine::zero()
    } else {
        let x = fq_from_be(g1_x_bytes)?;
        let y = fq_from_be(g1_y_bytes)?;
        let aff = G1Affine::new_unchecked(x, y);
        if !aff.is_on_curve() {
            return Err("G1 not on curve".into());
        }
        if !aff.is_in_correct_subgroup_assuming_on_curve() {
            return Err("G1 not in prime-order subgroup".into());
        }
        aff
    };

    let g2_zero = g2_x_c1.iter().all(|&b| b == 0)
        && g2_x_c0.iter().all(|&b| b == 0)
        && g2_y_c1.iter().all(|&b| b == 0)
        && g2_y_c0.iter().all(|&b| b == 0);
    let g2 = if g2_zero {
        G2Affine::zero()
    } else {
        let x = fq2_from_be(g2_x_c1, g2_x_c0)?;
        let y = fq2_from_be(g2_y_c1, g2_y_c0)?;
        let aff = G2Affine::new_unchecked(x, y);
        if !aff.is_on_curve() {
            return Err("G2 not on curve".into());
        }
        if !aff.is_in_correct_subgroup_assuming_on_curve() {
            return Err("G2 not in prime-order subgroup".into());
        }
        aff
    };
    Ok((g1, g2))
}

// Compute predicate(pairs) := prod_i e(g1_i, g2_i) == 1_GT.
// Empty input -> identity product -> true.
fn pairing_check(pairs: &[(G1Affine, G2Affine)]) -> bool {
    let mut g1s = Vec::with_capacity(pairs.len());
    let mut g2s = Vec::with_capacity(pairs.len());
    for (a, b) in pairs.iter() {
        g1s.push(*a);
        g2s.push(*b);
    }
    Bn254::multi_pairing(g1s.iter(), g2s.iter()).0 == Fq12::ONE
}

fn handle(line: &str) -> Result<String, String> {
    let mut it = line.split_whitespace();
    let op = it.next().ok_or("missing op")?;
    match op {
        "pair" => {
            let hex_str = it.next().unwrap_or("");
            if it.next().is_some() {
                return Err("trailing tokens".into());
            }
            let bytes = parse_hex(hex_str)?;
            if bytes.len() % 192 != 0 {
                return Err(format!(
                    "pair input must be multiple of 192 bytes; got {}",
                    bytes.len()
                ));
            }
            let mut pairs = Vec::new();
            let mut off = 0usize;
            while off < bytes.len() {
                let (a, b) = decode_pair(&bytes[off..off + 192])?;
                pairs.push((a, b));
                off += 192;
            }
            let r = pairing_check(&pairs);
            Ok(format!("{}", r as u8))
        }
        _ => Err(format!("bad op: {op}")),
    }
}

fn main() {
    // Sanity-link types so dead-code elimination doesn't drop them.
    let _ = G1Affine::zero();
    let _ = G2Affine::zero();
    let _: Fr = Fr::zero();

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                let _ = writeln!(out, "err io: {e}");
                let _ = out.flush();
                std::process::exit(1);
            }
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match handle(trimmed) {
            Ok(s) => {
                let _ = writeln!(out, "ok {s}");
            }
            Err(e) => {
                let _ = writeln!(out, "err {e}");
            }
        }
        let _ = out.flush();
    }
}
