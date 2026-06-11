// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// ark_oracle -- second oracle for Banderwagon Fp/Fr KAT generation.
//
// Reads a tiny line-protocol on stdin and writes one line per request to
// stdout. The Go KAT generators use this to cross-verify gnark-crypto outputs
// against the arkworks implementation before committing C++ KAT vectors.
//
// Protocol (one request per line, ASCII; little-endian hex):
//   fp <add|mul> <a_le_hex> <b_le_hex>
//   fr <add|mul> <a_le_hex> <b_le_hex>
//
// Each input is exactly 64 hex chars (32 bytes, little-endian canonical).
// Each response is "ok <r_le_hex>" or "err <message>". The binary blocks on
// stdin and exits when stdin closes.
//
// Field mapping:
//   fp -> ark_bls12_381::Fr            (BLS12-381 scalar field; the Banderwagon
//                                       base field Fp == this).
//   fr -> ark_ed_on_bls12_381_bandersnatch::Fr (Bandersnatch scalar field).

use std::io::{self, BufRead, Write};

use ark_bls12_381::Fr as Bls12381Fr;
use ark_ed_on_bls12_381_bandersnatch::Fr as BandersnatchFr;
use ark_ff::{BigInteger, PrimeField, Zero};

fn parse_hex32(s: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", s.len()));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = hex_nibble(s.as_bytes()[2 * i])?;
        let lo = hex_nibble(s.as_bytes()[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
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

fn hex32(b: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for &x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

// Convert 32-byte LE input to a field element. Reject non-canonical (>= modulus).
fn fp_from_le(b: &[u8; 32]) -> Result<Bls12381Fr, String> {
    let f = Bls12381Fr::from_le_bytes_mod_order(b);
    // Re-encode and require equality with input -> rejects non-canonical.
    let mut le = f.into_bigint().to_bytes_le();
    le.resize(32, 0u8);
    if le != b[..] {
        return Err("fp non-canonical: >= modulus".into());
    }
    Ok(f)
}

fn fr_from_le(b: &[u8; 32]) -> Result<BandersnatchFr, String> {
    let f = BandersnatchFr::from_le_bytes_mod_order(b);
    let mut le = f.into_bigint().to_bytes_le();
    le.resize(32, 0u8);
    if le != b[..] {
        return Err("fr non-canonical: >= modulus".into());
    }
    Ok(f)
}

fn fp_to_le(f: &Bls12381Fr) -> [u8; 32] {
    let mut le = f.into_bigint().to_bytes_le();
    le.resize(32, 0u8);
    let mut out = [0u8; 32];
    out.copy_from_slice(&le[..32]);
    out
}

fn fr_to_le(f: &BandersnatchFr) -> [u8; 32] {
    let mut le = f.into_bigint().to_bytes_le();
    le.resize(32, 0u8);
    let mut out = [0u8; 32];
    out.copy_from_slice(&le[..32]);
    out
}

fn handle(line: &str) -> Result<String, String> {
    let mut it = line.split_whitespace();
    let field = it.next().ok_or("missing field")?;
    let op = it.next().ok_or("missing op")?;
    let a_hex = it.next().ok_or("missing a")?;
    let b_hex = it.next().ok_or("missing b")?;
    if it.next().is_some() {
        return Err("trailing tokens".into());
    }
    let a_b = parse_hex32(a_hex)?;
    let b_b = parse_hex32(b_hex)?;

    match field {
        "fp" => {
            let a = fp_from_le(&a_b)?;
            let b = fp_from_le(&b_b)?;
            let r = match op {
                "add" => a + b,
                "mul" => a * b,
                _ => return Err(format!("bad op: {op}")),
            };
            Ok(hex32(&fp_to_le(&r)))
        }
        "fr" => {
            let a = fr_from_le(&a_b)?;
            let b = fr_from_le(&b_b)?;
            let r = match op {
                "add" => a + b,
                "mul" => a * b,
                _ => return Err(format!("bad op: {op}")),
            };
            Ok(hex32(&fr_to_le(&r)))
        }
        _ => Err(format!("bad field: {field}")),
    }
}

fn main() {
    // Sanity-link both crates so dead-code elimination doesn't drop them.
    let _ = Bls12381Fr::zero();
    let _ = BandersnatchFr::zero();

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
            Ok(hex) => {
                let _ = writeln!(out, "ok {hex}");
            }
            Err(e) => {
                let _ = writeln!(out, "err {e}");
            }
        }
        let _ = out.flush();
    }
}
