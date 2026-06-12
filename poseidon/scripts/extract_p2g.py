#!/usr/bin/env python3
"""Extract Poseidon2-Goldilocks-t=8 constants from upstream horizen-labs source.
Emits a self-contained C++ header with hex literals for:
  - MAT_DIAG8_M_1[8]  (8 entries)
  - RC8[30][8]        (30 rounds, t=8 entries each; partial rounds: only [0] non-zero)
"""
import re, sys
src = open('/tmp/horizen_goldilocks.rs').read()
def slice_block(name):
    # Find "pub static ref NAME: Vec<...> = vec![" ... matching outer "];"
    pat = re.compile(r'pub static ref ' + name + r': [^=]*=\s*vec!\[(.*?)\n    \];', re.DOTALL)
    m = pat.search(src)
    if not m:
        sys.exit("missing block " + name)
    return m.group(1)

def hexes(block):
    return re.findall(r'from_hex\("0x([0-9a-fA-F]+)"\)', block)

mat = hexes(slice_block('MAT_DIAG8_M_1'))
assert len(mat) == 8, len(mat)
rc_block = slice_block('RC8')
# Parse RC8 as 30 inner vecs each with 8 hexes
rounds = re.findall(r'vec!\[(.*?)\n    \],', rc_block, re.DOTALL)
assert len(rounds) == 30, len(rounds)
rc = [hexes(r) for r in rounds]
for r in rc:
    assert len(r) == 8, len(r)

print(f'// Poseidon2-Goldilocks-t=8 constants. Auto-extracted from')
print(f'// horizen-labs/poseidon2 @ main:')
print(f'//   plain_implementations/src/poseidon2/poseidon2_instance_goldilocks.rs')
print(f'// Source URL: https://raw.githubusercontent.com/HorizenLabs/poseidon2/main/plain_implementations/src/poseidon2/poseidon2_instance_goldilocks.rs')
print(f'// Parameters: t=8, d=7, rF=8 (4 pre + 4 post), rP=22, rounds=30.')
print(f'// SPDX-License-Identifier: BSD-3-Clause-Eco')
print(f'//')
print(f'// DO NOT EDIT BY HAND. Re-run scripts/extract_p2g.py to regenerate.')
print()
print(f'#pragma once')
print(f'#include <cstdint>')
print()
print(f'namespace kinet::crypto::poseidon::p2g {{')
print()
print(f'inline constexpr int    T              = 8;')
print(f'inline constexpr int    SBOX_DEGREE    = 7;')
print(f'inline constexpr int    FULL_ROUNDS    = 8;')
print(f'inline constexpr int    PARTIAL_ROUNDS = 22;')
print(f'inline constexpr int    HALF_FULL      = 4;')
print(f'inline constexpr int    TOTAL_ROUNDS   = 30;')
print()
print(f'// MAT_DIAG8_M_1[i] = (diagonal entry of M_I) - 1.')
print(f'// matmul_internal: sum = Sum(state); state[i] = state[i]*MAT_DIAG[i] + sum.')
print(f'inline constexpr uint64_t MAT_DIAG8_M_1[T] = {{')
for h in mat:
    print(f'    UINT64_C(0x{h}),')
print(f'}};')
print()
print(f'// Round constants. Layout: 4 pre-full + 22 partial + 4 post-full.')
print(f'// For partial rounds, only RC8[r][0] is added (slots 1..7 are zero in upstream).')
print(f'inline constexpr uint64_t RC8[TOTAL_ROUNDS][T] = {{')
for i, r in enumerate(rc):
    if i < 4:
        tag = "full pre  "
    elif i < 4+22:
        tag = "partial    "
    else:
        tag = "full post "
    inner = ", ".join(f"UINT64_C(0x{h})" for h in r)
    print(f'    {{ {inner} }},  // round {i:2d} ({tag})')
print(f'}};')
print()
print(f'}}  // namespace kinet::crypto::poseidon::p2g')
