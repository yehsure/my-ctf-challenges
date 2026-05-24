#!/usr/bin/env python3
"""
Solution script for "3-Layer Vault" CTF Challenge
Flag format: DWY_YK{...}

Reverse engineering steps:
  1. Identify the 3-layer transformation in vault_check()
  2. Invert Layer 3 (ROR instead of ROL)
  3. Invert Layer 2 (XOR is self-inverse)
  4. Invert Layer 1 (apply reverse permutation)
"""

# ─── Constants extracted from binary ──────────────────────────────────────────

PERM = [5, 11, 3, 15, 7, 17, 1, 13, 9, 0, 16, 4, 12, 8, 2, 10, 14, 6]
# (Found by reading the permutation table at .rodata in Ghidra/IDA)

TARGET = bytes([208, 19, 117, 176, 89, 84, 124, 211, 139, 21, 164, 2, 97, 165, 78, 247, 158, 138])
# (Found by reading TARGET array in .rodata)

# ─── Reconstruct XORKEY from LFSR ─────────────────────────────────────────────
# Binary: Galois LFSR — 16-bit, polynomial tap 0xB400, seed 0x1337
# Decompiler hint: the seed 0x1337 + bit-manipulation loop generates this stream

def lfsr_keys(n, seed=0x1337):
    keys, state = [], seed
    for _ in range(n):
        keys.append(state & 0xFF)
        lsb = state & 1
        state >>= 1
        if lsb:
            state ^= 0xB400
    return bytes(keys)

XORKEY = lfsr_keys(len(TARGET))

# ─── Helper: bit rotation ─────────────────────────────────────────────────────

def ror8(v: int, n: int) -> int:
    """Rotate byte v right by n bits."""
    n &= 7
    return ((v >> n) | (v << (8 - n))) & 0xFF

def rol8(v: int, n: int) -> int:
    """Rotate byte v left by n bits."""
    n &= 7
    return ((v << n) | (v >> (8 - n))) & 0xFF

# ─── Reverse the 3 layers ─────────────────────────────────────────────────────

def solve():
    N = len(TARGET)

    # STEP 1 — Undo Layer 3: ROR by (i%5)+1
    step3_inv = bytes(ror8(TARGET[i], (i % 5) + 1) for i in range(N))

    # STEP 2 — Undo Layer 2: XOR is self-inverse (A ^ K ^ K == A)
    step2_inv = bytes(step3_inv[i] ^ XORKEY[i] for i in range(N))

    # STEP 3 — Undo Layer 1: forward was out[PERM[i]] = inp[i]
    #           so reverse is  inp[i] = out[PERM[i]]
    step1_inv = bytes(step2_inv[PERM[i]] for i in range(N))

    inner = step1_inv.decode("ascii")
    flag  = f"DWY_YK{{{inner}}}"
    return flag

# ─── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    flag = solve()
    print(f"[+] Recovered flag: {flag}")

    # Quick sanity check — re-apply forward transform and verify against TARGET
    inner = flag[7:-1].encode()
    N = len(inner)
    buf = bytearray(N)
    for i in range(N):
        buf[PERM[i]] = inner[i]
    for i in range(N):
        buf[i] ^= XORKEY[i]
    for i in range(N):
        buf[i] = rol8(buf[i], (i % 5) + 1)

    assert bytes(buf) == TARGET, "Sanity check FAILED!"
    print("[+] Sanity check passed ✓")
