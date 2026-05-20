#!/usr/bin/env python3
"""
Solver for "Chromatic Shadows" CTF Forensics Challenge
Usage:  python solve.py capture.png
"""
import struct
import zlib
import base64
import sys
import numpy as np
from PIL import Image


# ─── HELPERS ──────────────────────────────────────────────────────────────────

def rot13(s: str) -> str:
    out = []
    for c in s:
        if 'a' <= c <= 'z':
            out.append(chr((ord(c) - ord('a') + 13) % 26 + ord('a')))
        elif 'A' <= c <= 'Z':
            out.append(chr((ord(c) - ord('A') + 13) % 26 + ord('A')))
        else:
            out.append(c)
    return ''.join(out)


def parse_png_chunks(filepath: str):
    with open(filepath, 'rb') as f:
        raw = f.read()
    SIG = b'\x89PNG\r\n\x1a\n'
    assert raw[:8] == SIG, "File is not a valid PNG"

    chunks = []
    offset = 8
    while offset < len(raw):
        length = struct.unpack('>I', raw[offset:offset+4])[0]
        ctype  = raw[offset+4:offset+8]
        cdata  = raw[offset+8:offset+8+length]
        chunks.append((ctype.decode('ascii', errors='replace'), cdata))
        offset += 12 + length
        if ctype == b'IEND':
            break
    return chunks


def extract_hint(chunks, verbose=True) -> dict | None:
    """
    Find the 'Artist' tEXt chunk, base64-decode its value,
    then ROT13-decode to get the actual hint.
    Returns a dict with keys: channel, modulus, xor_key.
    """
    for ctype, cdata in chunks:
        if ctype == 'tEXt':
            null_idx = cdata.index(b'\x00')
            keyword  = cdata[:null_idx].decode()
            value    = cdata[null_idx+1:].decode()
            if verbose:
                print(f"  [tEXt] keyword={keyword!r}  value={value!r}")
            if keyword == 'Artist':
                rot13ed = base64.b64decode(value).decode()
                hint    = rot13(rot13ed)
                if verbose:
                    print(f"  → base64 decoded : {rot13ed!r}")
                    print(f"  → rot13 decoded  : {hint!r}")
                # Parse: "Resonance: G-channel, filter=(x*y)%17==0, XOR=0x5A"
                params = {}
                for part in hint.split(','):
                    part = part.strip()
                    if 'G-channel' in part:
                        params['channel'] = 1          # G index in RGB
                    elif 'filter=' in part:
                        # extract modulus from "(x*y)%17==0"
                        expr = part.split('filter=')[1]
                        modulus = int(expr.split('%')[1].split('==')[0])
                        params['modulus'] = modulus
                    elif 'XOR=' in part:
                        params['xor_key'] = int(part.split('XOR=')[1], 16)
                return params
    return None


def candidate_positions(width, height, modulus, min_coord=1):
    return [
        (x, y)
        for y in range(min_coord, height)
        for x in range(min_coord, width)
        if (x * y) % modulus == 0
    ]


def extract_lsb_bits(pixels, positions, channel):
    return [int(pixels[y, x, channel]) & 1 for x, y in positions]


def bits_to_bytes(bits):
    out = []
    for i in range(0, len(bits) - (len(bits) % 8), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        out.append(byte)
    return bytes(out)


# ─── MAIN SOLVER ──────────────────────────────────────────────────────────────

def solve(filepath: str = 'capture.png', verbose: bool = True) -> str | None:

    def log(*args):
        if verbose:
            print(*args)

    log("=" * 60)
    log("  Chromatic Shadows – Solver")
    log("=" * 60)

    # ── STEP 1: Inspect PNG chunk structure ───────────────────────────────────
    log("\n[Step 1] Parsing PNG chunks …")
    chunks = parse_png_chunks(filepath)
    for ctype, cdata in chunks:
        log(f"  {ctype:8s}  ({len(cdata):6,} bytes)")

    # ── STEP 2: Extract and decode the hidden hint ────────────────────────────
    log("\n[Step 2] Looking for hidden hint in metadata …")
    params = extract_hint(chunks, verbose=verbose)
    if not params:
        log("  [!] No hint found – trying defaults")
        params = {'channel': 1, 'modulus': 17, 'xor_key': 0x5A}
    log(f"  Recovered params → {params}")

    channel  = params['channel']
    modulus  = params['modulus']
    xor_key  = params['xor_key']

    # ── STEP 3: Load pixel data ───────────────────────────────────────────────
    log("\n[Step 3] Loading image …")
    img    = Image.open(filepath).convert('RGB')
    pixels = np.array(img)
    height, width = pixels.shape[:2]
    log(f"  Dimensions : {width} x {height}")

    # ── STEP 4: Build candidate pixel positions ───────────────────────────────
    log(f"\n[Step 4] Building position list  (x*y) % {modulus} == 0 …")
    positions = candidate_positions(width, height, modulus)
    log(f"  Total positions : {len(positions):,}")

    # ── STEP 5: Extract LSBs ──────────────────────────────────────────────────
    log(f"\n[Step 5] Extracting LSBs from channel index {channel} (G) …")
    bits      = extract_lsb_bits(pixels, positions, channel)
    raw_bytes = bits_to_bytes(bits)
    log(f"  Extracted {len(bits)} bits → {len(raw_bytes)} bytes")

    # ── STEP 6: XOR decrypt ───────────────────────────────────────────────────
    log(f"\n[Step 6] XOR decrypting with key 0x{xor_key:02X} …")
    decrypted = bytes([b ^ xor_key for b in raw_bytes])

    # ── STEP 7: Find the flag ─────────────────────────────────────────────────
    log("\n[Step 7] Searching for flag …")
    log(f"  First 64 bytes : {decrypted[:64]}")

    for prefix in (b'CTF{', b'FLAG{', b'flag{', b'ctf{'):
        idx = decrypted.find(prefix)
        if idx != -1:
            end = decrypted.find(b'}', idx)
            if end != -1:
                flag = decrypted[idx:end+1].decode(errors='replace')
                log(f"\n  *** FLAG FOUND: {flag} ***\n")
                return flag

    log("\n[!] Flag pattern not found – dumping first 200 bytes:")
    log(f"  {decrypted[:200]}")
    return None


if __name__ == '__main__':
    path = sys.argv[1] if len(sys.argv) > 1 else 'capture.png'
    result = solve(path, verbose=True)
    if result:
        print(f"\nFLAG: {result}")
