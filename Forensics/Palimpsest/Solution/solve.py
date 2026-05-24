#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║   SOLVE SCRIPT  ─  Palimpsest  (CTF Forensics)      ║
║   Usage:  python3 solve.py redacted_report.pdf       ║
╚══════════════════════════════════════════════════════╝
"""

import sys, zlib, re

BANNER = """
╔══════════════════════════════════════════════════════╗
║          Palimpsest – PDF Forensics Solver           ║
╚══════════════════════════════════════════════════════╝
"""

def solve(path: str) -> None:
    print(BANNER)
    print(f"[*] Target : {path}")

    with open(path, "rb") as f:
        data = f.read()
    print(f"[*] Size   : {len(data):,} bytes\n")

    # ──────────────────────────────────────────────────────────────────────
    # STEP 1 – Count %%EOF markers
    #   A PDF with incremental updates has MORE than one %%EOF.
    #   Each %%EOF closes one revision.
    # ──────────────────────────────────────────────────────────────────────
    eof_offsets = []
    pos = 0
    while True:
        idx = data.find(b"%%EOF", pos)
        if idx == -1:
            break
        eof_offsets.append(idx)
        pos = idx + 5

    print(f"[STEP 1] Scanning for %%EOF markers...")
    print(f"         Found : {len(eof_offsets)} marker(s)")
    for i, o in enumerate(eof_offsets, 1):
        print(f"         Rev {i}: %%EOF at offset {o}  (0x{o:04X})")

    if len(eof_offsets) < 2:
        print("\n[-] Single revision only – flag is not hidden this way.")
        return

    print("\n[+] MULTIPLE REVISIONS DETECTED  →  PDF Incremental Update!")
    print("    The latest revision may have overwritten earlier objects.")
    print("    We need to examine the ORIGINAL revision.\n")

    # ──────────────────────────────────────────────────────────────────────
    # STEP 2 – Extract Revision 1 (bytes up to and including first %%EOF)
    # ──────────────────────────────────────────────────────────────────────
    rev1_end = eof_offsets[0] + 5
    rev1     = data[:rev1_end]
    print(f"[STEP 2] Extracting Revision 1 ...")
    print(f"         Bytes  : 0 – {rev1_end}  ({len(rev1):,} bytes)")

    # ──────────────────────────────────────────────────────────────────────
    # STEP 3 – List ALL objects in Revision 1
    #   Enumerate "N 0 obj" patterns; some may not be referenced by the
    #   page tree and thus invisible in any PDF viewer.
    # ──────────────────────────────────────────────────────────────────────
    print(f"\n[STEP 3] Enumerating objects in Revision 1 ...")
    obj_matches = list(re.finditer(rb"(\d+) 0 obj", rev1))
    for m in obj_matches:
        num = int(m.group(1))
        off = m.start()
        print(f"         Obj {num:2d} at offset {off:5d}  (0x{off:04X})")

    # Objects referenced by the page tree
    referenced = {1, 2, 3, 4, 5, 6}   # catalog, pages, page, content, font, info
    all_objs   = {int(m.group(1)) for m in obj_matches}
    orphans    = all_objs - referenced
    if orphans:
        print(f"\n[!] UNREFERENCED (orphan) objects: {orphans}")
        print("    These will NOT be rendered by a PDF viewer  ← suspicious!")

    # ──────────────────────────────────────────────────────────────────────
    # STEP 4 – Inspect Object 7 (the suspicious orphan)
    # ──────────────────────────────────────────────────────────────────────
    print(f"\n[STEP 4] Inspecting Object 7 ...")
    pos7 = rev1.find(b"7 0 obj")
    if pos7 == -1:
        print("[-] Object 7 not found in Revision 1.")
        return

    # Read the object dictionary (everything before 'stream')
    dict_end      = rev1.find(b"\nstream\n", pos7)
    obj7_dict_raw = rev1[pos7: dict_end].decode("latin-1")
    print(f"         Dict   : {obj7_dict_raw.strip()}")

    has_flat = b"FlateDecode" in rev1[pos7: dict_end]
    print(f"         Filter : {'FlateDecode  ← zlib compressed!' if has_flat else 'none'}")

    if not has_flat:
        print("[-] Expected FlateDecode. Check other orphan objects.")
        return

    # ──────────────────────────────────────────────────────────────────────
    # STEP 5 – Extract the raw stream bytes
    # ──────────────────────────────────────────────────────────────────────
    stream_start = dict_end + len(b"\nstream\n")
    stream_end   = rev1.find(b"\nendstream", stream_start)
    raw_stream   = rev1[stream_start: stream_end]

    print(f"\n[STEP 5] Extracting raw stream ...")
    print(f"         Length : {len(raw_stream)} bytes")
    print(f"         Hex    : {raw_stream[:20].hex()} ...")

    # ──────────────────────────────────────────────────────────────────────
    # STEP 6 – FlateDecode = zlib.decompress
    # ──────────────────────────────────────────────────────────────────────
    print(f"\n[STEP 6] Decompressing (FlateDecode / zlib) ...")
    try:
        decompressed = zlib.decompress(raw_stream)
    except Exception as e:
        print(f"[-] zlib.decompress() failed: {e}")
        return

    decoded_str = decompressed.decode("ascii")
    print(f"         Result : {decoded_str}")
    print(f"         Looks like: HEX STRING  ({len(decoded_str)} hex chars = {len(decoded_str)//2} bytes)")

    # ──────────────────────────────────────────────────────────────────────
    # STEP 7 – Hex decode → plaintext flag
    # ──────────────────────────────────────────────────────────────────────
    print(f"\n[STEP 7] Hex-decoding ...")
    try:
        flag = bytes.fromhex(decoded_str).decode("utf-8")
    except Exception as e:
        print(f"[-] Hex decode failed: {e}")
        return

    print(f"\n{'━'*52}")
    print(f"  🏁  FLAG :  {flag}")
    print(f"{'━'*52}\n")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "redacted_report.pdf"
    solve(target)
