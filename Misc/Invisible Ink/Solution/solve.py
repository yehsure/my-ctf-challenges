#!/usr/bin/env python3
"""
solve.py — Solution script for "Mực Vô Hình" / "Invisible Ink"
Zero-Width Character Steganography Challenge

Author  : [your name]
Kỹ thuật: Zero-Width Character Steganography + Base64 decoding
"""

import base64
import sys

# ── Mapping ──────────────────────────────────────────────────────────────────
ZWS  = '\u200b'   # Zero Width Space       → bit 0
ZWNJ = '\u200c'   # Zero Width Non-Joiner  → bit 1

# ── Step 1: Đọc file / Read file ─────────────────────────────────────────────
filename = sys.argv[1] if len(sys.argv) > 1 else 'message.txt'

with open(filename, 'r', encoding='utf-8') as f:
    content = f.read()

print(f"[*] Đã đọc file: {filename}")
print(f"[*] Tổng ký tự trong file  : {len(content)}")

# ── Step 2: Trích xuất ký tự zero-width / Extract zero-width chars ───────────
zwc_seq = [c for c in content if c in (ZWS, ZWNJ)]
print(f"[*] Ký tự ZWC tìm thấy     : {len(zwc_seq)}")
print(f"[*] Ký tự hiển thị         : {len(content) - len(zwc_seq)}")

if len(zwc_seq) == 0:
    print("[-] Không tìm thấy ký tự zero-width nào. Sai file?")
    sys.exit(1)

if len(zwc_seq) % 8 != 0:
    print(f"[!] Cảnh báo: {len(zwc_seq)} ký tự không chia hết cho 8 — có thể bị cắt xén.")

# ── Step 3: Chuyển bitstream → ASCII / Convert bitstream to ASCII ─────────────
bits = ''.join('1' if c == ZWNJ else '0' for c in zwc_seq)
print(f"[*] Bitstream ({len(bits)} bits): {bits[:48]}...")

chars = []
for i in range(0, len(bits) - 7, 8):
    byte = bits[i:i+8]
    val  = int(byte, 2)
    if 32 <= val <= 126:          # printable ASCII only
        chars.append(chr(val))
    else:
        chars.append('?')          # non-printable placeholder

extracted_text = ''.join(chars)
print(f"[*] Văn bản trích xuất     : {extracted_text}")

# ── Step 4: Giải mã Base64 / Decode Base64 ───────────────────────────────────
print()
try:
    # Xử lý padding nếu thiếu
    padded = extracted_text + '=' * (-len(extracted_text) % 4)
    decoded = base64.b64decode(padded).decode('utf-8')
    print(f"[+] Base64 decoded → FLAG  : {decoded}")
except Exception as e:
    print(f"[-] Base64 decode thất bại: {e}")
    print(f"    Văn bản thô: {extracted_text}")

# ── Bonus: In phân tích chi tiết / Bonus: Detailed analysis ─────────────────
print()
print("─── Chi tiết phân tích ───────────────────────────────────────────────")
print(f"  U+200B (ZWS  = 0) count : {zwc_seq.count(ZWS)}")
print(f"  U+200C (ZWNJ = 1) count : {zwc_seq.count(ZWNJ)}")
print(f"  Bytes encoded           : {len(zwc_seq) // 8}")
print(f"  File size overhead      : +{len(content.encode('utf-8')) - len([c for c in content if c not in (ZWS,ZWNJ)])} bytes (approx)")
