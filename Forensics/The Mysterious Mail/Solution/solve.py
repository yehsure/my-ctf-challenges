#!/usr/bin/env python3
# whitespace_steg_decode.py — Decode whitespace steganography (SNOW-style)
# Quy ước: SPACE = 0, TAB = 1 (binary), đọc từng dòng lấy trailing whitespace

def decode_whitespace_steg(filepath):
    bits = []
    with open(filepath, 'r') as f:
        for line in f:
            # Lấy phần trailing whitespace (trước newline)
            stripped = line.rstrip('\n').rstrip('\r')
            trailing = stripped[len(stripped.rstrip()):]  # chỉ phần cuối
            for ch in trailing:
                if ch == ' ':
                    bits.append('0')
                elif ch == '\t':
                    bits.append('1')

    # Ghép bit thành bytes
    chars = []
    for i in range(0, len(bits) - 7, 8):
        byte = ''.join(bits[i:i+8])
        val = int(byte, 2)
        if val == 0:
            break
        chars.append(chr(val))

    return ''.join(chars)

result = decode_whitespace_steg("hidden_message.txt")
print(f"[+] Decoded message: {result}")
