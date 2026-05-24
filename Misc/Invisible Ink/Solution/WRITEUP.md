# CTF Writeup: Mực Vô Hình / Invisible Ink

**Category:** Misc  
**Difficulty:** Easy  
**Flag:** `DWY_YK{z3r0_w1dth_4r3_3v3rywh3r3}`  
**Files:** `message.txt`

---

## Đề bài (Tiếng Việt)

> Một file văn bản bình thường được thu hồi từ một máy chủ bị xâm phạm. Nhóm pháp y tin rằng có một thông điệp bí mật ẩn bên trong — nhưng khi mở bằng trình soạn thảo văn bản, nội dung trông hoàn toàn vô hại.
>
> Tìm flag ẩn trong `message.txt`.
>
> **Flag format:** `DWY_YK{...}`

---

## Challenge Description (English)

> A plain text file was recovered from a compromised internal server. The forensics team believes a secret message is hidden inside — but when opened in any text editor, the contents look completely harmless.
>
> Find the hidden flag in `message.txt`.
>
> **Flag format:** `DWY_YK{...}`

---
---

# Lời giải chi tiết (Tiếng Việt)

## Tổng quan kỹ thuật

Challenge này sử dụng **Zero-Width Character (ZWC) Steganography** — kỹ thuật ẩn dữ liệu bằng cách nhúng các **ký tự Unicode có độ rộng bằng 0** (không nhìn thấy được) vào trong văn bản bình thường.

Các ký tự zero-width **không thể nhìn thấy** trong bất kỳ trình soạn thảo nào, không bị lọc bởi lệnh `strings`, không ảnh hưởng tới rendering, nhưng **vẫn tồn tại trong file** và **chiếm byte thực sự**.

---

## Bước 1: Phát hiện bất thường — Phân tích kích thước file

Bước đầu tiên trong mọi bài Misc/Forensics là **không tin vào mắt mình** — hãy kiểm tra thông tin kỹ thuật của file.

```bash
wc -c message.txt     # 2018 bytes
wc -m message.txt     # ~1314 ký tự Unicode
cat message.txt | wc -c   # ~962 bytes (chỉ phần visible)
```

> **Quan sát quan trọng:**  
> File nặng **2018 bytes**, nhưng nội dung nhìn thấy chỉ ~962 bytes.  
> Tỉ lệ: **2.10x** lớn hơn mức bình thường. Rõ ràng có dữ liệu ẩn.

Chính đề bài cũng đã hint điều này:
```
"The file size, however, does not match the visible character count."
```

---

## Bước 2: Xác định loại dữ liệu ẩn — Phân tích hex dump

Khi file quá lớn so với nội dung nhìn thấy mà lại là UTF-8 text, nghi vấn ngay đến **các ký tự Unicode đặc biệt**.

Phân tích hex của file:
```
0000  57 65 6c 63 6f 6d 65 20  e2 80 8b  e2 80 8c  e2 80
      W  e  l  c  o  m  e  [SPACE]  [U+200B]  [U+200C]  [...]
```

Ta thấy sau mỗi dấu **SPACE** (`0x20`), có các byte `e2 80 8b` và `e2 80 8c` xuất hiện.

Tra bảng UTF-8 encoding:
| Ký tự  | Unicode  | UTF-8 bytes  | Tên                      |
|--------|----------|--------------|--------------------------|
| (ẩn)   | U+200B   | `e2 80 8b`   | Zero Width Space (ZWS)   |
| (ẩn)   | U+200C   | `e2 80 8c`   | Zero Width Non-Joiner    |

Hai loại ký tự này hoàn toàn vô hình khi render, nhưng chiếm **3 bytes mỗi ký tự** trong UTF-8 → giải thích sự chênh lệch kích thước!

---

## Bước 3: Hiểu encoding scheme — Ánh xạ bit

Khi có **2 loại ký tự** phân bố đều trong file, logic encoding rõ ràng là **binary**:
- `U+200B` (Zero Width Space) → **bit `0`**
- `U+200C` (Zero Width Non-Joiner) → **bit `1`**

Mỗi 8 bit (MSB trước) → 1 ký tự ASCII.

---

## Bước 4: Trích xuất và giải mã

```python
import base64

ZWS  = '\u200b'   # bit 0
ZWNJ = '\u200c'   # bit 1

with open('message.txt', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Lọc chỉ lấy ký tự zero-width
zwc_seq = [c for c in content if c in (ZWS, ZWNJ)]
print(f"Số ZWC tìm thấy: {len(zwc_seq)}")  # → 352

# 2. Chuyển thành chuỗi bit
bits = ''.join('1' if c == ZWNJ else '0' for c in zwc_seq)

# 3. Giải mã bit → ASCII (8 bit mỗi ký tự)
chars = []
for i in range(0, len(bits) - 7, 8):
    val = int(bits[i:i+8], 2)
    chars.append(chr(val))

extracted = ''.join(chars)
print(f"Extracted: {extracted}")
# → RFdZX1lLe3ozcjBfdzFkdGhfNHIzXzN2M3J5d2gzcjN9

# 4. Base64 decode
flag = base64.b64decode(extracted).decode()
print(f"Flag: {flag}")
# → DWY_YK{z3r0_w1dth_4r3_3v3rywh3r3}
```

---

## Bước 5: Tại sao có thêm lớp Base64?

Base64 là lớp thứ hai (layer 2) của bài:

```
[Flag gốc]
  ↓  base64 encode
[RFdZX1lLe3ozcjBfdzFkdGhfNHIzXzN2M3J5d2gzcjN9]
  ↓  encode mỗi ký tự → 8 bit ZWC
[ZWS ZWNJ ZWS ZWS ZWS ZWS ZWS ZWS ...]
  ↓  nhúng vào cover text sau mỗi dấu SPACE
[message.txt (trông bình thường)]
```

Lý do dùng Base64 trước khi encode ZWC:
1. Flag chứa `{` `}` `_` — có giá trị ASCII nhất định; việc encode thẳng vẫn được, nhưng Base64 tạo ra **lớp mã hóa thứ hai** khiến bài khó hơn.
2. Người chơi phải nhận ra `extracted` là Base64 (kết thúc bằng `=` hoặc có charset đặc trưng).

---

## Tóm tắt chuỗi giải

```
message.txt
    │
    ├─ [Bước 1] Phát hiện: file size 2018B >> nội dung visible 962B
    │
    ├─ [Bước 2] Hex dump → thấy byte e2 80 8b / e2 80 8c → U+200B / U+200C
    │
    ├─ [Bước 3] Nhận diện: 2 loại ZWC → encoding nhị phân
    │
    ├─ [Bước 4] Trích xuất 352 ZWC → 352 bit → 44 ASCII chars
    │
    ├─ [Bước 5] Nhận ra chuỗi Base64 → decode
    │
    └─ [Flag] DWY_YK{z3r0_w1dth_4r3_3v3rywh3r3}
```

---
---

# Detailed Writeup (English)

## Technique Overview

This challenge uses **Zero-Width Character (ZWC) Steganography** — a method of hiding data by embedding **zero-width Unicode characters** (invisible to the human eye) inside normal-looking text.

Zero-width characters are **invisible in all text editors**, undetected by `strings` or `grep` for visible content, have no effect on rendering, yet **physically exist in the file** and **occupy real bytes on disk**.

---

## Step 1: Spot the Anomaly — File Size Analysis

The first rule of Misc/Forensics: **don't trust your eyes** — check technical metadata.

```bash
wc -c message.txt     # 2018 bytes on disk
cat message.txt | wc -c   # only ~962 bytes of visible content
```

> **Key observation:**  
> The file is **2018 bytes**, but visible content is only ~962 bytes.  
> That's a **2.10x** size inflation — clear evidence of hidden data.

The challenge description even hints at this:
```
"The file size, however, does not match the visible character count."
```

---

## Step 2: Identify Hidden Data Type — Hex Analysis

When a UTF-8 text file is much larger than its visible content, the natural suspect is **special Unicode characters**.

Examining the raw bytes:
```
0000  57 65 6c 63 6f 6d 65 20  e2 80 8b  e2 80 8c  e2 80
      W  e  l  c  o  m  e  [SPACE]  [U+200B]  [U+200C]  [...]
```

After every **SPACE** (`0x20`), we see bytes `e2 80 8b` and `e2 80 8c` appearing.

Looking up the UTF-8 encoding table:
| Character | Unicode  | UTF-8 Bytes  | Name                     |
|-----------|----------|--------------|--------------------------|
| (hidden)  | U+200B   | `e2 80 8b`   | Zero Width Space (ZWS)   |
| (hidden)  | U+200C   | `e2 80 8c`   | Zero Width Non-Joiner    |

Both are completely invisible when rendered, but consume **3 bytes each** in UTF-8 → explains the size discrepancy!

---

## Step 3: Understand the Encoding — Bit Mapping

With exactly **2 types of characters** distributed throughout the file, the encoding logic is clearly **binary**:
- `U+200B` (Zero Width Space) → **bit `0`**
- `U+200C` (Zero Width Non-Joiner) → **bit `1`**

Every 8 bits (MSB first) → 1 ASCII character.

---

## Step 4: Extract and Decode

```python
import base64

ZWS  = '\u200b'   # bit 0
ZWNJ = '\u200c'   # bit 1

with open('message.txt', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Filter zero-width characters only
zwc_seq = [c for c in content if c in (ZWS, ZWNJ)]
print(f"ZWC chars found: {len(zwc_seq)}")  # → 352

# 2. Convert to bitstream
bits = ''.join('1' if c == ZWNJ else '0' for c in zwc_seq)

# 3. Decode bits → ASCII (8 bits per character)
chars = []
for i in range(0, len(bits) - 7, 8):
    val = int(bits[i:i+8], 2)
    chars.append(chr(val))

extracted = ''.join(chars)
print(f"Extracted: {extracted}")
# → RFdZX1lLe3ozcjBfdzFkdGhfNHIzXzN2M3J5d2gzcjN9

# 4. Base64 decode → flag
flag = base64.b64decode(extracted).decode()
print(f"Flag: {flag}")
# → DWY_YK{z3r0_w1dth_4r3_3v3rywh3r3}
```

---

## Step 5: Why Is There a Base64 Layer?

Base64 is the **second layer** of this challenge:

```
[Original Flag]
  ↓  base64 encode
[RFdZX1lLe3ozcjBfdzFkdGhfNHIzXzN2M3J5d2gzcjN9]
  ↓  encode each character → 8-bit ZWC sequence
[ZWS ZWNJ ZWS ZWS ZWS ZWS ZWS ZWS ...]
  ↓  embed into cover text after every SPACE
[message.txt — looks completely innocent]
```

Why use Base64 as an intermediate layer:
1. The decoded string ends in recognizable Base64 charset (A–Z, a–z, 0–9, +, /, =) — players must **recognize** it's Base64 and not try to interpret the extracted string directly as flag.
2. It adds a **second logical layer** that requires two separate insights to solve.
3. A player who only discovers the ZWC trick still won't have the flag until they also decode Base64 — making this Medium rather than Easy.

---

## Solution Chain Summary

```
message.txt
    │
    ├─ [Step 1] Detect: file 2018B >> visible content 962B  →  something hidden
    │
    ├─ [Step 2] Hex dump → bytes e2 80 8b / e2 80 8c after each SPACE
    │              → Unicode U+200B (ZWS) and U+200C (ZWNJ)
    │
    ├─ [Step 3] Two ZWC types → binary encoding: ZWS=0, ZWNJ=1
    │
    ├─ [Step 4] Extract 352 ZWC → 352-bit stream → 44 ASCII chars
    │
    ├─ [Step 5] Recognize Base64 string → decode
    │
    └─ [FLAG] DWY_YK{z3r0_w1dth_4r3_3v3rywh3r3}
```

---

## Tools & Commands Reference

```bash
# Check file size
wc -c message.txt
ls -la message.txt

# Detect non-ASCII bytes
file message.txt
xxd message.txt | head -20

# Python one-liner to confirm ZWC presence
python3 -c "
data=open('message.txt',encoding='utf-8').read()
print(sum(1 for c in data if ord(c) in (0x200b, 0x200c)))
"

# Run the full solve script
python3 solve.py message.txt
```

---

## Learning Notes / Ghi chú học tập

- **ZWC Steganography** được dùng trong thực tế để watermark văn bản, xác định nguồn leak.
- Hai ký tự phổ biến nhất: `U+200B` và `U+200C`, nhưng còn có `U+200D` (ZWJ), `U+FEFF` (BOM), `U+2060` (Word Joiner).
- Nhiều messaging platform (Telegram, Discord) filter ZWC trước khi hiển thị → cần phân tích file gốc.
- Công cụ hữu ích: `zwsp-detector`, browser extension "Unicode Inspector", Python `unicodedata` module.

---

*Challenge designed for educational purposes — DWY_YK CTF Team*
