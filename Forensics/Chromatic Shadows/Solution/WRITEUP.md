# Chromatic Shadows — Full Writeup
### CTF Forensics · Easy-Medium

---

## 🇻🇳 Writeup (Tiếng Việt)

---

### Đề bài

> *"Một khung hình hỏng được phục hồi từ trạm giám sát ven biển bị bỏ hoang sau nhiều năm nằm trong kho lưu trữ cùng các tín hiệu bị lỗi."*
> *"Dù bức ảnh trông gần như bình thường, các kỹ thuật viên vẫn không thể xác định liệu bên trong nó còn sót lại dữ liệu nào hay không."*
>
> File đính kèm: `capture.png`

---

### Tổng quan tư duy giải

Challenge này có **3 lớp** giấu thông tin, mỗi lớp cần một kỹ thuật forensics/crypto riêng:

```
[Lớp 1] Phân tích cấu trúc PNG chunk  →  tìm chunk tEXt "Artist"
[Lớp 2] Giải mã hint: base64 → ROT13  →  thu được công thức
[Lớp 3] Trích xuất LSB theo công thức  →  XOR decrypt  →  FLAG
```

Điểm khiến challenge này khó:
- **Không dùng sequential LSB** — các tool tự động như `zsteg`, `StegSolve` sẽ thất bại
- **Pixel selection** dựa trên số học (bộ lọc số học toán học), không theo thứ tự thông thường
- **Hint bị double-encode**: base64 bọc ngoài ROT13

---

### Bước 1 — Nhận diện file và kiểm tra cơ bản

Việc đầu tiên với bất kỳ challenge forensics nào: **đừng vội dùng tool stego, hãy kiểm tra metadata trước.**

```bash
file capture.png
# capture.png: PNG image data, 400 x 400, 8-bit/color RGB, non-interlaced

exiftool capture.png
# ...
# Artist : RXJmYmFuYXByOiBULXB1bmFhcnksIHN2eWdyZT0oaypsKSUxNz09MCwgS0JFPTBrNU4=
# ...
```

**Quan sát:** Trường `Artist` chứa một chuỗi trông rất giống base64 (ký tự chữ-số, padding `=` ở cuối). Đây là đầu mối đầu tiên.

Ngoài ra, có thể dùng Python để kiểm tra các chunk của PNG:

```python
import struct, zlib

with open('capture.png', 'rb') as f:
    raw = f.read()

SIG = b'\x89PNG\r\n\x1a\n'
assert raw[:8] == SIG

offset = 8
while offset < len(raw):
    length = struct.unpack('>I', raw[offset:offset+4])[0]
    ctype  = raw[offset+4:offset+8].decode()
    print(f"Chunk: {ctype}  ({length} bytes)")
    offset += 12 + length
    if ctype == 'IEND':
        break
```

Output:
```
Chunk: IHDR  (13 bytes)
Chunk: tEXt  (75 bytes)   ← không phải chunk chuẩn, đáng ngờ!
Chunk: IDAT  (65536 bytes)
Chunk: IDAT  (65536 bytes)
...
Chunk: IEND  (0 bytes)
```

Chunk `tEXt` nằm ngay sau `IHDR` — đây là vị trí được chèn thủ công, không phải vị trí mặc định của các trình tạo PNG.

---

### Bước 2 — Giải mã hint ẩn trong chunk tEXt

Đọc nội dung chunk `tEXt`:

```python
import base64

# Chunk tEXt có cấu trúc: keyword \x00 value
raw_text = b"Artist\x00RXJmYmFuYXByOiBULXB1bmFhcnksIHN2eWdyZT0oaypsKSUxNz09MCwgS0JFPTBrNU4="

null_idx = raw_text.index(b'\x00')
keyword  = raw_text[:null_idx].decode()
value    = raw_text[null_idx+1:].decode()

print(f"Keyword : {keyword}")   # Artist
print(f"Value   : {value}")

# Giải mã base64
step1 = base64.b64decode(value).decode()
print(f"After b64: {step1}")    # Trông lạ — thử ROT13
```

Kết quả sau base64:
```
Erfbanapr: T-punaary, svygre=(k*l)%17==0, KBE=0k5N
```

Nhận ra pattern ROT13: `Erf` → `Res`, `T-` → `G-`. Áp dụng ROT13:

```python
import codecs
hint = codecs.decode(step1, 'rot_13')
print(hint)
# Resonance: G-channel, filter=(x*y)%17==0, XOR=0x5A
```

**Hint đã giải mã:**
- **Kênh màu:** Green (G), index = 1 trong RGB
- **Bộ lọc pixel:** `(x * y) % 17 == 0` (với x, y ≥ 1)
- **Khóa XOR:** `0x5A`

---

### Bước 3 — Hiểu bộ lọc pixel `(x*y) % 17 == 0`

Đây là bước tư duy quan trọng nhất.

Vì 17 là **số nguyên tố**, `17 | (x*y)` ⟺ `17|x` hoặc `17|y`.

```python
# Các giá trị x chia hết cho 17 trong [1, 399]: 17, 34, 51, ..., 391 → 23 giá trị
# Tương tự với y
# Tổng số vị trí: 23*399 + 23*399 - 23*23 = 17,825 vị trí
```

Với flag dài 49 byte → cần 49×8 = **392 bit** → đủ chỗ chứa với biên độ lớn.

Thứ tự duyệt: row-major (y tăng trước, rồi x), bỏ qua các pixel có x=0 hoặc y=0.

---

### Bước 4 — Trích xuất và giải mã

```python
import numpy as np
from PIL import Image

img    = Image.open('capture.png').convert('RGB')
pixels = np.array(img)
H, W   = pixels.shape[:2]   # 400, 400

# Xây dựng danh sách vị trí theo bộ lọc
positions = [
    (x, y)
    for y in range(1, H)
    for x in range(1, W)
    if (x * y) % 17 == 0
]
print(f"Số vị trí: {len(positions)}")   # 17,825

# Trích xuất LSB từ kênh Green tại các vị trí đó
bits = [int(pixels[y, x, 1]) & 1 for x, y in positions]

# Gom thành byte
raw_bytes = []
for i in range(0, len(bits) - 7, 8):
    byte = 0
    for j in range(8):
        byte = (byte << 1) | bits[i + j]
    raw_bytes.append(byte)

# XOR decrypt với key 0x5A
XOR_KEY   = 0x5A
decrypted = bytes([b ^ XOR_KEY for b in raw_bytes])

# Tìm flag
idx = decrypted.find(b'DWY_YK{')
end = decrypted.find(b'}', idx)
print(decrypted[idx:end+1].decode())
```

Output:
```
DWY_YK{ch3ck_b3y0nd_th3_sp3ctrum_4nd_s33_th3_tr4c3s}
```

---

### Tóm tắt flow giải

```
capture.png
    │
    ├─[exiftool / parse chunks]──► tEXt chunk "Artist" → base64 string
    │                                       │
    │                               base64 decode → ROT13 string
    │                                       │
    │                               rot13 decode → HINT
    │                                       │
    │                          channel=G, modulus=17, key=0x5A
    │
    ├─[PIL + numpy]─────────────► load pixel data (400×400 RGB)
    │
    ├─[filter]──────────────────► positions where (x*y) % 17 == 0 (x,y ≥ 1)
    │
    ├─[LSB extract]─────────────► bits[i] = pixels[y,x,GREEN] & 1
    │
    ├─[bits → bytes]────────────► big-endian packing, 8 bits per byte
    │
    └─[XOR 0x5A]────────────────► DWY_YK{ch3ck_b3y0nd_th3_sp3ctrum_4nd_s33_th3_tr4c3s}
```

---

### Các bẫy dành cho người chơi

| Bẫy | Tại sao khó? |
|-----|-------------|
| Dùng `zsteg`, `StegSolve` | Chỉ test sequential LSB → miss hoàn toàn |
| Bỏ qua metadata | Hint nằm trong chunk tEXt, không xem EXIF sẽ không tìm ra |
| Quên ROT13 | Sau base64 ra chuỗi có nghĩa nhưng lạ → cần nhận ra ROT13 |
| Dùng sai kênh màu | Challenge dùng Green (1), không phải Red (0) hay Blue (2) |
| Include pixel x=0 hoặc y=0 | 0×y=0, 0%17=0 → sẽ bao gồm tất cả cột/hàng đầu tiên → sai |

---
---

## 🇬🇧 Writeup (English)

---

### Challenge Description

> *"A corrupted frame was recovered from an abandoned coastal monitoring station after years of being archived with damaged transmissions."*
> *"Although the image appears mostly intact, analysts were unable to determine whether any useful data remained inside it.*"
>
> Attachment: `capture.png`

---

### Overview

This challenge has **3 layers**, each requiring a distinct forensics/crypto technique:

```
[Layer 1] Analyse PNG chunk structure  →  find tEXt chunk "Artist"
[Layer 2] Decode hint: base64 → ROT13  →  recover the formula
[Layer 3] Extract LSB by formula  →  XOR decrypt  →  FLAG
```

Why this is hard:
- **Non-sequential LSB** — automated tools like `zsteg` and `StegSolve` will produce no result
- **Pixel selection** is arithmetic-based, not positional
- **Double-encoded hint**: base64 wrapping ROT13

---

### Step 1 — Identify the file and check basics

First rule of forensics: **check metadata before running any stego tool.**

```bash
file capture.png
# capture.png: PNG image data, 400 x 400, 8-bit/color RGB, non-interlaced

exiftool capture.png
# ...
# Artist : RXJmYmFuYXByOiBULXB1bmFhcnksIHN2eWdyZT0oaypsKSUxNz09MCwgS0JFPTBrNU4=
# ...
```

**Observation:** The `Artist` field contains a string that looks unmistakably like base64 (alphanumeric characters, trailing `=` padding). This is our first clue.

We can also inspect PNG chunks manually:

```python
import struct

with open('capture.png', 'rb') as f:
    raw = f.read()

offset = 8   # skip PNG signature
while offset < len(raw):
    length = struct.unpack('>I', raw[offset:offset+4])[0]
    ctype  = raw[offset+4:offset+8].decode()
    print(f"Chunk: {ctype}  ({length} bytes)")
    offset += 12 + length
    if ctype == 'IEND':
        break
```

Output:
```
Chunk: IHDR  (13 bytes)
Chunk: tEXt  (75 bytes)    ← non-standard position, suspicious
Chunk: IDAT  (65536 bytes)
...
Chunk: IEND  (0 bytes)
```

The `tEXt` chunk sits immediately after `IHDR` — a position typical of manual injection, not standard encoders.

---

### Step 2 — Decode the hidden hint in the tEXt chunk

```python
import base64, codecs

# tEXt chunk layout: keyword \x00 value
keyword = "Artist"
value   = "RXJmYmFuYXByOiBULXB1bmFhcnksIHN2eWdyZT0oaypsKSUxNz09MCwgS0JFPTBrNU4="

step1 = base64.b64decode(value).decode()
print(f"After base64: {step1}")
# Erfbanapr: T-punaary, svygre=(k*l)%17==0, KBE=0k5N

# Recognise ROT13 pattern: Erf→Res, T-→G-
hint = codecs.decode(step1, 'rot_13')
print(f"After ROT13 : {hint}")
# Resonance: G-channel, filter=(x*y)%17==0, XOR=0x5A
```

**Decoded hint:**
- **Channel:** Green (index 1 in RGB array)
- **Pixel filter:** `(x * y) % 17 == 0`  (with x, y ≥ 1)
- **XOR key:** `0x5A`

---

### Step 3 — Understanding the pixel filter `(x*y) % 17 == 0`

This is the key insight.

Since 17 is **prime**, `17 | (x·y)` ⟺ `17|x` **or** `17|y`.

```
x divisible by 17 in [1,399] : 17, 34, ..., 391  →  23 values
y can be anything  in [1,399] :                   → 399 values
Positions from x-side : 23 × 399 = 9,177

y divisible by 17 in [1,399] : same 23 values
x anything: 399 values
Positions from y-side : 23 × 399 = 9,177

Overlap (both divisible): 23 × 23 = 529

Total unique positions : 9,177 + 9,177 − 529 = 17,825
```

Flag is 49 bytes → 49 × 8 = **392 bits** needed. 17,825 ≫ 392. ✓

Traversal order is row-major: y increases in the outer loop, x in the inner loop.

---

### Step 4 — Extract and decrypt

```python
import numpy as np
from PIL import Image

img    = Image.open('capture.png').convert('RGB')
pixels = np.array(img)
H, W   = pixels.shape[:2]   # 400, 400

# Build position list using the filter
positions = [
    (x, y)
    for y in range(1, H)
    for x in range(1, W)
    if (x * y) % 17 == 0
]
print(f"Positions: {len(positions)}")   # 17,825

# Extract LSB from Green channel at those positions
bits = [int(pixels[y, x, 1]) & 1 for x, y in positions]

# Pack bits into bytes (big-endian)
raw_bytes = []
for i in range(0, len(bits) - 7, 8):
    byte = 0
    for j in range(8):
        byte = (byte << 1) | bits[i + j]
    raw_bytes.append(byte)

# XOR decrypt
XOR_KEY   = 0x5A
decrypted = bytes([b ^ XOR_KEY for b in raw_bytes])

# Find flag
idx = decrypted.find(b'DWY_YK{')
end = decrypted.find(b'}', idx)
print(decrypted[idx:end+1].decode())
```

Output:
```
DWY_YK{ch3ck_b3y0nd_th3_sp3ctrum_4nd_s33_th3_tr4c3s}
```

---

### Solution flow summary

```
capture.png
    │
    ├─[exiftool / chunk parser]──► tEXt chunk "Artist" → base64 string
    │                                       │
    │                               base64 decode → ROT13'd string
    │                                       │
    │                               rot13 decode → HINT
    │                                       │
    │                          channel=G, modulus=17, key=0x5A
    │
    ├─[PIL + numpy]──────────────► load pixel array (400×400 RGB)
    │
    ├─[filter]───────────────────► positions where (x*y) % 17 == 0 (x,y ≥ 1)
    │
    ├─[LSB extract]──────────────► bits[i] = pixels[y,x,GREEN] & 1
    │
    ├─[bits → bytes]─────────────► big-endian, 8 bits per byte
    │
    └─[XOR 0x5A]─────────────────► DWY_YK{ch3ck_b3y0nd_th3_sp3ctrum_4nd_s33_th3_tr4c3s}
```

---

### Traps for participants

| Trap | Why it fails |
|------|-------------|
| Running `zsteg` or `StegSolve` | They only test sequential LSB → complete miss |
| Skipping metadata inspection | The hint is in a `tEXt` chunk; no metadata → no formula |
| Forgetting ROT13 step | After base64 the string is meaningful-ish but garbled; need to spot ROT13 |
| Using wrong channel (R or B) | The data is in Green only |
| Including x=0 or y=0 pixels | 0×y=0, 0%17=0 → pulls in entire first row/column → garbage output |

---

## Flag

```
DWY_YK{ch3ck_b3y0nd_th3_sp3ctrum_4nd_s33_th3_tr4c3s}
```
