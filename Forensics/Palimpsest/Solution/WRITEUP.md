# Palimpsest — CTF Forensics Writeup
### 🇻🇳 Tiếng Việt  |  🇬🇧 English

---

## 📋 Thông tin Challenge / Challenge Info

| | |
|---|---|
| **Tên / Name** | Palimpsest |
| **Thể loại / Category** | Forensics |
| **Độ khó / Difficulty** | Easy |
| **File** | `redacted_report.pdf` |
| **Flag** | `DWY_YK{r3v1s10n_h1st0ry_n3v3r_l13s}` |

---

## 🇻🇳 Mô tả bài / Challenge Description (VI)

> Một báo cáo mật của bộ phận An ninh vừa được chỉnh sửa và hai đoạn quan trọng đã bị *[REDACTED]*. Tuy nhiên, nguồn tin nội bộ cho biết phiên bản gốc chứa thông tin cực kỳ nhạy cảm.  
> Liệu bạn có phục hồi được nội dung đã bị "xóa" không?

## 🇬🇧 Challenge Description (EN)

> A classified internal security report was recently edited — two key sections are now *[REDACTED]*. An inside source claims the original version contained critical sensitive data.  
> Can you recover what was erased?

---

---

# 🇻🇳 PHÂN TÍCH & LỜI GIẢI (TIẾNG VIỆT)

---

## Kiến thức nền cần biết

### PDF là gì về mặt cấu trúc?

Một file PDF không phải là một blob nhị phân đơn giản. Nó có **cấu trúc rõ ràng** bao gồm:

```
%PDF-1.4                   ← Header (phiên bản)
%<binary>                  ← Dấu hiệu file nhị phân
...
N 0 obj                    ← Object (đối tượng)
  << /Type ... >>          ← Dictionary
  stream                   ← Dữ liệu nhị phân (tuỳ chọn)
  ...
  endstream
endobj
...
xref                       ← Cross-Reference Table
0 N                        ← N object, bắt đầu từ obj 0
nnnnnnnnnn ggggg n/f       ← Offset của từng object
...
trailer                    ← Trailer dictionary
<< /Size N /Root 1 0 R ... >>
startxref
<offset>                   ← Vị trí của bảng xref
%%EOF                      ← Kết thúc file
```

Khi đọc một PDF, trình đọc **bắt đầu từ cuối file**, tìm `startxref`, nhảy đến bảng `xref`, rồi dùng bảng đó để định vị từng object.

---

### PDF Incremental Update là gì?

Đây là **kỹ thuật cốt lõi** của bài này.

Khi bạn mở một PDF, chỉnh sửa (thêm annotation, chữ ký số, sửa nội dung), rồi **Save** — PDF viewer thường **không xóa dữ liệu cũ**. Thay vào đó, nó **nối thêm (append)** vào cuối file:

```
[Dữ liệu gốc — Revision 1]
%%EOF                      ← Kết thúc revision 1

[Object mới / object được cập nhật — Revision 2]
xref                       ← Bảng xref bổ sung (chỉ liệt kê object thay đổi)
trailer
  << ... /Prev <offset xref 1> >>   ← Trỏ về xref của revision 1
startxref
%%EOF                      ← Kết thúc revision 2
```

- Trình đọc PDF hiện đại sẽ **merge hai bảng xref** (ưu tiên xref mới nhất).
- Dữ liệu của revision 1 **vẫn còn nguyên** trong file nhưng không được tham chiếu nữa.
- Đây chính là kỹ thuật **palimpsest** — như những tờ giấy da thời cổ bị cạo đi và viết lại, nhưng vết cũ vẫn còn.

---

## Từng bước giải

### Bước 0: Mở file

Khi mở `redacted_report.pdf` bằng bất kỳ PDF viewer nào, bạn thấy:

```
INTERNAL REPORT - CASE #2024-0731
Classification: CONFIDENTIAL
Author: Security Division
Created: 2024-07-31  |  Last Modified: 2024-08-05
[REDACTED - Pending Security Clearance Review]
[REDACTED - Pending Security Clearance Review]
Document reviewed. Contents cleared for distribution.
```

**Điểm đáng chú ý:**
- `Last Modified: 2024-08-05` → file đã bị chỉnh sửa sau khi tạo
- `exiftool` hoặc `pdfinfo` cũng sẽ xác nhận điều này:

```bash
$ exiftool redacted_report.pdf
...
Create Date    : 2024:07:31 09:00:00+07:00
Modify Date    : 2024:08:05 14:30:00+07:00   ← File đã bị sửa!
```

Câu hỏi đặt ra: **Trước khi bị sửa, nội dung gốc là gì?**

---

### Bước 1: Tìm dấu vết của Incremental Update

Công cụ đầu tiên và đơn giản nhất: `strings` hoặc `grep`.

```bash
$ strings redacted_report.pdf | grep "%%EOF"
%%EOF
%%EOF
```

Có **2 dấu `%%EOF`** → **100% là PDF Incremental Update.**

Hoặc dùng Python:
```python
data = open("redacted_report.pdf", "rb").read()
count = data.count(b"%%EOF")
print(count)   # → 2
```

---

### Bước 2: Trích xuất Revision 1

Revision 1 là toàn bộ dữ liệu từ đầu file đến `%%EOF` **đầu tiên**.

```python
data = open("redacted_report.pdf", "rb").read()
eof1 = data.index(b"%%EOF")
rev1 = data[: eof1 + 5]
open("revision1.pdf", "wb").write(rev1)
```

File `revision1.pdf` bây giờ là PDF phiên bản gốc (trước khi bị chỉnh sửa).

---

### Bước 3: Kiểm tra tất cả Object trong Revision 1

Đây là bước **quan trọng nhất**. Dùng `pdf-parser.py` (công cụ forensics PDF phổ biến) hoặc tự phân tích:

```bash
$ python3 pdf-parser.py --stats revision1.pdf
```

Hoặc tìm thủ công bằng regex:
```python
import re
for m in re.finditer(rb"(\d+) 0 obj", rev1):
    print(f"Obj {m.group(1).decode()} tại offset {m.start()}")
```

Kết quả:
```
Obj  1 tại offset  16   (Catalog)
Obj  2 tại offset  66   (Pages)
Obj  4 tại offset 124   (Content stream)
Obj  3 tại offset 573   (Page)
Obj  5 tại offset 712   (Font)
Obj  6 tại offset 813   (Info/Metadata)
Obj  7 tại offset 1095  (???)
```

Kiểm tra page tree:
- Catalog (obj 1) → Pages (obj 2) → Page (obj 3) → Content (obj 4) + Font (obj 5)
- Info → obj 6

**Object 7 không được tham chiếu bởi bất kỳ node nào trong page tree → Orphan object!**  
PDF viewer sẽ không hiển thị nó → **Đây là nơi chứa dữ liệu ẩn.**

---

### Bước 4: Đọc nội dung Object 7

```python
pos7 = rev1.index(b"7 0 obj")
dict_end = rev1.index(b"\nstream\n", pos7)
print(rev1[pos7:dict_end].decode())
```

Output:
```
7 0 obj
<< /Length 60 /Filter /FlateDecode >>
```

**`/Filter /FlateDecode`** → Stream được nén bằng **zlib** (đây là filter phổ biến nhất trong PDF).

---

### Bước 5: Trích xuất stream thô

```python
stream_start = dict_end + len(b"\nstream\n")
stream_end   = rev1.index(b"\nendstream", stream_start)
raw_stream   = rev1[stream_start:stream_end]
print(f"Stream bytes: {len(raw_stream)}")   # → 60
print(f"Hex preview: {raw_stream[:12].hex()}")
# → 78da1dcac91500200c42c1963484...
#   ^^^^ 78 9C hoặc 78 DA = zlib magic bytes
```

---

### Bước 6: Giải nén FlateDecode (zlib)

```python
import zlib
decompressed = zlib.decompress(raw_stream)
print(decompressed.decode("ascii"))
```

Output:
```
4457595f594b7b723376317331306e5f683173743072795f6e337633725f6c3133737d
```

Đây là một chuỗi hex!

---

### Bước 7: Giải mã Hex → Flag

```python
flag = bytes.fromhex(decompressed.decode("ascii")).decode("utf-8")
print(flag)
```

```
DWY_YK{r3v1s10n_h1st0ry_n3v3r_l13s}
```

---

## Sơ đồ tổng kết

```
redacted_report.pdf
│
├─ [0 .. EOF₁]  ← REVISION 1 (phiên bản gốc)
│   ├─ obj 1  Catalog
│   ├─ obj 2  Pages
│   ├─ obj 3  Page → obj 4
│   ├─ obj 4  ContentStream  "INTERNAL REPORT..." (đầy đủ)
│   ├─ obj 5  Font
│   ├─ obj 6  Info  (CreationDate only)
│   └─ obj 7  ⬅ HIDDEN STREAM (orphan, không render)
│               FlateDecode → zlib_compress(hex(FLAG))
│
└─ [EOF₁ .. EOF₂]  ← REVISION 2 (incremental update)
    ├─ obj 8  ContentStream  "[REDACTED]..."
    ├─ obj 3  Page → obj 8   (ghi đè tham chiếu)
    ├─ obj 6  Info + ModDate  (ghi đè metadata)
    └─ obj 7  Decoy stream   (ghi đè obj 7 gốc trong xref)
               "Document integrity verified..."
```

---

## Các công cụ hữu ích

| Công cụ | Tác dụng |
|---|---|
| `strings` / `grep` | Tìm `%%EOF` |
| `hexdump -C` | Xem raw bytes, xác nhận zlib header `78 9C` / `78 DA` |
| `exiftool` | Xem metadata, phát hiện `ModDate` ≠ `CreateDate` |
| `pdfinfo` | Thống kê cơ bản về PDF |
| `pdf-parser.py` (Didier Stevens) | Phân tích từng object, trích xuất stream |
| `pdfid.py` | Thống kê nhanh các object type |
| Python `zlib` module | Giải nén FlateDecode |

---

---

# 🇬🇧 ANALYSIS & SOLUTION (ENGLISH)

---

## Background Knowledge

### PDF Internal Structure

A PDF file is not a monolithic binary blob. It has a well-defined structure:

```
%PDF-1.4                   ← Header (version)
%<binary bytes>            ← Signals binary file content
...
N 0 obj                    ← Object definition
  << /Type ... >>          ← Object dictionary
  stream                   ← Optional binary payload
  ...
  endstream
endobj
...
xref                       ← Cross-Reference Table
0 N                        ← N objects starting from obj 0
nnnnnnnnnn ggggg n/f       ← Byte offset of each object
...
trailer
<< /Size N /Root 1 0 R ... >>
startxref
<offset>                   ← Position of the xref table
%%EOF                      ← End of file marker
```

When a PDF reader opens a file, it **starts from the END**: finds `startxref`, jumps to the `xref` table, and uses that table to locate every object by its byte offset.

---

### What is a PDF Incremental Update?

This is the **core concept** of this challenge.

When you open a PDF, annotate it, sign it, or edit it, and then **save**, most PDF viewers do **not** truncate and rewrite the file. Instead, they **append** new data to the end:

```
[Original content — Revision 1]
%%EOF                         ← End of revision 1

[New / updated objects — Revision 2]
xref                          ← Incremental xref (only changed objects)
trailer
  << ... /Prev <xref1_offset> >>   ← Points back to revision 1's xref
startxref
%%EOF                         ← End of revision 2
```

- A modern PDF reader **merges both xref tables** (newer entries win).
- The original revision 1 bytes **remain untouched** in the file — just unreachable via the latest xref.
- This is the "palimpsest" effect: like ancient parchment scraped and overwritten, where traces of the original persist.

**Critical forensics implication:** Even if a document appears "clean" when opened, a previous revision may contain data the author intended to erase.

---

## Step-by-Step Solution

### Step 0: Initial Triage

Opening `redacted_report.pdf` in any viewer shows:

```
INTERNAL REPORT - CASE #2024-0731
Classification: CONFIDENTIAL
Author: Security Division
Created: 2024-07-31  |  Last Modified: 2024-08-05
[REDACTED - Pending Security Clearance Review]
[REDACTED - Pending Security Clearance Review]
Document reviewed. Contents cleared for distribution.
```

Key observations:
- `Last Modified: 2024-08-05` — the document was edited after creation
- `exiftool` confirms the timestamps:

```bash
$ exiftool redacted_report.pdf
Create Date  : 2024:07:31 09:00:00+07:00
Modify Date  : 2024:08:05 14:30:00+07:00   ← Modified!
```

This strongly implies content was changed. The forensics question becomes: **what was in the original version?**

---

### Step 1: Detect Incremental Update

The simplest tool: `strings` or a binary search for `%%EOF`.

```bash
$ strings redacted_report.pdf | grep -c "%%EOF"
2
```

**Two `%%EOF` markers** → **confirmed PDF Incremental Update.**

```python
data = open("redacted_report.pdf", "rb").read()
print(data.count(b"%%EOF"))   # → 2
```

The positions:
```
Rev 1 %%EOF at offset 0x05B7  (1463)
Rev 2 %%EOF at offset 0x0A7F  (2687)
```

---

### Step 2: Extract Revision 1

Revision 1 is everything from the start of the file through the first `%%EOF`.

```python
data    = open("redacted_report.pdf", "rb").read()
eof_idx = data.index(b"%%EOF")
rev1    = data[: eof_idx + 5]
open("revision1.pdf", "wb").write(rev1)
```

`revision1.pdf` is now the pristine pre-modification document.

---

### Step 3: Enumerate ALL Objects in Revision 1

This is the **critical step**. Standard PDF viewers only render objects reachable from the page tree. We must look at **every object** in the raw bytes.

```bash
$ python3 pdf-parser.py --stats revision1.pdf
# or manually:
```

```python
import re
for m in re.finditer(rb"(\d+) 0 obj", rev1):
    print(f"Obj {m.group(1).decode():2s}  offset {m.start()}")
```

Result:
```
Obj  1  offset   16   → Catalog
Obj  2  offset   66   → Pages
Obj  4  offset  124   → Content stream
Obj  3  offset  573   → Page
Obj  5  offset  712   → Font
Obj  6  offset  813   → Info/Metadata
Obj  7  offset 1095   → ???
```

Cross-check the page tree:
- Catalog (1) → Pages (2) → Page (3) → Contents: obj 4 + Font: obj 5
- Info: obj 6

**Object 7 is not referenced by any node in the page tree. It is an orphan object.**
No PDF viewer will render it — making it an ideal hiding place.

---

### Step 4: Inspect Object 7

```python
pos7     = rev1.index(b"7 0 obj")
dict_end = rev1.index(b"\nstream\n", pos7)
print(rev1[pos7:dict_end].decode())
```

```
7 0 obj
<< /Length 60 /Filter /FlateDecode >>
```

**`/Filter /FlateDecode`** = the stream is **zlib-compressed**.  
FlateDecode is the most common compression filter in PDF, equivalent to `zlib.compress()`.

---

### Step 5: Extract the Raw Stream Bytes

```python
stream_start = dict_end + len(b"\nstream\n")
stream_end   = rev1.index(b"\nendstream", stream_start)
raw_stream   = rev1[stream_start:stream_end]

print(f"Length : {len(raw_stream)} bytes")
print(f"Hex    : {raw_stream[:12].hex()}")
```

```
Length : 60 bytes
Hex    : 78da1dcac91500200c42c196...
         ^^^^ 0x78 0xDA = zlib deflate magic bytes (confirmed!)
```

Zlib magic bytes reference:
- `78 01` — low compression
- `78 9C` — default compression  
- `78 DA` — best compression ← what we have here

---

### Step 6: Decompress via zlib (FlateDecode)

```python
import zlib
decompressed = zlib.decompress(raw_stream)
print(decompressed.decode("ascii"))
```

```
4457595f594b7b723376317331306e5f683173743072795f6e337633725f6c3133737d
```

This is a **hex-encoded string** (all characters are `[0-9a-f]`, length 70 = 35 pairs).

---

### Step 7: Hex Decode → Flag

```python
flag = bytes.fromhex(decompressed.decode("ascii")).decode("utf-8")
print(flag)
```

```
DWY_YK{r3v1s10n_h1st0ry_n3v3r_l13s}
```

---

## Challenge Architecture Summary

```
redacted_report.pdf (2,693 bytes)
│
├─ REVISION 1  [bytes 0 → 1468]
│   ├─ obj 1  Catalog
│   ├─ obj 2  Pages
│   ├─ obj 3  Page  ──────────────────────→ obj 4
│   ├─ obj 4  Content  "INTERNAL REPORT... (full text)"
│   ├─ obj 5  Font  /Helvetica
│   ├─ obj 6  Info  CreationDate only
│   └─ obj 7  ← HIDDEN STREAM (ORPHAN — never rendered)
│              /Filter /FlateDecode
│              payload = zlib( hex_encode(FLAG) )
│
└─ REVISION 2  [bytes 1468 → 2693]  ← Appended incremental update
    ├─ obj 8  Content  "[REDACTED]..."
    ├─ obj 3* Updates page to point to obj 8
    ├─ obj 6* Updates Info, adds ModDate
    └─ obj 7* Decoy stream  "Document integrity verified..."
              (overwrites obj 7 in the incremental xref,
               but the ORIGINAL obj 7 bytes are still in the file!)
```

The incremental xref in revision 2 carries a `/Prev` pointer back to revision 1's xref, forming a **linked chain**. PDF readers follow this chain forward (newest first); forensic analysts must also follow it **backward**.

---

## Why Standard Tools Miss This

| Approach | Why It Fails |
|---|---|
| Open in PDF viewer | Shows only the latest revision (obj 7 is the decoy) |
| `strings` on the file | Stream data is zlib-compressed — no readable strings |
| `binwalk` / `foremost` | Finds the zlib stream but doesn't interpret it in PDF context |
| `exiftool` | Reveals the ModDate clue but not the hidden object |
| AI (without the file) | Can explain techniques but cannot extract the actual flag |
| Automated PDF scanners | Typically analyze only the most recent xref state |

**The intended path requires:**  
1. Recognising the multiple `%%EOF` pattern  
2. Understanding PDF incremental updates  
3. Manually enumerating objects in the older revision  
4. Knowing that `FlateDecode = zlib`  
5. Recognising hex encoding and decoding it  

---

## Encoding Chain (Data Flow)

```
FLAG (plaintext UTF-8)
  "DWY_YK{r3v1s10n_h1st0ry_n3v3r_l13s}"
          │
          ▼ FLAG.hex()  [hex-encode each byte as 2 ASCII chars]
  "4457595f594b7b...7d"
          │
          ▼ zlib.compress(level=9)  [FlateDecode]
  b'\x78\xda\x1d\xca...'  [60 bytes of binary]
          │
          ▼ Stored as PDF stream in obj 7, Revision 1
```

Decode in reverse:
```
stream bytes → zlib.decompress() → hex string → bytes.fromhex() → FLAG
```

---

## Key Takeaways (Forensics Lessons)

1. **%%EOF count matters.** A PDF with N `%%EOF` markers has N revisions.
2. **Incremental updates never truly delete data.** Old bytes remain until the file is "flattened" (re-saved from scratch).
3. **Orphan objects are suspicious.** Any PDF object not reachable from the Catalog/page tree deserves examination.
4. **FlateDecode ≡ zlib.** This is the default PDF stream compression; always try `zlib.decompress()` when you see it.
5. **Metadata timestamps are clues.** A `ModDate` significantly later than `CreateDate` is a strong forensic indicator.

---

## Tools Reference

```bash
# Check %%EOF count
python3 -c "print(open('f.pdf','rb').read().count(b'%%EOF'))"

# Extract revision 1
python3 -c "
d=open('redacted_report.pdf','rb').read()
open('rev1.pdf','wb').write(d[:d.index(b'%%EOF')+5])
"

# Analyze with Didier Stevens' tools (pip install pdfid pdf-parser)
pdfid.py   redacted_report.pdf
pdf-parser.py --stats  rev1.pdf
pdf-parser.py --object 7 --filter --dump stream.bin  rev1.pdf

# Decompress manually
python3 -c "import zlib; print(zlib.decompress(open('stream.bin','rb').read()))"

# Full automated solve
python3 solve.py redacted_report.pdf
```

---

