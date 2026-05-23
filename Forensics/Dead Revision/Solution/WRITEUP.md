# Dead Revision — CTF Writeup
## Office Document Forensics | Medium+

---

# 🇻🇳 WRITEUP — LỜI GIẢI CHI TIẾT (TIẾNG VIỆT)

## Tổng quan giải pháp

Bài này yêu cầu người chơi hiểu cấu trúc bên trong của định dạng `.docx` (Office Open XML), biết cách điều tra các thành phần ẩn, và thực hiện một chuỗi giải mã đơn giản. Có **5 bước chính**:

```
[1] Nhận ra .docx là ZIP container
    ↓
[2] Tìm breadcrumb trong word/comments.xml
    ↓
[3] Giải mã XOR key từ docProps/custom.xml  (Base64 → Hex → Key)
    ↓
[4] Tìm payload mã hóa trong <w:del> của word/document.xml
    ↓
[5] XOR giải mã → Flag
```

---

## Bước 1 — Nhận ra cấu trúc ZIP (OOXML)

### Kiến thức nền tảng

Định dạng `.docx`, `.xlsx`, `.pptx` của Microsoft Office đều là **file ZIP** được đổi tên, chứa các file XML bên trong. Đây là chuẩn **Office Open XML (OOXML)** theo ISO/IEC 29500.

Khi bạn mở file bằng Word, chương trình chỉ *render* phần hiển thị. Nhiều thành phần XML bên trong hoàn toàn **không được hiển thị ra màn hình**.

### Thực hiện

```bash
# Kiểm tra magic bytes của file
file investigation_report.docx
# → investigation_report.docx: Zip archive data...

# Xem nội dung ZIP mà không giải nén
unzip -l investigation_report.docx

# Giải nén để kiểm tra toàn bộ cấu trúc
unzip investigation_report.docx -d extracted_doc/
tree extracted_doc/
```

**Kết quả:**
```
extracted_doc/
├── [Content_Types].xml        ← Khai báo kiểu nội dung
├── _rels/
│   └── .rels                  ← Quan hệ các file
├── docProps/
│   ├── app.xml                ← Metadata ứng dụng
│   ├── core.xml               ← Metadata tài liệu (tác giả, ngày...)
│   └── custom.xml  ⚠️         ← Thuộc tính tùy chỉnh (ĐÁ QUAN TRỌNG)
└── word/
    ├── _rels/
    │   └── document.xml.rels
    ├── comments.xml ⚠️         ← Bình luận (ĐÁ QUAN TRỌNG)
    ├── document.xml ⚠️         ← Nội dung tài liệu (ĐÁ QUAN TRỌNG)
    ├── settings.xml
    └── styles.xml
```

**Nhận xét:** Hai file đáng ngờ ngay lập tức: `word/comments.xml` và `docProps/custom.xml`.

---

## Bước 2 — Đọc word/comments.xml (Tìm breadcrumb)

### Kiến thức nền tảng

Trong OOXML, file `word/comments.xml` lưu trữ tất cả các **chú thích (comments)** được chèn vào tài liệu. Khi "Track Changes" tắt và comments bị ẩn, người dùng thông thường sẽ không thấy chúng trong giao diện Word.

Điều đặc biệt: comments lưu cả **tên tác giả** và **ngày giờ** — thông tin có thể tiết lộ nhiều thứ trong forensics.

### Thực hiện

```bash
cat extracted_doc/word/comments.xml
# hoặc dùng xmllint để format đẹp hơn:
xmllint --format extracted_doc/word/comments.xml
```

**Nội dung file:**
```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:comments ...>
  <w:comment w:id="0"
             w:author="Analyst_7"
             w:date="2024-03-15T02:47:00Z"
             w:initials="A7">
    <w:p>
      <w:r>
        <w:t>Review complete. Artifact embedded successfully.
             Decryption key stored in document properties
             under the verification checksum field. Author: A7.</w:t>
      </w:r>
    </w:p>
  </w:comment>
</w:comments>
```

### Phân tích

| Điểm đáng chú ý | Ý nghĩa |
|---|---|
| `w:author="Analyst_7"` | Tác giả bí ẩn — không phải tác giả chính (J. Morrison) |
| `w:date="2024-03-15T02:47:00Z"` | 2:47 SA — thời điểm bất thường |
| `"Artifact embedded successfully"` | Xác nhận payload đã được nhúng |
| `"key stored in document properties under the verification checksum field"` | **Breadcrumb quan trọng** → trỏ đến `docProps/custom.xml`, trường `CheckSum` |

---

## Bước 3 — Giải mã XOR key từ docProps/custom.xml

### Kiến thức nền tảng

`docProps/custom.xml` lưu trữ các **thuộc tính tùy chỉnh (custom properties)** mà tác giả tài liệu tự định nghĩa. Chúng hiển thị trong Word tại: *File → Info → Properties → Advanced Properties → Custom*. Đây là nơi ít được kiểm tra nhất trong forensics tài liệu Office.

### Thực hiện

```bash
xmllint --format extracted_doc/docProps/custom.xml
```

**Nội dung:**
```xml
<Properties ...>
  <property ... name="Division">
    <vt:lpwstr>Research &amp; Analysis</vt:lpwstr>
  </property>
  <property ... name="ProjectID">
    <vt:lpwstr>PRJ-2024-0847</vt:lpwstr>
  </property>
  <property ... name="CheckSum">
    <vt:lpwstr>NGQ2ZjZjNjU0ODc1NmU3NA==</vt:lpwstr>  <!-- 👈 ĐÂY -->
  </property>
  <property ... name="Clearance">
    <vt:lpwstr>LEVEL-5</vt:lpwstr>
  </property>
  <property ... name="ReviewCycle">
    <vt:i4>7</vt:i4>
  </property>
</Properties>
```

**Trường `CheckSum` chứa:** `NGQ2ZjZjNjU0ODc1NmU3NA==`

Đây trông như **Base64** (dấu hiệu: toàn chữ/số + `=` ở cuối).

### Giải mã

```python
import base64

checksum_b64 = "NGQ2ZjZjNjU0ODc1NmU3NA=="

# Bước 3a: Base64 decode
hex_str = base64.b64decode(checksum_b64).decode("utf-8")
print(hex_str)
# → "4d6f6c6548756e74"
```

Kết quả `4d6f6c6548756e74` trông như chuỗi **hexadecimal** (chỉ có ký tự 0-9 và a-f, độ dài chẵn).

```python
# Bước 3b: Hex decode → XOR key
xor_key = bytes.fromhex(hex_str)
print(xor_key)
# → b'MoleHunt'
```

**XOR key = `MoleHunt`** — cũng chính là tên dự án điều tra!

**Chuỗi giải mã:**
```
"NGQ2ZjZjNjU0ODc1NmU3NA=="
         ↓ Base64 decode
"4d6f6c6548756e74"
         ↓ Hex decode
b'MoleHunt'
```

---

## Bước 4 — Tìm payload trong thẻ `<w:del>` (Tracked Deletion)

### Kiến thức nền tảng

Đây là phần kỹ thuật nhất của bài. Trong OOXML, tính năng **Track Changes** (Theo dõi thay đổi) cho phép ghi lại mọi chỉnh sửa trong tài liệu. Khi một đoạn văn bị xóa với Track Changes bật, nội dung đó **không thực sự biến mất** — nó được bọc trong thẻ `<w:del>`:

```xml
<!-- Nội dung bị "xóa" nhưng vẫn tồn tại trong XML -->
<w:del w:id="42" w:author="Analyst_7" w:date="...">
  <w:r>
    <w:delText>nội dung bị xóa ở đây</w:delText>
  </w:r>
</w:del>
```

Khi Word hiển thị tài liệu với "Show Markup" tắt → `<w:del>` bị **ẩn hoàn toàn**. Nhưng trong raw XML → **vẫn còn nguyên vẹn**.

### Thực hiện

```bash
# Tìm tất cả thẻ w:del trong document.xml
grep -n "w:del\|w:delText" extracted_doc/word/document.xml
```

**Hoặc dùng Python/xmllint:**
```bash
python3 -c "
import re, open
content = open('extracted_doc/word/document.xml').read()
dels = re.findall(r'<w:delText[^>]*>([^<]+)</w:delText>', content)
print(dels)
"
```

**Kết quả:**
```python
['0938353a113e1503255b183a2f455d07120b5f097b015d10120b5c563b2a0044393058093f411707120b5d167c051e47791d11']
```

Đây là một chuỗi **hex dài** (102 ký tự = 51 bytes) — rõ ràng là payload được mã hóa.

**Phần XML gốc trông như thế này:**
```xml
<w:p w:rsidR="00A31F2C">
  <w:del w:id="42" w:author="Analyst_7" w:date="2024-03-15T02:47:00Z">
    <w:r w:rsidDel="00A31F2C">
      <w:rPr>
        <w:rFonts w:ascii="Courier New" w:hAnsi="Courier New"/>
        <w:sz w:val="18"/>
      </w:rPr>
      <w:delText>0938353a113e1503...1d11</w:delText>
    </w:r>
  </w:del>
</w:p>
```

---

## Bước 5 — XOR Giải mã → Flag

### Kiến thức nền tảng

**XOR cipher** là phương thức mã hóa đơn giản:
- `plaintext XOR key = ciphertext`  
- `ciphertext XOR key = plaintext`

Khi key ngắn hơn plaintext → **key được lặp vòng (cyclic)**:
```
byte[i] = ciphertext[i] XOR key[i % len(key)]
```

### Thực hiện

```python
encrypted_hex = "0938353a113e1503255b183a2f455d07120b5f097b015d10120b5c563b2a0044393058093f411707120b5d167c051e47791d11"
xor_key = b"MoleHunt"

enc_bytes = bytes.fromhex(encrypted_hex)
dec_bytes = bytes([enc_bytes[i] ^ xor_key[i % len(xor_key)]
                   for i in range(len(enc_bytes))])

print(dec_bytes.decode("utf-8"))
```

### Minh họa giải mã (8 byte đầu)

```
Index │ Enc (hex) │ Key (char) │ XOR  │ Dec (char)
──────┼───────────┼────────────┼──────┼───────────
  0   │   0x09    │  M (0x4D)  │ 0x44 │    D
  1   │   0x38    │  o (0x6F)  │ 0x57 │    W
  2   │   0x35    │  l (0x6C)  │ 0x59 │    Y
  3   │   0x3A    │  e (0x65)  │ 0x5F │    _
  4   │   0x11    │  H (0x48)  │ 0x59 │    Y
  5   │   0x3E    │  u (0x75)  │ 0x4B │    K
  6   │   0x15    │  n (0x6E)  │ 0x7B │    {
  7   │   0x03    │  t (0x74)  │ 0x77 │    w
 ...  │    ...    │    ...     │  ... │   ...
```

**Kết quả:**

```
🚩 DWY_YK{wh4t_g03s_d3l3t3d_d03s_n0t_4lw4ys_d1s4pp34r}
```

---

## Tóm tắt chuỗi khai thác đầy đủ

```
investigation_report.docx
│
├─ [UNZIP] ──────────────────────────────────────────────────
│
├─ word/comments.xml
│    └─ Analyst_7 comment: "key stored in... checksum field"
│         │
│         ▼
├─ docProps/custom.xml
│    └─ CheckSum = "NGQ2ZjZjNjU0ODc1NmU3NA=="
│         │
│         ├─ Base64 decode → "4d6f6c6548756e74"
│         └─ Hex decode    → b"MoleHunt"  (XOR KEY)
│
├─ word/document.xml
│    └─ <w:del author="Analyst_7"> ... </w:del>
│         └─ <w:delText>0938353a...1d11</w:delText>  (PAYLOAD)
│
└─ XOR(payload_bytes, "MoleHunt") → FLAG
```

---

---

# 🇺🇸 WRITEUP — DETAILED SOLUTION (ENGLISH)

## Solution Overview

This challenge requires understanding the internal structure of the `.docx` format (Office Open XML), the ability to investigate hidden components, and performing a simple decryption chain. There are **5 main steps**:

```
[1] Identify .docx as a ZIP container
    ↓
[2] Find the breadcrumb in word/comments.xml
    ↓
[3] Decode the XOR key from docProps/custom.xml  (Base64 → Hex → Key)
    ↓
[4] Find the encrypted payload in <w:del> inside word/document.xml
    ↓
[5] XOR decrypt → Flag
```

---

## Step 1 — Identify ZIP / OOXML Structure

### Background

Microsoft Office `.docx`, `.xlsx`, and `.pptx` files are **renamed ZIP archives** containing XML files. This is the **Office Open XML (OOXML)** standard (ISO/IEC 29500).

When Word opens a file, it only *renders* the visible portion. Many XML components inside the package are **never rendered to the screen**.

### Execution

```bash
# Check file magic bytes
file investigation_report.docx
# → investigation_report.docx: Zip archive data...

# List ZIP contents without extracting
unzip -l investigation_report.docx

# Extract and explore
unzip investigation_report.docx -d extracted_doc/
tree extracted_doc/
```

**Result:**
```
extracted_doc/
├── [Content_Types].xml
├── _rels/
│   └── .rels
├── docProps/
│   ├── app.xml
│   ├── core.xml
│   └── custom.xml  ⚠️  (suspicious!)
└── word/
    ├── _rels/
    │   └── document.xml.rels
    ├── comments.xml ⚠️  (suspicious!)
    ├── document.xml ⚠️  (main content)
    ├── settings.xml
    └── styles.xml
```

---

## Step 2 — Read word/comments.xml (Breadcrumb)

### Background

`word/comments.xml` stores all **comments** inserted into the document. With Track Changes off and comments hidden, regular users never see them. Crucially, comments store the **author name** and **timestamp** — both forensically significant.

### Execution

```bash
xmllint --format extracted_doc/word/comments.xml
```

**Content:**
```xml
<w:comment w:id="0"
           w:author="Analyst_7"
           w:date="2024-03-15T02:47:00Z">
  <w:p>
    <w:r>
      <w:t>Review complete. Artifact embedded successfully.
           Decryption key stored in document properties
           under the verification checksum field. Author: A7.</w:t>
    </w:r>
  </w:p>
</w:comment>
```

### Analysis

| Observation | Significance |
|---|---|
| `w:author="Analyst_7"` | Unknown author — not the doc creator (J. Morrison) |
| `w:date="2024-03-15T02:47:00Z"` | 2:47 AM — suspicious timestamp |
| `"Artifact embedded successfully"` | Confirms payload was planted |
| `"key stored in document properties under the verification checksum field"` | **Direct breadcrumb** → `docProps/custom.xml`, field `CheckSum` |

---

## Step 3 — Decode XOR key from docProps/custom.xml

### Background

`docProps/custom.xml` stores **custom properties** defined by the document author. They're accessible in Word at: *File → Info → Properties → Advanced Properties → Custom tab*. This is one of the least-examined areas in Office document forensics.

### Execution

```bash
xmllint --format extracted_doc/docProps/custom.xml
```

**Relevant section:**
```xml
<property ... name="CheckSum">
  <vt:lpwstr>NGQ2ZjZjNjU0ODc1NmU3NA==</vt:lpwstr>
</property>
```

The `CheckSum` value `NGQ2ZjZjNjU0ODc1NmU3NA==` looks like **Base64** (alphanumeric + trailing `=` padding).

### Decoding

```python
import base64

# Step 3a: Base64 decode
hex_str = base64.b64decode("NGQ2ZjZjNjU0ODc1NmU3NA==").decode("utf-8")
print(hex_str)
# → "4d6f6c6548756e74"   ← all hex chars (0-9, a-f) + even length

# Step 3b: Hex decode → raw bytes = XOR key
xor_key = bytes.fromhex(hex_str)
print(xor_key)
# → b'MoleHunt'
```

**Decode chain:**
```
"NGQ2ZjZjNjU0ODc1NmU3NA=="
         ↓ Base64 decode
"4d6f6c6548756e74"
         ↓ Hex decode
b'MoleHunt'   ← XOR key
```

The key `MoleHunt` mirrors the investigation codename — classic insider tradecraft.

---

## Step 4 — Find encrypted payload in `<w:del>` (Tracked Deletion)

### Background

This is the core forensic insight of the challenge. In OOXML, **Track Changes** records every edit. When text is deleted with Track Changes enabled, the content is **not actually removed** — it is wrapped in a `<w:del>` element:

```xml
<w:del w:id="42" w:author="Analyst_7" w:date="...">
  <w:r>
    <w:delText>hidden content lives here</w:delText>
  </w:r>
</w:del>
```

With "Show Markup" off in Word → `<w:del>` is **completely invisible** in the rendered view.  
In raw XML → **it remains intact and readable**.

This is a well-documented forensic vector for recovering "deleted" document content.

### Execution

```bash
# Quick grep
grep -o '<w:delText[^>]*>[^<]*</w:delText>' extracted_doc/word/document.xml
```

**Result:**
```
<w:delText>0938353a113e1503255b183a2f455d07120b5f097b015d10120b5c563b2a0044393058093f411707120b5d167c051e47791d11</w:delText>
```

This 102-character hex string (51 bytes) is clearly the XOR-encrypted flag payload.

The full `<w:del>` block in context:
```xml
<w:p w:rsidR="00A31F2C">
  <w:del w:id="42" w:author="Analyst_7" w:date="2024-03-15T02:47:00Z">
    <w:r w:rsidDel="00A31F2C">
      <w:rPr>
        <w:rFonts w:ascii="Courier New" .../>
      </w:rPr>
      <w:delText>0938353a...1d11</w:delText>
    </w:r>
  </w:del>
</w:p>
```

Note: the same `Analyst_7` author and `02:47` timestamp — consistent with the planted comment.

---

## Step 5 — XOR Decrypt → Flag

### Background

**XOR cipher:**  
`ciphertext[i] XOR key[i % len(key)] = plaintext[i]`

Key `MoleHunt` (8 bytes) cycles over the 51-byte payload.

### Execution

```python
encrypted_hex = "0938353a113e1503255b183a2f455d07120b5f097b015d10120b5c563b2a0044393058093f411707120b5d167c051e47791d11"
xor_key = b"MoleHunt"

enc_bytes = bytes.fromhex(encrypted_hex)
dec_bytes = bytes([enc_bytes[i] ^ xor_key[i % len(xor_key)]
                   for i in range(len(enc_bytes))])

print(dec_bytes.decode("utf-8"))
```

### Byte-level illustration (first 8 bytes)

```
i  │ enc  │ key     │ dec
───┼──────┼─────────┼─────
0  │ 0x09 │ M=0x4D  │ 0x44 = 'D'
1  │ 0x38 │ o=0x6F  │ 0x57 = 'W'
2  │ 0x35 │ l=0x6C  │ 0x59 = 'Y'
3  │ 0x3A │ e=0x65  │ 0x5F = '_'
4  │ 0x11 │ H=0x48  │ 0x59 = 'Y'
5  │ 0x3E │ u=0x75  │ 0x4B = 'K'
6  │ 0x15 │ n=0x6E  │ 0x7B = '{'
7  │ 0x03 │ t=0x74  │ 0x77 = 'w'
...│  ... │  ...    │  ...
```

**Output:**

```
🚩 DWY_YK{wh4t_g03s_d3l3t3d_d03s_n0t_4lw4ys_d1s4pp34r}
```

---

## Full Exploit Chain Summary

```
investigation_report.docx
│
├─[UNZIP / treat as ZIP]──────────────────────────────────────
│
├─► word/comments.xml
│       Analyst_7 (02:47 AM): "key stored in... checksum field"
│                     │
│                     ▼
├─► docProps/custom.xml
│       CheckSum = "NGQ2ZjZjNjU0ODc1NmU3NA=="
│          │
│          ├─ Base64 decode ──► "4d6f6c6548756e74"
│          └─ Hex decode    ──► b"MoleHunt"  (XOR KEY)
│
├─► word/document.xml
│       <w:del author="Analyst_7"> ... </w:del>
│           └── <w:delText>0938353a...1d11</w:delText>
│                              │
│                              ▼
└─► XOR decrypt (key="MoleHunt")
        └── FLAG: DWY_YK{wh4t_g03s_d3l3t3d_d03s_n0t_4lw4ys_d1s4pp34r}
```

---

# 🔑 KEY FORENSIC CONCEPTS TESTED

| Concept | Where applied |
|---|---|
| OOXML = ZIP container | Step 1 |
| Custom document properties | Step 3 (docProps/custom.xml) |
| OOXML comment metadata (author, timestamp) | Step 2 (word/comments.xml) |
| Track Changes / Tracked Deletions (`<w:del>`) | Step 4 (word/document.xml) |
| Base64 encoding recognition | Step 3a |
| Hex encoding recognition | Step 3b |
| XOR cipher decryption (cyclic key) | Step 5 |

---

*Flag: `DWY_YK{wh4t_g03s_d3l3t3d_d03s_n0t_4lw4ys_d1s4pp34r}`*
