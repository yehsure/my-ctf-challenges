# CTF Challenge: Multi-Layer XOR
**Difficulty:** Easy | **Category:** Reverse Engineering | **Points:** 100

---

## Đề bài / Problem Statement

**[Tiếng Việt]**

Trong một buổi pentest, nhóm bạn tìm thấy một file binary bí ẩn tên `checker` trên server của đối thủ. File này không có source code đi kèm, không có documentation, và không ai biết nó làm gì.

Khi chạy thử, chương trình chỉ hiện một màn hình đơn giản chờ nhập liệu:

```
================================
    CTF Flag Checker v1.0
================================
Enter flag:
```

Nếu nhập sai, nó trả về `[-] Wrong flag. Keep digging!` rồi thoát ngay lập tức — không có thêm thông tin gì khác.

Nhiệm vụ của bạn: **tìm ra flag đúng đang được ẩn bên trong binary này**.

Không có server để kết nối. Không có network traffic để phân tích. Không có hint nào được in ra màn hình. Chỉ có duy nhất file binary này — và kỹ năng reverse engineering của bạn.

> **Lưu ý:** Flag không nằm dưới dạng plaintext trong binary. Nó đã bị biến đổi qua nhiều bước trước khi được nhúng vào. Nhiệm vụ của bạn là tìm hiểu *có bao nhiêu lớp* đang che giấu nó và tháo gỡ từng lớp một.

---

**[English]**

During a pentest engagement, your team discovers a mysterious binary called `checker` sitting on a target server. No source code, no documentation, no README — nobody knows what it does or who put it there.

When executed, the program displays a simple prompt and waits:

```
================================
    CTF Flag Checker v1.0
================================
Enter flag:
```

A wrong answer immediately returns `[-] Wrong flag. Keep digging!` and exits — no further output, no timing differences, no hints.

Your mission: **recover the correct flag hidden inside this binary**.

No server to connect to. No network traffic to capture. No strings printed to guide you. Just this one binary — and your reverse engineering skills.

> **Note:** The flag is not stored as plaintext inside the binary. It has been transformed through multiple steps before being embedded. Your job is to figure out *how many layers* are concealing it and peel them back one by one.

---

## Challenge Files

| File | Description |
|---|---|
| `checker` | Binary to reverse (Linux ELF x86-64, stripped) |

**Build từ source / Build from source:**
```bash
gcc -O2 -s -o checker checker.c
```

---

## Hints (mở ra nếu bí / reveal if stuck)

<details>
<summary>Hint 1 — Miễn phí / Free (0 points deducted)</summary>

Dùng `strings checker` và chú ý những chuỗi trông bất thường.

Run `strings checker` and pay close attention to anything that looks out of place.
</details>

<details>
<summary>Hint 2 — (-10 points)</summary>

Một trong những chuỗi bạn thấy trông rất giống một encoding phổ biến. Còn hai chuỗi ngắn khác trông như... key?

One of the strings looks like a very common encoding format. Two other short strings look suspiciously like... keys?
</details>

<details>
<summary>Hint 3 — (-20 points)</summary>

Thứ tự xử lý từ binary ra flag: bước 1 là decode, bước 2 và 3 là XOR.

Processing order from binary data to flag: step 1 is a decode operation, steps 2 and 3 are XOR operations.
</details>

---

## Flag Format

```
DWY_YK{...}
```

---

## Writeup

### Bước 1 – Trinh sát ban đầu / Initial Recon

```bash
$ file checker
checker: ELF 64-bit LSB executable, x86-64, stripped

$ strings checker | grep -E "[A-Za-z0-9+/=]{20,}|rev|eng"
U1xIXUVde3gwagsuaGwgJkwxITs4ZV81Y0MhZEM3IjMkeV0hfiQJZmNlNHU5Kw==
rev3rse
eng1neer
Enter flag:
```

Quan sát / Observations:
- Chuỗi base64 dài → payload đã bị encode
- Hai key lộ rõ: `rev3rse` và `eng1neer`

---

### Bước 2 – Phân tích tĩnh / Static Analysis (Ghidra / IDA)

Decompile `main()` cho thấy / Decompile `main()` reveals:

```
payload  →  b64_decode  →  XOR("eng1neer")  →  XOR("rev3rse")  →  strcmp(input)
```

Flow mã hóa gốc / Original encoding flow (build time):
```
flag  →  XOR("rev3rse")  →  XOR("eng1neer")  →  base64  →  embed in binary
```

Để giải / To solve, reverse the flow:
```
payload  →  base64 decode  →  XOR("eng1neer")  →  XOR("rev3rse")  →  flag
```

---

### Bước 3 – Solve Script

```python
import base64

payload = bytes([
     85,  49, 120,  73,  88,  85,  86, 100, 101,  51,
    103, 119,  97, 103, 115, 117,  97,  71, 119, 103,
     74, 107, 119, 120,  73,  84, 115,  52,  90,  86,
     56,  49,  89,  48,  77, 104,  90,  69,  77,  51,
     73, 106,  77, 107, 101,  86,  48, 104, 102, 105,
     81,  74,  90, 109,  78, 108,  78,  72,  85,  53,
     75, 119,  61,  61
])

step1 = base64.b64decode(payload)
key2  = b"eng1neer"
step2 = bytes([step1[i] ^ key2[i % len(key2)] for i in range(len(step1))])
key1  = b"rev3rse"
flag  = bytes([step2[i] ^ key1[i % len(key1)] for i in range(len(step2))])

print(flag.decode())  # DWY_YK{x0r_mul71_l4y3r_15_50_71r3d_bu7_fun!!!}
```

---

### Bước 4 – Kết quả / Result

```
$ python3 solve.py
[+] FLAG: DWY_YK{x0r_mul71_l4y3r_15_50_71r3d_bu7_fun!!!}

$ ./checker
Enter flag: DWY_YK{x0r_mul71_l4y3r_15_50_71r3d_bu7_fun!!!}
[+] Correct! Flag accepted!
[+] Well done, reverse engineer!
```

---

## Flag

```
DWY_YK{x0r_mul71_l4y3r_15_50_71r3d_bu7_fun!!!}
```

---

## Kiến thức rút ra / Key Takeaways

| Kỹ thuật / Technique | Mô tả / Description |
|---|---|
| `strings` | Tìm chuỗi có thể đọc trong binary / Find readable strings in binary |
| XOR Cipher | Đối xứng — cùng thao tác để encode và decode / Symmetric — same op to encode & decode |
| Base64 | Mã hóa binary → text / Binary-to-text encoding |
| Static Analysis | Đọc code mà không cần chạy binary / Read code without executing the binary |

---
