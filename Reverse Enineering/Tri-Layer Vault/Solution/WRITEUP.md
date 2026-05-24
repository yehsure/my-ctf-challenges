# CTF Writeup — "Tri-Layer Vault"
### Category: Reverse Engineering | Difficulty: Medium / Medium+
### Flag: `DWY_YK{s1mpl3_vm_byt3c0d3}`

---

## ━━ TIẾNG VIỆT ━━

---

## 📄 Đề bài (Mô tả challenge)

> Kho tiền nhiều lớp bảo vệ đang thách thức bạn.
> Mỗi byte của flag bị che giấu qua nhiều phép biến đổi khác nhau.
> Mở khoá được không?
>
> File: `crack_me` (stripped ELF 64-bit)
> Flag format: `DWY_YK{...}`

---

## 🔍 Bước 1 — Phân tích tĩnh ban đầu (Static Analysis)

### 1.1 Xác định loại file

```bash
$ file crack_me
crack_me: ELF 64-bit LSB pie executable, x86-64, stripped

$ strings crack_me | grep -E "DWY|flag|enter|wrong|correct" -i
3 - L A Y E R  VAULT
Enter flag:
[-] Wrong length. Expected %zu characters.
[-] Bad format. Flag must be DWY_YK{...}
[-] Wrong flag.  Keep reversing!
[+] Correct!  Flag: %s
DWY_YK{
```

**Quan sát:**  
- Binary đã bị strip (không còn tên hàm/biến)  
- Chuỗi `DWY_YK{` tồn tại trong `.rodata`  
- Thông báo lỗi cho biết flag phải có độ dài cố định

### 1.2 Mở trong Ghidra / IDA Pro

Sau khi load binary vào Ghidra, ta tìm hàm `main` bằng cách nhảy đến
`entry` → tìm lời gọi `__libc_start_main` → đối số đầu tiên chính là `main`.

**Giả mã (pseudo-code) của `main` sau khi Ghidra decompile:**

```c
// main (địa chỉ ví dụ: 0x1280)
undefined8 main(void) {
    char input[128];
    size_t total_len;
    
    puts("╔...╗\n║  3 - L A Y E R  VAULT  ║\n╚...╝");
    printf("Enter flag: ");
    fgets(input, 128, stdin);
    input[strcspn(input, "\n\r")] = '\0';
    
    total_len = 0x1a;  // = 26 = len("DWY_YK{") + 18 + len("}")
    if (strlen(input) != total_len) {
        printf("[-] Wrong length...\n");
        return 1;
    }
    if (memcmp(input, "DWY_YK{", 7) || input[25] != '}') {
        printf("[-] Bad format...\n");
        return 1;
    }
    if (vault_check(input + 7)) {
        printf("[+] Correct! Flag: %s\n", input);
    } else {
        printf("[-] Wrong flag...\n");
    }
    return 0;
}
```

**Kết luận:** Flag có 26 ký tự, phần bên trong (`inner`) có 18 ký tự.

---

## 🔍 Bước 2 — Phân tích hàm `vault_check`

Đây là hàm quan trọng nhất. Ghidra decompile ra khoảng như sau:

```c
// vault_check (địa chỉ ví dụ: 0x11e0)
undefined4 vault_check(byte *inner) {
    byte buf[18];
    int i;
    
    // LAYER 1 — Permutation
    for (i = 0; i < 18; i++) {
        buf[PERM[i]] = inner[i];
    }
    
    // LAYER 2 — XOR
    for (i = 0; i < 18; i++) {
        buf[i] ^= XORKEY[i];
    }
    
    // LAYER 3 — ROL (Rotate Left)
    for (i = 0; i < 18; i++) {
        n = (i % 5) + 1;
        buf[i] = (buf[i] << n) | (buf[i] >> (8 - n));
    }
    
    return (memcmp(buf, TARGET, 18) == 0);
}
```

### 2.1 Tìm các mảng dữ liệu trong `.rodata`

Khi nhìn vào địa chỉ của `PERM`, `XORKEY`, `TARGET` trong Ghidra:

```
PERM (18 bytes):
  05 0b 03 0f 07 11 01 0d 09 00 10 04 0c 08 02 0a 0e 06
  = [5, 11, 3, 15, 7, 17, 1, 13, 9, 0, 16, 4, 12, 8, 2, 10, 14, 6]

TARGET (18 bytes):
  d0 13 75 b0 59 54 7c d3 8b 15 a4 02 61 a5 4e f7 9e 8a
  = [208, 19, 117, 176, 89, 84, 124, 211, 139, 21, 164, 2, 97, 165, 78, 247, 158, 138]
```

### 2.2 Tìm XORKEY — phân tích vòng lặp LFSR

`XORKEY` không được lưu trực tiếp dưới dạng mảng — nó được tạo ra
tại runtime bởi một **Galois LFSR 16-bit**. Trong assembly ta thấy:

```asm
; Khởi tạo seed
mov  eax, 0x1337       ; seed = 0x1337

; Vòng lặp sinh key
.loop:
  mov  bl, al          ; key[i] = state & 0xFF
  test al, 1           ; lsb = state & 1
  shr  eax, 1          ; state >>= 1
  jz   .no_xor
  xor  ax, 0xB400      ; if (lsb) state ^= 0xB400
.no_xor:
  ; ... lưu bl vào XORKEY[i]
```

**Đây là LFSR Galois 16-bit với:**
- Seed: `0x1337`
- Polynomial tap: `0xB400`

Sinh ra: `[55, 155, 205, 102, 179, 89, 44, 22, 139, 197, 98, 177, 88, 44, 22, 139, 197, 98]`

---

## 🔍 Bước 3 — Đảo ngược 3 lớp biến đổi

```
INPUT (inner)  ──[Layer 1: PERM]──►  tmp
               ──[Layer 2: XOR]───►  tmp
               ──[Layer 3: ROL]───►  TARGET
```

Để tìm `inner`, ta đi ngược từ `TARGET`:

### Đảo Layer 3: ROL → ROR

ROL (Rotate Left) bị đảo bằng ROR (Rotate Right) với cùng số bit:

```
step3_inv[i] = ROR8(TARGET[i], (i%5)+1)
```

### Đảo Layer 2: XOR → XOR

XOR tự đảo ngược:  `A ^ K ^ K == A`

```
step2_inv[i] = step3_inv[i] ^ XORKEY[i]
```

### Đảo Layer 1: Ngược permutation

Forward: `out[PERM[i]] = inp[i]`  
Suy ra:  `inp[i] = out[PERM[i]]`

```
inner[i] = step2_inv[PERM[i]]
```

---

## 🔍 Bước 4 — Script giải

```python
#!/usr/bin/env python3

PERM   = [5, 11, 3, 15, 7, 17, 1, 13, 9, 0, 16, 4, 12, 8, 2, 10, 14, 6]
TARGET = bytes([208, 19, 117, 176, 89, 84, 124, 211, 139, 21,
                164, 2, 97, 165, 78, 247, 158, 138])

# Sinh XORKEY từ Galois LFSR
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

def ror8(v, n):
    n &= 7
    return ((v >> n) | (v << (8 - n))) & 0xFF

N = len(TARGET)
step3_inv = bytes(ror8(TARGET[i], (i % 5) + 1) for i in range(N))
step2_inv = bytes(step3_inv[i] ^ XORKEY[i] for i in range(N))
inner     = bytes(step2_inv[PERM[i]] for i in range(N))

print(f"Flag: DWY_YK{{{inner.decode()}}}")
```

**Output:**

```
Flag: DWY_YK{s1mpl3_vm_byt3c0d3}
```

---

## 💡 Tóm tắt kỹ thuật

| Layer | Biến đổi | Đảo ngược |
|-------|----------|-----------|
| 1 | Hoán vị byte theo bảng `PERM` | Lập bảng nghịch hoán vị |
| 2 | XOR với keystream LFSR Galois | XOR lại với cùng keystream |
| 3 | Quay trái (ROL) từng byte | Quay phải (ROR) cùng số bit |

**Điểm khó của challenge:**
- Layer 1 và 3 thường bị nhầm hướng đảo
- XORKEY không lưu trực tiếp — phải hiểu LFSR để tái tạo
- Cần phân tích đủ cả 3 layer mới giải được

---
---

## ━━ ENGLISH ━━

---

## 📄 Challenge Description

> A multi-layered vault is challenging you.
> Each byte of the flag is hidden through various transformations.
> Can you unlock it?
>
> File: `crack_me` (stripped ELF 64-bit)
> Flag format: `DWY_YK{...}`

---

## 🔍 Step 1 — Initial Static Analysis

### 1.1 Identify the file type

```bash
$ file crack_me
crack_me: ELF 64-bit LSB pie executable, x86-64, stripped

$ strings crack_me | grep -Ei "DWY|flag|enter|wrong|correct"
3 - L A Y E R  VAULT
Enter flag:
[-] Wrong length. Expected %zu characters.
[-] Bad format. Flag must be DWY_YK{...}
[-] Wrong flag.  Keep reversing!
[+] Correct!  Flag: %s
DWY_YK{
```

**Observations:**
- Binary is stripped (no symbol names)
- The prefix `DWY_YK{` exists in `.rodata`
- Error messages confirm the flag has a fixed length

### 1.2 Load into Ghidra / IDA Pro

Navigate to `entry` → locate `__libc_start_main` call → first argument is `main`.

**Decompiled pseudo-code of `main`:**

```c
undefined8 main(void) {
    char input[128];
    
    puts("╔...╗\n║  3 - L A Y E R  VAULT  ║\n╚...╝");
    printf("Enter flag: ");
    fgets(input, 128, stdin);
    input[strcspn(input, "\n\r")] = '\0';
    
    // total_len == 26 == 7 + 18 + 1
    if (strlen(input) != 26) { puts("Wrong length"); return 1; }
    if (memcmp(input, "DWY_YK{", 7) || input[25] != '}') {
        puts("Bad format"); return 1;
    }
    if (vault_check(input + 7))
        printf("[+] Correct! Flag: %s\n", input);
    else
        puts("[-] Wrong flag. Keep reversing!");
    return 0;
}
```

**Conclusion:** The flag is 26 characters total. The inner part (18 characters) is passed to `vault_check`.

---

## 🔍 Step 2 — Analyzing `vault_check`

This is the key function. After decompilation:

```c
undefined4 vault_check(byte *inner) {
    byte buf[18];
    int i;
    
    // LAYER 1 — Permutation
    for (i = 0; i < 18; i++)
        buf[PERM[i]] = inner[i];
    
    // LAYER 2 — XOR with keystream
    for (i = 0; i < 18; i++)
        buf[i] ^= XORKEY[i];
    
    // LAYER 3 — Rotate Left
    for (i = 0; i < 18; i++) {
        int n = (i % 5) + 1;
        buf[i] = (buf[i] << n) | (buf[i] >> (8 - n));
    }
    
    return (memcmp(buf, TARGET, 18) == 0);
}
```

### 2.1 Extracting arrays from `.rodata`

Reading the bytes at the addresses referenced by the loops:

```
PERM (18 bytes):
  05 0b 03 0f 07 11 01 0d 09 00 10 04 0c 08 02 0a 0e 06
  = [5, 11, 3, 15, 7, 17, 1, 13, 9, 0, 16, 4, 12, 8, 2, 10, 14, 6]

TARGET (18 bytes):
  d0 13 75 b0 59 54 7c d3 8b 15 a4 02 61 a5 4e f7 9e 8a
  = [208, 19, 117, 176, 89, 84, 124, 211, 139, 21, 164, 2, 97, 165, 78, 247, 158, 138]
```

### 2.2 Reverse-engineering XORKEY — the Galois LFSR

`XORKEY` is **not stored as a plain array** — it is generated at runtime by
a **16-bit Galois LFSR**. In the disassembly you'll spot the pattern:

```asm
mov  eax, 0x1337    ; seed initialisation
; per-byte loop:
mov  bl, al         ; key_byte = state & 0xFF
test al, 1          ; test LSB
shr  eax, 1         ; state >>= 1
jz   .skip
xor  ax, 0xB400     ; if (LSB was 1): state ^= 0xB400
.skip:
```

This is a **Galois 16-bit LFSR** with:
- Seed: `0x1337`
- Feedback polynomial tap: `0xB400`

It generates the key stream:
`[55, 155, 205, 102, 179, 89, 44, 22, 139, 197, 98, 177, 88, 44, 22, 139, 197, 98]`

---

## 🔍 Step 3 — Inverting the 3 Layers

The forward pipeline is:

```
inner ──[PERM]──► ──[XOR]──► ──[ROL]──► TARGET
```

We reverse it step by step starting from TARGET:

### Invert Layer 3: ROL → ROR

Rotate Right undoes Rotate Left with the same bit count:

```
step3_inv[i] = ROR8(TARGET[i], (i%5)+1)
```

### Invert Layer 2: XOR → XOR (self-inverse)

XOR is its own inverse: `A ^ K ^ K == A`

```
step2_inv[i] = step3_inv[i] ^ XORKEY[i]
```

### Invert Layer 1: Reverse permutation

Forward permutation:  `out[PERM[i]] = inp[i]`  
Rearranging:          `inp[i]       = out[PERM[i]]`

```
inner[i] = step2_inv[PERM[i]]
```

---

## 🔍 Step 4 — Solution Script

```python
#!/usr/bin/env python3

PERM   = [5, 11, 3, 15, 7, 17, 1, 13, 9, 0, 16, 4, 12, 8, 2, 10, 14, 6]
TARGET = bytes([208, 19, 117, 176, 89, 84, 124, 211, 139, 21,
                164, 2, 97, 165, 78, 247, 158, 138])

def lfsr_keys(n, seed=0x1337):
    """Galois 16-bit LFSR — poly tap 0xB400."""
    keys, state = [], seed
    for _ in range(n):
        keys.append(state & 0xFF)
        lsb = state & 1
        state >>= 1
        if lsb:
            state ^= 0xB400
    return bytes(keys)

XORKEY = lfsr_keys(len(TARGET))

def ror8(v, n):
    n &= 7
    return ((v >> n) | (v << (8 - n))) & 0xFF

N         = len(TARGET)
step3_inv = bytes(ror8(TARGET[i], (i % 5) + 1) for i in range(N))
step2_inv = bytes(step3_inv[i] ^ XORKEY[i] for i in range(N))
inner     = bytes(step2_inv[PERM[i]] for i in range(N))

print(f"Flag: DWY_YK{{{inner.decode()}}}")
```

**Output:**

```
Flag: DWY_YK{s1mpl3_vm_byt3c0d3}
```

---

## 💡 Technical Summary

| Layer | Forward Transform | Inverse |
|-------|-------------------|---------|
| 1 | Permute bytes using `PERM` table | `inner[i] = tmp[PERM[i]]` |
| 2 | XOR with Galois LFSR keystream | XOR again with same stream |
| 3 | Rotate each byte left (ROL) | Rotate right (ROR) same amount |

**Why this is Medium/Medium+:**
- The binary is stripped — no function names  
- `XORKEY` is computed at runtime via LFSR, not stored directly — you must understand the LFSR to reconstruct it  
- Layer 1 inversion is easy to get wrong (confusing `out[PERM[i]] = inp[i]` vs `out[i] = inp[PERM[i]]`)  
- All three layers must be fully understood before the flag can be recovered  
- There are no easy shortcuts — AI tools require the correct LFSR reconstruction to solve it

---

## 📂 File List

| File | Description |
|------|-------------|
| `crack_me` | Stripped challenge binary (distributed to contestants) |
| `challenge.c` | Source code (author reference only, NOT distributed) |
| `solve.py` | Solution / solver script |
