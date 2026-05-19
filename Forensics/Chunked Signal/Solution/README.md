# 👻 Ghost Packets — v2

---

## 🇻🇳 MÔ TẢ ĐỀ BÀI (Tiếng Việt)

**Tên bài:** Ghost Packets  
**Thể loại:** Forensics  
**Độ khó:** Medium-Hard
**Tags:** `pcap` `dns-tunneling` `base32` `xor` `zip` `steganography`  
**Flag format:** `DWY_YK{...}`

---

### 📖 Đề bài

SOC nhận được alert về một thiết bị nội bộ `10.10.10.5` đang giao tiếp bất thường với domain không rõ nguồn gốc.

Kỹ sư kịp dump traffic thành file `challenge.pcap` trước khi kết nối bị cắt.

> 📎 **File đính kèm:** `challenge.pcap`  
> 🚩 **Flag format:** `DWY_YK{...}`

---

---

## 🇬🇧 CHALLENGE DESCRIPTION (English)

**Name:** Ghost Packets  
**Category:** Forensics  
**Difficulty:** Medium-Hard
**Tags:** `pcap` `dns-tunneling` `base32` `xor` `zip` `steganography`  
**Flag format:** `DWY_YK{...}`

---

### 📖 Briefing

The SOC received an alert about unusual outbound traffic from `10.10.10.5`.

An analyst captured the session in `challenge.pcap` moments before the connection terminated.

> 📎 **Attachment:** `challenge.pcap`  
> 🚩 **Flag format:** `DWY_YK{...}`

---

---

# 📝 WRITEUP — Ghost Packets v2

## Attack Chain Overview

```
challenge.pcap  (6493 packets, ~1.5 MB)
    │
    ├─ DNS noise:  google, microsoft, discord, spotify   ← red herrings
    │
    ├─ DNS TXT  key.dwyyk.com
    │             └─ "sess=xk:0x5a;ts=..."              ← XOR key = 0x5a
    │
    ├─ HTTP POST  /api/v2/telemetry
    │             └─ User-Agent: ...CTF-Implant/Pass:<password>...
    │                                                    ← ZIP password
    │
    └─ DNS queries  NNNN.BASE32CHUNK.dwyyk.com  ×2584   ← shuffled order!
          │
          ▼
          sort by NNNN → join → base32 decode → XOR 0x5a
          │
          ▼
          AES-encrypted ZIP  (password from User-Agent)
          │
          ▼  extract
          frag_001.dat … frag_010.dat
          │  header ;idx=XX/10;rev=1  ← INDEX IS REVERSED
          │  hex: 16-byte blocks, each reversed + XOR 0xC3
          │
          ▼  deobfuscate + sort correctly
          reconstructed.png  (800×600 C2 dashboard)
          │
          ▼  LSB stego — red channel bit-0
          DWY_YK{y34h_dn5_3xf1l_4nd_7ry_70_r3c0v3r_f1l35_by_x0r_4nd_345y_l5b_w4573_71m3_bu7_fun_r16h7?}
```

---

## Step 1 — Open PCAP & Survey

```bash
# Quick protocol stats
tshark -r challenge.pcap -q -z io,phs

# Count DNS queries per destination
tshark -r challenge.pcap -Y 'dns.flags.response==0' \
  -T fields -e ip.dst -e dns.qry.name 2>/dev/null | sort | uniq -c | sort -rn | head -20
```

Observation: The bulk of DNS traffic goes to `8.8.8.8`.  
Among the domains, `dwyyk.com` stands out — never seen in normal traffic, hundreds of unique subdomains.

---

## Step 2 — Identify DNS Exfiltration Pattern

```bash
tshark -r challenge.pcap -Y 'dns.flags.response==0 && dns.qry.name contains "dwyyk.com"' \
  -T fields -e dns.qry.name 2>/dev/null | sort | head -20
```

Sample output:
```
0001.biivsxsoljnvuok2veypibs2ljnfvncj.dwyyk.com
0734.cx5h7rtfzo2w4hftx5pa5fnlyxzqsyxb.dwyyk.com
1892.htyjukhqn4n2tagy4q27rw3fndgzt3mz.dwyyk.com
```

**Pattern:** `NNNN.ENCODED.dwyyk.com`
- `NNNN` = 4-digit zero-padded **chunk order** (packets arrive shuffled!)
- `ENCODED` = **Base32** data (`[a-z2-7]` → DNS-safe, no `/+=`)

---

## Step 3 — Extract XOR Key from DNS TXT

```bash
tshark -r challenge.pcap -Y 'dns.qry.type==16' \
  -T fields -e dns.qry.name -e dns.resp.name -e dns.txt 2>/dev/null
```

Response for `key.dwyyk.com`:
```
sess=xk:0x5a;ts=1710000004
```

**→ XOR key = `0x5a`**

Note: It's buried in a `sess=` cookie-like string. The `xk:` prefix is the signal.

---

## Step 4 — Extract ZIP Password from HTTP

```bash
# Follow TCP stream in Wireshark: right-click any TCP packet → Follow → TCP Stream
# Or with tshark:
tshark -r challenge.pcap -Y 'tcp contains "CTF-Implant"' \
  -T fields -e http.user_agent 2>/dev/null
```

User-Agent line:
```
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 CTF-Implant/Pass:U$3r-4g3nt_Exf1l! rv:109.0
```

**→ ZIP password = `U$3r-4g3nt_Exf1l!`**  
(keyword `Pass:` before the actual password)

---

## Step 5 — Reassemble Chunks → XOR → ZIP

```python
import re, base64
from scapy.all import rdpcap
from scapy.layers.dns import DNS, DNSQR

pkts   = rdpcap("challenge.pcap")
pat    = re.compile(r"^(\d+)\.([a-z2-7]+)\.dwyyk\.com$")
chunks = {}

for p in pkts:
    if p.haslayer(DNS) and p[DNS].qr == 0 and p[DNS].qd:
        qname = p[DNS].qd.qname.decode(errors="replace").rstrip(".")
        m = pat.match(qname)
        if m:
            chunks[int(m.group(1))] = m.group(2).upper()

# Sort by sequence number
joined = "".join(chunks[k] for k in sorted(chunks))

# Re-pad base32 (padding was stripped for DNS safety)
pad    = (8 - len(joined) % 8) % 8
raw    = base64.b32decode(joined + "=" * pad)

# XOR decrypt
xor_key   = 0x5a
zip_bytes = bytes([b ^ xor_key for b in raw])

assert zip_bytes[:2] == b"PK", "ZIP magic check failed!"
open("recovered.zip", "wb").write(zip_bytes)
```

---

## Step 6 — Extract AES ZIP

```python
import pyzipper

with pyzipper.AESZipFile("recovered.zip") as zf:
    zf.setpassword(b"U$3r-4g3nt_Exf1l!")
    zf.extractall("frags/")
```

Standard `zipfile` module will **fail** here — this is AES-256 encrypted (WinZip AES), not the legacy ZipCrypto. You must use `pyzipper`.

---

## Step 7 — Deobfuscate Fragments & Reconstruct Image

Each `frag_NNN.dat` looks like:
```
;idx=07/10;rev=1
a3f91bc2...  (long hex string)
```

**The trap:** `idx=07/10` does NOT mean "fragment #7".  
It means `real_position = 10 - 7 = 3` (zero-indexed).

Deobfuscation logic (per fragment):
1. Hex-decode → raw bytes
2. Split into 16-byte blocks
3. Each block: **reverse** the bytes
4. Then **XOR every byte with `0xC3`**

How to find `0xC3`: attempt XOR with common values (0x00, 0xFF, 0xAA…) and check if result starts with PNG magic `\x89PNG` after re-assembling position-0 fragment.

```python
import re
from pathlib import Path

FRAG_XOR = 0xC3
SUB_CHUNK = 16

def deobfuscate(hex_str):
    raw = bytes.fromhex(hex_str)
    out = b""
    for i in range(0, len(raw), SUB_CHUNK):
        block = raw[i:i+SUB_CHUNK]
        out  += bytes([b ^ FRAG_XOR for b in block[::-1]])  # reverse then XOR
    return out

frag_data = {}
for f in sorted(Path("frags").iterdir()):
    lines   = f.read_text().splitlines()
    m       = re.search(r";idx=(\d+)/(\d+)", lines[0])
    rev_idx, total = int(m.group(1)), int(m.group(2))
    real    = total - rev_idx          # ← un-reverse the index
    frag_data[real] = deobfuscate("".join(lines[1:]))

image_bytes = b"".join(frag_data[k] for k in sorted(frag_data))
assert image_bytes[:8] == b"\x89PNG\r\n\x1a\n"
open("reconstructed.png","wb").write(image_bytes)
```

---

## Step 8 — LSB Steganography

The recovered image is an 800×600 PNG. Running `zsteg`:

```bash
zsteg reconstructed.png
```

Or manual Python extraction (LSB of red channel):

```python
from PIL import Image

img    = Image.open("reconstructed.png").convert("RGB")
pixels = list(img.getdata())
bits   = [r & 1 for r, g, b in pixels]

chars = []
for i in range(0, len(bits)-7, 8):
    byte = int("".join(str(b) for b in bits[i:i+8]), 2)
    if byte == 0: break
    chars.append(chr(byte))

print("".join(chars))
```

Output:
```
DWY_YK{y34h_dn5_3xf1l_4nd_7ry_70_r3c0v3r_f1l35_by_x0r_4nd_345y_l5b_w4573_71m3_bu7_fun_r16h7?}
```

---

## 🏁 Flag

```
DWY_YK{y34h_dn5_3xf1l_4nd_7ry_70_r3c0v3r_f1l35_by_x0r_4nd_345y_l5b_w4573_71m3_bu7_fun_r16h7?}
```

---


## 🎓 Skills Tested

| Skill | Where |
|-------|-------|
| DNS traffic analysis | Identifying anomalous domains among noise |
| DNS exfiltration detection | Base32 subdomains as covert channel |
| Packet sequencing | Out-of-order chunks with embedded indices |
| XOR cipher reversal | Single-byte key hidden in DNS TXT |
| HTTP artifact correlation | Linking User-Agent to another protocol |
| AES ZIP decryption | `pyzipper` vs `zipfile` distinction |
| Binary obfuscation reversal | Per-block reverse + XOR |
| LSB steganography | Red channel bit-0 extraction |

---

