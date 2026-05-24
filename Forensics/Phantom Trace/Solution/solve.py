#!/usr/bin/env python3
"""
=============================================================
  Phantom Trace - CTF Forensics Challenge - Solution Script
  Challenge: Log Analysis / DNS Exfiltration
  Flag Format: DWY_YK{...}
=============================================================
"""

import re
import base64
from collections import defaultdict
from datetime import datetime


SEPARATOR = "=" * 60


def parse_access_log(filepath="access.log"):
    """
    Step 1 & 2: Identify attacker IP from access.log
    Look for: high-frequency requests, suspicious User-Agents, LFI payloads
    """
    print(f"\n{'[STEP 1 & 2]':=<60}")
    print("Parsing access.log to identify the attacker...\n")

    ip_counts = defaultdict(int)
    suspicious_uas = {}
    lfi_attempts = []
    lfi_success = None

    lfi_patterns = [
        r"\.\./",
        r"php://filter",
        r"/etc/passwd",
        r"/proc/self",
        r"/var/log",
    ]

    try:
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                # Parse Apache combined log format
                match = re.match(
                    r'(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d+) (\d+) "([^"]*)" "([^"]*)"',
                    line,
                )
                if not match:
                    continue

                ip, timestamp, request, status, size, referer, ua = match.groups()
                ip_counts[ip] += 1

                # Flag suspicious User-Agents
                suspicious_ua_keywords = [
                    "sqlmap", "nikto", "zgrab", "scanner", "masscan", "nmap"
                ]
                for keyword in suspicious_ua_keywords:
                    if keyword.lower() in ua.lower():
                        suspicious_uas[ip] = ua
                        break

                # Find LFI attempts and successes
                for pattern in lfi_patterns:
                    if re.search(pattern, request, re.IGNORECASE):
                        entry = {
                            "ip": ip,
                            "timestamp": timestamp,
                            "request": request,
                            "status": int(status),
                            "size": int(size),
                        }
                        lfi_attempts.append(entry)

                        # A 200 response with large body on LFI = success!
                        if int(status) == 200 and int(size) > 1000:
                            lfi_success = entry
                        break

    except FileNotFoundError:
        print(f"  [!] File not found: {filepath}")
        return None

    # Report
    print("  [+] Top IPs by request count:")
    for ip, count in sorted(ip_counts.items(), key=lambda x: -x[1])[:5]:
        marker = " <-- SUSPICIOUS" if ip in suspicious_uas else ""
        print(f"      {ip:20s} : {count:4d} requests{marker}")

    print(f"\n  [+] IPs with suspicious User-Agents:")
    for ip, ua in suspicious_uas.items():
        print(f"      {ip} -> UA: {ua}")

    print(f"\n  [+] LFI attempts found: {len(lfi_attempts)}")
    for attempt in lfi_attempts[:5]:
        print(f"      [{attempt['timestamp']}] {attempt['ip']} -> "
              f"Status={attempt['status']} Size={attempt['size']}")
        print(f"        Request: {attempt['request']}")

    if lfi_success:
        print(f"\n  [!!!] SUCCESSFUL LFI DETECTED:")
        print(f"        IP        : {lfi_success['ip']}")
        print(f"        Timestamp : {lfi_success['timestamp']}")
        print(f"        Request   : {lfi_success['request']}")
        print(f"        Response  : HTTP 200, {lfi_success['size']} bytes")
        print(f"\n  [*] The attacker read /etc/passwd and found valid usernames!")
        attacker_ip = lfi_success["ip"]
    else:
        # Fallback: most suspicious IP
        attacker_ip = list(suspicious_uas.keys())[0] if suspicious_uas else None

    print(f"\n  [RESULT] Attacker IP identified: {attacker_ip}")
    return attacker_ip


def parse_auth_log(filepath="auth.log", attacker_ip=None):
    """
    Step 3: Correlate attacker IP with SSH authentication log
    Find brute-force pattern, then the successful login and target username
    """
    print(f"\n{'[STEP 3]':=<60}")
    print("Parsing auth.log to trace SSH activity...\n")

    brute_force_attempts = defaultdict(lambda: defaultdict(int))
    successful_login = None

    try:
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                # Match failed password
                fail_match = re.search(
                    r"Failed password for (?:invalid user )?(\S+) from (\S+) port",
                    line,
                )
                if fail_match:
                    user, src_ip = fail_match.groups()
                    brute_force_attempts[src_ip][user] += 1

                # Match successful login
                success_match = re.search(
                    r"Accepted password for (\S+) from (\S+) port \d+ ssh2", line
                )
                if success_match:
                    user, src_ip = success_match.groups()
                    # Extract timestamp from log line (syslog format)
                    ts_match = re.match(r"(\w+ \d+ \d+:\d+:\d+)", line)
                    timestamp = ts_match.group(1) if ts_match else "unknown"
                    successful_login = {
                        "user": user,
                        "src_ip": src_ip,
                        "timestamp": timestamp,
                        "line": line,
                    }

    except FileNotFoundError:
        print(f"  [!] File not found: {filepath}")
        return None

    print("  [+] SSH Brute-Force attempts by source IP:")
    for src_ip, users in brute_force_attempts.items():
        total = sum(users.values())
        marker = " <-- ATTACKER" if attacker_ip and src_ip == attacker_ip else ""
        print(f"      {src_ip:20s}: {total} failed attempts across {len(users)} usernames{marker}")
        if attacker_ip and src_ip == attacker_ip:
            print(f"        Targeted usernames: {', '.join(users.keys())}")

    if successful_login:
        print(f"\n  [!!!] SUCCESSFUL SSH LOGIN FOUND:")
        print(f"        Timestamp : {successful_login['timestamp']}")
        print(f"        User      : {successful_login['user']}")
        print(f"        From IP   : {successful_login['src_ip']}")
        print(f"        Log line  : {successful_login['line']}")

        if attacker_ip and successful_login["src_ip"] == attacker_ip:
            print(f"\n  [!!!] Attacker IP matches SSH login source!")
            print(f"  [*]  Username discovered via LFI (/etc/passwd): "
                  f"'{successful_login['user']}'")
    else:
        print("\n  [-] No successful SSH login found.")

    return successful_login


def parse_dns_log(filepath="dns_queries.log", login_time_str=None):
    """
    Step 4 & 5: Find DNS exfiltration chunks in dns_queries.log
    - Look for queries to *.exfil.redteam-c2.xyz after SSH login time
    - Extract sequence numbers and base64 chunks
    - Sort, concatenate, and decode the flag
    """
    print(f"\n{'[STEP 4 & 5]':=<60}")
    print("Parsing dns_queries.log for DNS exfiltration activity...\n")

    exfil_domain = "exfil.redteam-c2.xyz"
    exfil_chunks = {}
    all_queries = []

    try:
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                all_queries.append(line)

                if exfil_domain in line:
                    # Extract timestamp, client, and query
                    ts_match = re.match(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+) UTC", line)
                    query_match = re.search(r"QUERY=([^\s|]+)", line)

                    if not query_match:
                        continue

                    query = query_match.group(1)

                    # Match seq-N.BASE64CHUNK.exfil.redteam-c2.xyz
                    chunk_match = re.match(
                        r"seq-(\d+)\.([A-Za-z0-9+/=]+)\." + re.escape(exfil_domain),
                        query,
                    )

                    if chunk_match:
                        seq_num = int(chunk_match.group(1))
                        b64_chunk = chunk_match.group(2)
                        timestamp = ts_match.group(1) if ts_match else "unknown"
                        exfil_chunks[seq_num] = {
                            "chunk": b64_chunk,
                            "timestamp": timestamp,
                            "query": query,
                        }
                        print(f"  [+] Exfil chunk found:")
                        print(f"        Timestamp : {timestamp}")
                        print(f"        Query     : {query}")
                        print(f"        Seq #     : {seq_num}")
                        print(f"        B64 chunk : {b64_chunk}\n")
                    else:
                        # Ping/beacon packet (no chunk data)
                        print(f"  [~] Beacon query (no data): {query}")

    except FileNotFoundError:
        print(f"  [!] File not found: {filepath}")
        return None

    if not exfil_chunks:
        print("  [-] No DNS exfiltration chunks found.")
        return None

    print(f"  [+] Total chunks found: {len(exfil_chunks)}")
    print(f"  [+] Chunk sequence numbers: {sorted(exfil_chunks.keys())}")

    # Sort by sequence number
    print(f"\n  [+] Sorting chunks by sequence number...")
    sorted_keys = sorted(exfil_chunks.keys())
    sorted_chunks = [exfil_chunks[k]["chunk"] for k in sorted_keys]

    print(f"  [+] Ordered chunks:")
    for seq in sorted_keys:
        print(f"      seq-{seq}: {exfil_chunks[seq]['chunk']}")

    # Concatenate
    b64_full = "".join(sorted_chunks)
    print(f"\n  [+] Concatenated base64 string:")
    print(f"      {b64_full}")

    # Decode
    print(f"\n  [+] Base64 decoding...")
    try:
        # Add padding if needed
        padding = 4 - (len(b64_full) % 4)
        if padding != 4:
            b64_full_padded = b64_full + "=" * padding
        else:
            b64_full_padded = b64_full

        decoded_bytes = base64.b64decode(b64_full_padded)
        decoded_str = decoded_bytes.decode("utf-8")
        return decoded_str
    except Exception as e:
        print(f"  [!] Base64 decode error: {e}")
        print(f"  [*] Try URL-safe base64: replacing - with + and _ with /")
        try:
            b64_safe = b64_full.replace("-", "+").replace("_", "/")
            decoded_bytes = base64.b64decode(b64_safe + "==")
            decoded_str = decoded_bytes.decode("utf-8")
            return decoded_str
        except Exception as e2:
            print(f"  [!] Also failed: {e2}")
            return None


def main():
    print(SEPARATOR)
    print("  PHANTOM TRACE — CTF Forensics Solver")
    print("  Category: Log Analysis / DNS Exfiltration")
    print(SEPARATOR)

    # Step 1 & 2: Identify attacker from web log
    attacker_ip = parse_access_log("access.log")

    # Step 3: Trace SSH login
    ssh_login = parse_auth_log("auth.log", attacker_ip)

    # Step 4 & 5: Decode DNS exfiltration
    flag = parse_dns_log("dns_queries.log")

    # Final result
    print(f"\n{'[FINAL RESULT]':=<60}")
    print(f"\n  Attack Chain Summary:")
    print(f"  1. Attacker IP   : {attacker_ip}")
    print(f"  2. Attack vector : Local File Inclusion (?page= parameter)")
    print(f"  3. Data leaked   : /etc/passwd (found username: {ssh_login['user'] if ssh_login else 'N/A'})")
    print(f"  4. SSH login     : {ssh_login['timestamp'] if ssh_login else 'N/A'} "
          f"as '{ssh_login['user'] if ssh_login else 'N/A'}' from {attacker_ip}")
    print(f"  5. Exfil method  : DNS subdomain tunneling to exfil.redteam-c2.xyz")

    if flag:
        print(f"\n  {'*' * 50}")
        print(f"  FLAG: {flag}")
        print(f"  {'*' * 50}\n")
    else:
        print("\n  [-] Could not recover flag. Check log files.\n")


if __name__ == "__main__":
    main()
