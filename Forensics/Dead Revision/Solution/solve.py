#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║       CTF Solver: "Dead Revision" — Office Forensics        ║
║       Flag format: DWY_YK{...}                              ║
╚══════════════════════════════════════════════════════════════╝

Cách dùng / Usage:
    python3 solve.py investigation_report.docx
"""

import sys
import zipfile
import base64
import xml.etree.ElementTree as ET
import re

# XML namespaces used in OOXML
NS = {
    "w":  "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
    "cp": "http://schemas.openxmlformats.org/officeDocument/2006/custom-properties",
    "vt": "http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes",
}

BANNER = """
╔══════════════════════════════════════════════════════════╗
║         Dead Revision — CTF Forensics Solver            ║
╚══════════════════════════════════════════════════════════╝
"""

def separator(title: str):
    print(f"\n{'─'*60}")
    print(f"  STEP: {title}")
    print('─'*60)


def step1_list_structure(docx_path: str, z: zipfile.ZipFile):
    """
    BƯỚC 1: Nhận ra .docx là file ZIP và liệt kê cấu trúc bên trong.
    STEP 1: Recognize the .docx as a ZIP container and list its structure.
    """
    separator("Recognize OOXML / ZIP structure")
    print(f"[*] Target file  : {docx_path}")
    print(f"[*] .docx = ZIP format (Office Open XML / OOXML)")
    print(f"\n[i] Internal file structure:")
    for info in z.infolist():
        print(f"    {info.filename}")


def step2_read_comments(z: zipfile.ZipFile) -> str:
    """
    BƯỚC 2: Đọc file word/comments.xml để tìm breadcrumb từ tác giả ẩn.
    STEP 2: Read word/comments.xml to find the breadcrumb left by the hidden author.
    Returns the comment text.
    """
    separator("Inspect word/comments.xml — find the breadcrumb")
    raw = z.read("word/comments.xml").decode("utf-8")
    root = ET.fromstring(raw)

    comments = root.findall(f".//{{{NS['w']}}}comment")
    print(f"[+] Found {len(comments)} comment(s) in word/comments.xml:\n")
    comment_text = ""
    for c in comments:
        author = c.get(f"{{{NS['w']}}}author", "?")
        date   = c.get(f"{{{NS['w']}}}date",   "?")
        texts  = c.findall(f".//{{{NS['w']}}}t")
        text   = "".join(t.text or "" for t in texts)
        comment_text = text
        print(f"    Author : {author}")
        print(f"    Date   : {date}")
        print(f"    Text   : {text}")

    print(f"\n[!] Key observation: author='Analyst_7', mentions")
    print(f"    'key stored in document properties under the")
    print(f"    verification checksum field'")
    print(f"    → Next target: docProps/custom.xml")
    return comment_text


def step3_extract_xor_key(z: zipfile.ZipFile) -> bytes:
    """
    BƯỚC 3: Đọc docProps/custom.xml, tìm thuộc tính 'CheckSum',
            giải mã Base64 → chuỗi Hex → XOR key bytes.
    STEP 3: Read docProps/custom.xml, locate the 'CheckSum' custom property,
            decode Base64 → hex string → XOR key bytes.
    Returns the XOR key as bytes.
    """
    separator("Extract XOR key from docProps/custom.xml")
    raw = z.read("docProps/custom.xml").decode("utf-8")
    root = ET.fromstring(raw)

    print("[i] Custom properties found:")
    checksum_b64 = None
    for prop in root.findall(f".//{{{NS['cp']}}}property"):
        name = prop.get("name", "?")
        val_el = prop.find(f"{{{NS['vt']}}}lpwstr")
        val_i4 = prop.find(f"{{{NS['vt']}}}i4")
        val = (val_el.text if val_el is not None else
               val_i4.text if val_i4 is not None else "?")
        print(f"    name={name!r:20s}  value={val!r}")
        if name == "CheckSum":
            checksum_b64 = val

    print(f"\n[+] CheckSum value (raw): {checksum_b64!r}")

    # Decode Base64 → hex string
    hex_str = base64.b64decode(checksum_b64).decode("utf-8")
    print(f"[+] Base64 decoded       : {hex_str!r}")
    print(f"    └─ This looks like a hex string...")

    # Decode hex → raw bytes (XOR key)
    xor_key = bytes.fromhex(hex_str)
    print(f"[+] Hex decoded (XOR key): {xor_key!r}  →  '{xor_key.decode()}'")
    return xor_key


def step4_find_encrypted_payload(z: zipfile.ZipFile) -> str:
    """
    BƯỚC 4: Phân tích word/document.xml, tìm các thẻ <w:del> (tracked deletions)
            chứa <w:delText> — đây là payload mã hóa bị ẩn khỏi giao diện Word.
    STEP 4: Parse word/document.xml, locate <w:del> (tracked deletion) elements
            containing <w:delText> — invisible in the rendered document.
    Returns the hex-encoded encrypted payload string.
    """
    separator("Locate encrypted payload in word/document.xml — <w:del>")
    raw = z.read("word/document.xml").decode("utf-8")

    # Find all <w:del> blocks
    del_elements = re.findall(
        r'<w:del\b[^>]*w:author="([^"]+)"[^>]*w:date="([^"]+)"[^>]*>.*?</w:del>',
        raw, re.DOTALL
    )

    print(f"[i] Searching for <w:del> tracked-deletion blocks in document.xml...")

    if del_elements:
        print(f"[+] Found {len(del_elements)} <w:del> block(s):\n")
        for author, date in del_elements:
            print(f"    w:author={author!r}   w:date={date!r}")

    # Extract <w:delText> content
    del_texts = re.findall(r'<w:delText[^>]*>([^<]+)</w:delText>', raw)
    print(f"\n[+] <w:delText> content(s):")
    for t in del_texts:
        print(f"    {t!r}")

    if not del_texts:
        print("[-] No delText found. Check manually with: grep -o '<w:del.*</w:del>' word/document.xml")
        sys.exit(1)

    encrypted_hex = del_texts[0].strip()
    print(f"\n[+] Encrypted payload (hex): {encrypted_hex}")
    print(f"[!] This appears to be hex-encoded encrypted data.")
    print(f"    → Apply XOR decryption with the recovered key.")
    return encrypted_hex


def step5_decrypt(encrypted_hex: str, xor_key: bytes) -> str:
    """
    BƯỚC 5: Giải mã payload — XOR từng byte với key (lặp vòng).
    STEP 5: Decrypt payload — XOR each byte with the key (cyclic).
    Returns the plaintext flag string.
    """
    separator("XOR Decrypt — recover the flag")
    enc_bytes = bytes.fromhex(encrypted_hex)
    print(f"[i] Encrypted bytes ({len(enc_bytes)} bytes): {enc_bytes.hex()}")
    print(f"[i] XOR key ({len(xor_key)} bytes, cyclic)  : {xor_key!r}")
    print()

    # XOR decryption (cyclic key)
    dec_bytes = bytes([enc_bytes[i] ^ xor_key[i % len(xor_key)]
                       for i in range(len(enc_bytes))])

    print(f"[i] XOR operation (first 8 bytes shown):")
    for i in range(min(8, len(enc_bytes))):
        e = enc_bytes[i]
        k = xor_key[i % len(xor_key)]
        d = dec_bytes[i]
        print(f"    byte[{i}]: 0x{e:02x} XOR 0x{k:02x} ({chr(k)}) = 0x{d:02x} ({chr(d) if 32 <= d < 127 else '?'})")
    print(f"    ...")

    flag = dec_bytes.decode("utf-8")
    return flag


def main():
    docx_path = sys.argv[1] if len(sys.argv) > 1 else "investigation_report.docx"
    print(BANNER)

    try:
        z = zipfile.ZipFile(docx_path, "r")
    except FileNotFoundError:
        print(f"[!] File not found: {docx_path}")
        sys.exit(1)

    with z:
        # ── Step 1: Structure ──────────────────────────────────────────
        step1_list_structure(docx_path, z)

        # ── Step 2: Comments breadcrumb ────────────────────────────────
        step2_read_comments(z)

        # ── Step 3: Extract XOR key from custom.xml ───────────────────
        xor_key = step3_extract_xor_key(z)

        # ── Step 4: Find encrypted payload in tracked deletions ────────
        encrypted_hex = step4_find_encrypted_payload(z)

        # ── Step 5: Decrypt ───────────────────────────────────────────
        flag = step5_decrypt(encrypted_hex, xor_key)

    separator("FLAG RECOVERED")
    print(f"\n  🚩  {flag}\n")


if __name__ == "__main__":
    main()
