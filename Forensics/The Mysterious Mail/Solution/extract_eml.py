#!/usr/bin/env python3
# extract_eml.py — Trích xuất attachment từ file .eml

import email
import base64
import sys
import os

def extract_attachments(eml_path):
    with open(eml_path, 'rb') as f:
        msg = email.message_from_bytes(f.read())

    count = 0
    for part in msg.walk():
        content_disposition = part.get("Content-Disposition", "")
        content_type = part.get_content_type()

        if "attachment" in content_disposition or content_type.startswith("image/"):
            filename = part.get_filename()
            payload = part.get_payload(decode=True)
            if payload:
                if not filename:
                    count += 1
                    ext = content_type.split("/")[-1]
                    filename = f"image{count}.{ext}"
                with open(filename, 'wb') as out:
                    out.write(payload)
                print(f"[+] Extracted: {filename}")

if __name__ == "__main__":
    eml_file = sys.argv[1] if len(sys.argv) > 1 else "suspicious_mail.eml"
    extract_attachments(eml_file)