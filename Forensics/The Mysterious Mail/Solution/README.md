# Hướng dẫn giải (Writeup)

## Bước 1 — Phân tích file .eml
Mở `suspicious_mail.eml` bằng text editor hoặc email client. Trong phần body/attachments, bạn sẽ thấy hai đoạn base64 tương ứng với hai file ảnh đính kèm.

Decode từng đoạn để lấy `image1.jpg` và `image2.jpg`:

Trích xuất attachment từ `.eml` (hoặc copy thủ công đoạn base64).
`python3 extract_eml.py suspicious_mail.eml`

## Bước 2 — Kiểm tra metadata bằng exiftool
exiftool image1.jpg

exiftool image2.jpg

`image1.jpg` → trường Comment:

  Q2hlY2tfYm90aF9pbWFnZXM=
Decode base64 → Check_both_images (gợi ý: hãy xem ảnh 2)

`image2.jpg` → trường Comment:

  bWV0YWRhdGFfbmV2ZXJfbGllcw==
Decode base64 → metadata_never_lies ✅ Đây là password!

## Bước 3 — Giải nén .zip
unzip -P metadata_never_lies secret_archive.zip
→ giải ra: hidden_message.txt

## Bước 4 — Whitespace Steganography
File `hidden_message.txt` trông bình thường khi đọc, nhưng ẩn chứa dữ liệu trong tab/space theo kỹ thuật Whitespace Steganography.
`python3 solve.py`

Output: DWY_YK{3ml_70_1m463_4nd_ju57_r34d_7h3_wh1735p4c3_r16h7?} 