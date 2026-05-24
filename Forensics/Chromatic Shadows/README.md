# Chromatic Shadows

| Field    | Value              |
|----------|--------------------|
| Category | Forensics          |
| Difficulty | Easy             |
| Author   | yehsure            |

---

## 🇻🇳 Mô tả (Tiếng Việt)

> Một khung hình hỏng được phục hồi từ trạm giám sát ven biển bị bỏ hoang sau nhiều năm nằm trong kho lưu trữ cùng các tín hiệu bị lỗi.
> Dù bức ảnh trông gần như bình thường, các kỹ thuật viên vẫn không thể xác định liệu bên trong nó còn sót lại dữ liệu nào hay không. Bạn có thể giúp tôi xác định không ?

**File:** `capture.png`  
**Flag format:** `DWY_YK{...}`

---

## 🇬🇧 Description (English)

> A corrupted frame was recovered from an abandoned coastal monitoring station after years of being archived with damaged transmissions.
> Although the image appears mostly intact, analysts were unable to determine whether any useful data remained inside it. Can you help me identify this?

**File:** `capture.png`  
**Flag format:** `DWY_YK{...}`

---

## Recommended Tools

```
exiftool    — metadata inspection
Python 3    — PIL/Pillow, numpy, struct
pngcheck    — PNG chunk analysis
binwalk     — file signature scanning (rabbit hole awareness)
```

*Note: Common automated stego tools (`zsteg`, `StegSolve`, `stegoveritas`) will NOT solve this challenge.*
