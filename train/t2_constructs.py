#!/usr/bin/env python3
"""train/t2_constructs.py — "giá trị này có CẤU TRÚC TẤN CÔNG rõ không?" (dùng để lọc chất lượng dữ liệu, không dùng khi chạy thật).

Vì sao cần: một payload "lọt Cổng 2" trong dataset công khai có thể chỉ là payload hỏng hoặc một giá trị bình thường nằm trong
request bị gắn nhãn tấn công (đọc tay 15/11: chỉ 57/126 payload lọt là tấn công thật; ở SR-BH tham số dài nhất của request
tấn công thường là giá trị hợp lệ). Nếu dạy tầng 2 coi các giá trị đó là "tấn công quan trọng" thì nó sẽ gắn nhãn văn bản hợp lệ.
Vì vậy chỉ payload lọt Cổng 2 VÀ có cấu trúc tấn công rõ mới được đánh dấu g2 = "pass" (cấy thêm, tính nặng, dùng để chọn
model); payload lọt còn lại mang g2 = "pass_weak" và được dùng như mọi payload tấn công khác.

Các biểu thức dưới đây viết tay ngày 15/11/2026, TRƯỚC khi có model mới nào được chấm trên dữ liệu này. Chúng cố ý hẹp: thà
bỏ sót một payload thật còn hơn nhận một chuỗi hợp lệ. Ký tự nháy lẻ ở cuối ("4.2.6'") KHÔNG được tính: quá giống văn bản thường.
"""
import re

RULES = [
    ("lenh", re.compile(r"[&|;`][\s+]*(?:/(?:usr/)?s?bin/)?(?:sleep|cat|ping|id|ls|uname|whoami|wget|curl|nc|echo|type|dir|net|powershell|cmd|sh|bash)\b"
                        r"|\$\(|`[^`]{1,80}`|\$\{?IFS|\$[a-z]{1,3}\b\s|/etc\$?\w*/passwd", re.I)),
    ("sql", re.compile(r"--\s*$|/\*|#\s*$|\bUNION\b.{0,40}\bSELECT\b|\bSELECT\b.{1,80}\bFROM\b|\bSELECT\s+[@(]|@@\w+"
                       r"|\b(?:OR|AND|HAVING)\s+[\w'\"]+\s*(?:=|<|>|LIKE)\s*[\w'\"]+|WAITFOR\s+DELAY|SLEEP\s*\(|BENCHMARK\s*\(|PG_SLEEP"
                       r"|;\s*(?:DROP|INSERT|UPDATE|DELETE|SELECT|EXEC)\b|\b(?:ASC|DESC)\s+--|\bCASE\s+WHEN\b|\bSELECT\s+\w+\s*;", re.I)),
    ("duong_dan", re.compile(r"\.\./|\.\.\\|\.\.%|/etc/|c:\\|boot\.ini|win\.ini|%2e%2e|0x2e0x2e|\.\.\.\./|file://|php://"
                             r"|etc.{1,8}passwd|etc.{1,8}issue|system32", re.I)),
    ("xss", re.compile(r"<\s*/?\s*[a-z][a-z0-9]*[^<>]{0,200}>|\bon[a-z]{3,}\s*=|javascript:|\b(?:alert|confirm|prompt|eval)\s*\(|document\.\w", re.I)),
]


def constructs(value):
    """Danh sách tên nhóm cấu trúc tấn công tìm thấy trong giá trị (rỗng = không có)."""
    return [name for name, rx in RULES if rx.search(value or "")]
