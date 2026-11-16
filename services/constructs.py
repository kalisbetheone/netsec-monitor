"""constructs: "giá trị này có CẤU TRÚC TẤN CÔNG rõ không?" — bộ biểu thức viết tay, dùng ở hai chỗ:

  1. classifier, khi bật TIER2_CONSTRUCT_GATE=1: nhãn của model tầng 2 chỉ được tính nếu có ít nhất một giá trị tham số khớp
     một nhóm dưới đây. Model tuyến tính trên n-gram ký tự gắn nhãn theo TỪ VỰNG ("order by price", "select a laptop", "ls"),
     còn các biểu thức này bắt CÚ PHÁP; mỗi bên sai ở chỗ khác nhau nên yêu cầu cả hai cùng đồng ý (nghiên cứu 16/11/2026:
     Nghien-cuu-khac-phuc-tang-2-NSM.md). Riêng bộ biểu thức thì khớp cả ~3 % request hợp lệ, nên KHÔNG dùng nó một mình.
  2. train/t2_pool_result.py: lọc chất lượng payload "lọt Cổng 2" khi dựng dữ liệu huấn luyện (train/t2_constructs.py nhập lại
     từ đây để hai nơi luôn dùng cùng một bộ).

Viết ngày 15/11/2026 (trước khi có model nào được chấm trên dữ liệu lọc bằng nó); chỉnh một lần sau khi xem 52 payload đã đọc tay
(dấu cách dạng '+' sau dấu nối lệnh). Cố ý hẹp: dấu nháy lẻ ở cuối ("4.2.6'"), từ khoá trần ("delete"), tên lệnh trần ("ls") KHÔNG
được tính. Mọi lượng từ đều có trần hoặc tuyến tính; nơi gọi cắt giá trị còn 2 000 ký tự.
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
MAX_LEN = 2000


def constructs(value):
    """Danh sách tên nhóm cấu trúc tấn công tìm thấy trong MỘT giá trị (rỗng = không có)."""
    v = (value or "")[:MAX_LEN]
    return [name for name, rx in RULES if rx.search(v)]


def any_construct(values):
    """True nếu có ít nhất một giá trị mang cấu trúc tấn công. Xét TỪNG giá trị: nhiều biểu thức neo ở cuối giá trị."""
    return any(constructs(v) for v in values)
