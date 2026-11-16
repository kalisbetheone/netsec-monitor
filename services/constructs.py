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

Bộ BỔ SUNG "v2" (16/11/2026, TIER2_CONSTRUCT_RULES=2; mặc định 1 = chỉ bộ gốc): viết từ các payload của phần TRAIN mà bộ gốc
không khớp (điều kiện luôn đúng có ngoặc, hàm SQL, nối chuỗi ||, lệnh sau dấu xuống dòng, mã PHP, ../ mã hoá base64, đường dẫn
tuyệt đối tới nhật ký / cấu hình máy chủ, thẻ HTML viết bằng thực thể). Vẫn giữ nguyên tắc hẹp ở trên: tên lệnh trần ("ifconfig"),
từ khoá trần, đường dẫn ổ đĩa thường ("D:\\photos") KHÔNG được tính. Kiểm trên phần valid: Nghien-cuu-khac-phuc-tang-2-NSM.md, mục 10.
"""
import os
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

_CMD = r"(?:id|ls|cat|ping|sleep|uname|whoami|netstat|nslookup|wget|curl|nc|ifconfig|ipconfig)"
_EXTRA_V2 = {
    "lenh": (
        # dấu nối lệnh + lệnh chưa có trong danh sách v1
        r"[&|;`][\s+]*(?:netstat|ipconfig|ifconfig|nslookup|phpinfo)\b"
        # xuống dòng (thật hoặc viết \n) rồi tới lệnh: có đường dẫn /bin, hoặc có tham số / dấu nối theo sau
        r"|(?:[\n\r]|\\[nr])\s*/(?:usr/)?s?bin/\w+"
        r"|(?:[\n\r]|\\[nr])\s*" + _CMD + r"(?:\s+[-/.~$]|\s*[|;&])"      # v2b: theo sau CHỈ là xuống dòng thì không tính (dòng 'id' của GraphQL)
        # cả giá trị chỉ là (xuống dòng +) một lệnh
        r"|^\s*(?:(?:[\n\r]|\\[nr])\s*)+" + _CMD + r"\s*$"
        r"|^\s*(?:ipconfig|ifconfig|netstat|whoami|uname)\s+[-/]\w+"
        r"|^\s*/(?:usr/)?s?bin/\w+(?:\s+-\w+)*\s*$"
        r"|^\s*(?:ls|ping|nc|netstat)\s+-\w+"
        r"|-e\s+/bin/(?:ba)?sh\b"
        # mã PHP / SSI
        r"|\bphp(?:info|version)\s*\(|\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b|\$\{\s*@?\w+\(|<\?php|<!--\s*#\s*(?:exec|include)\b"
    ),
    "sql": (
        # điều kiện luôn đúng có ngoặc:  ) or ('a'='a   ') or ('x')=('x   ) or (a=a
        r"\b(?:OR|AND)\s*\(\s*['\"]*\w+['\"]*\s*\)?\s*=\s*\(?\s*['\"]*\w+"
        r"|\b(?:OR|AND)\s+['\"]\w+['\"]\s+IN\s*\("
        r"|\b(?:OR|AND)\s+\w+\s*--"
        r"|\b(?:OR|AND)\s+\d+\s+BETWEEN\s+\d+\s+AND\s+\d+"
        r"|\b(?:OR|AND)\s+\w+\("
        r"|\b(?:ORDER|GROUP)\s+BY\s+\d+\s*(?:,\s*\d+|--|#)"
        r"|\bEXEC(?:UTE)?\s+(?:master\b|[sx]p_\w+|immediate\b)|\bxp_cmdshell\b"
        r"|\bSELECT\s+[\w.]+\(|\bSELECT\s+\*"
        r"|\b(?:version|current_user|database|system_user|session_user)\s*\(\s*\)"
        r"|['\"]\s*\|\|\s*[\w(.]|\|\|\s*['\"]|\d\s*\|\|\s*\w+\s*(?:\(|=|\bIS\b)"
        r"|\bUTL_(?:HTTP|INADDR|FILE|SMTP)\b|\bDBMS_\w+\.\w+|\bRANDOMBLOB\s*\("
        r"|\bINTO\s+(?:OUT|DUMP)FILE\b|\bBACKUP\s+(?:DATABASE|LOG)\b|\bDECLARE\s+@\w+"
        r"|\bINSERT\s+INTO\s+\w+.{0,80}\bVALUES\s*\("
        r"|\bCHA?R\(\s*(?:0x[0-9a-f]{1,4}|\d{1,3})\s*\)"
        r"|\\x27(?:\\x[0-9a-f]{2}|\s*(?:UNION|OR|AND|SELECT)\b)"
        r"|['\"\d]\s*\)+\s*UNION\b"
    ),
    "duong_dan": (
        # ../ và /etc/ mã hoá base64; ../ viết '..2f'
        r"(?:Li4v){2,}|L2V0Yy9|ZXRjL3(?:Bhc3N3|NoYWRvd)|(?:\.\.2f){2,}"
        # đường dẫn tuyệt đối tới tệp nhật ký / cấu hình của máy chủ
        r"|/var/(?:log|www|adm|run|lib|spool|mail|lock|cpanel|apache|cron|lp|saf)\b|/usr/(?:local|lib|ports)/|/opt/\w+/(?:logs?|conf|etc)\b"
        r"|/root/\.|/proc/(?:self|\d+)/|\bphp\.ini\b|\bhttpd\.conf\b|\.htaccess\b|\.htpasswd\b|\bmy\.cnf\b|\b(?:access|error)[._]log\b"
        r"|\bmaster\.passwd\b|\bntuser\.dat\b|\\(?:windows|winnt)\\|\\Program Files\\"
    ),
    "xss": (
        # '<' viết bằng thực thể HTML; thẻ viết bằng &lt; ... ; thẻ bị chèn dấu chấm phẩy
        r"&#(?:x0*3c|0*60)(?![0-9a-f])"
        r"|&lt;\s*/?\s*(?:script|img|a|iframe|embed|object|style|meta|layer|html|body|svg|link|base|form|input|xss)\b"
        r"|<;\s*/?\s*[a-z]+"
        r"|(?:&#(?:x[0-7][0-9a-f]|0*\d{2,3});?){4,}"
        r"|%uff1c\s*/?\s*[a-z]"
        r"|<\s*(?:script|iframe|img|svg|object|embed|body|style)\b[^<>]{0,200}\b(?:src|href|data|on\w+)\s*="
        r"|\b(?:alert|confirm|prompt|eval)\s*\?\.\s*\(|document\?\.\w|=\s*(?:alert|prompt|confirm|eval)\s*[,;]"
        r"|-moz-binding\s*:|\b(?:vbscript|livescript|mocha)\s*:"
    ),
}
EXTRA_V2 = {name: re.compile(rx, re.I) for name, rx in _EXTRA_V2.items()}
RULESET = os.getenv("TIER2_CONSTRUCT_RULES", "1")     # "1" = bộ gốc; "2" = bộ gốc + bổ sung v2


def constructs(value, ruleset=None):
    """Danh sách tên nhóm cấu trúc tấn công tìm thấy trong MỘT giá trị (rỗng = không có). ruleset: "1" | "2" (mặc định: RULESET)."""
    v = (value or "")[:MAX_LEN]
    if (ruleset or RULESET) == "2":
        return [name for name, rx in RULES if rx.search(v) or EXTRA_V2[name].search(v)]
    return [name for name, rx in RULES if rx.search(v)]


def any_construct(values):
    """True nếu có ít nhất một giá trị mang cấu trúc tấn công. Xét TỪNG giá trị: nhiều biểu thức neo ở cuối giá trị."""
    return any(constructs(v) for v in values)
