"""classifier: tiêu thụ web.logs + net.events (+ web.audit để lấy thân request) → gắn nhãn → ES;
phát cảnh báo vào topic alerts.

Tầng 1 (regex) so khớp trên TỪNG GIÁ TRỊ tham số (query + body) và đường dẫn, KHÔNG so trên
chuỗi query nguyên: dấu '&' ngăn tham số và TÊN tham số (id, cat, onload...) không còn bị
hiểu nhầm là payload. Tầng 2 (học máy) chỉ được hỏi khi giá trị có ký tự cú pháp tấn công.

Sửa sau đợt rà soát 12/11/2026:
  * Cảnh báo được phát TRƯỚC khi ghi Elasticsearch; việc ghi ES chạy ở luồng nền (N2).
  * Tầng 2 mặc định chỉ GHI NHẬN (TIER2_MODE=observe): nhãn của model nằm ở t2_label/t2_conf, không
    thành cảnh báo, cho tới khi model được huấn luyện lại (N1).
  * Không còn cắt 100 tham số / 2048 ký tự / 4096 ký tự: quét hết trong trần SCAN_MAX_PARAMS và
    SCAN_MAX_BYTES; vượt trần hoặc thân bị ModSecurity cắt thì gắn nhãn 'uninspected' (N3, C7).
  * Soi cả User-Agent, Referer và cookie (C2).
  * Giá trị nhạy cảm (mật khẩu, mã phiên, thẻ...) được che trước khi lưu (C1).
"""
import ipaddress, json, math, os, time, uuid, re
from collections import Counter
import secrule
from urllib.parse import unquote, unquote_plus
from common import (EsBuffer, Heartbeat, consumer, day_index, es_client, install_stop, iso, log,
                    parse_json_line, parse_ts, producer, running)

L = log("classifier")
INTERNAL = [ipaddress.ip_network(c.strip()) for c in os.getenv("INTERNAL_CIDRS", "10.10.30.0/24").split(",") if c.strip()]
MODEL_PATH = os.getenv("MODEL_PATH", "/models/tier2.joblib")
T2_THRESHOLD = float(os.getenv("TIER2_THRESHOLD", "0.90"))
# argmax: lớp cao nhất phải là lớp tấn công và >= θ (mặc định, khớp cách model hiện tại được đánh giá)
# mass  : 1 - P(benign) >= θ. CHỈ bật sau khi huấn luyện lại model với benign đa dạng — model run_4
#         cho P(benign)≈0 với hầu hết đầu vào lạ nên 'mass' sẽ báo nhầm gần như mọi request.
T2_DECISION = os.getenv("TIER2_DECISION", "argmax").lower()
T2_GATE = os.getenv("TIER2_SYNTAX_GATE", "1") != "0"
# observe: tầng 2 chỉ ghi nhận (t2_label/t2_conf), không đổi nhãn, không phát cảnh báo — mặc định cho tới khi
#          model được huấn luyện lại (model run_4 gắn nhãn tấn công cho mọi thân JSON/XML/multipart và nhiều câu
#          thường như "it's ok"; lượt chạy thử 12/11 chặn 5/5 IP người dùng hợp lệ vì vậy).
# corroborate: chỉ dùng nhãn tầng 2 khi ModSecurity CŨNG đã chặn chính request đó (hai bộ phát hiện độc lập cùng
#          đồng ý). Đo trên 2000 request thật (parity 12/11): phát hiện 71 % (enforce cũ 74 %), báo nhầm 8,3 % lưu
#          lượng lành tính (observe 1,5 %, enforce cũ 43,8 %).
# enforce: nhãn tầng 2 được dùng như trước (kèm cổng: không hỏi model với thân JSON/XML/multipart).
# weighted (15/11/2026): chế độ TRUNG GIAN giữa corroborate và enforce. Nhãn của model được dùng cả khi Cổng 2 không
#          chặn, nhưng cảnh báo đó mang cờ weighted=true: responder chỉ tính nửa trọng số (TIER2_WEIGHT) và không tính
#          vào cửa sổ dài, nên một lần model nhầm không khoá được người dùng. Khi Cổng 2 CŨNG chặn thì tính đủ như
#          corroborate. Nhờ vậy tấn công mà CRS lẫn regex tầng 1 bỏ lọt vẫn thành cảnh báo và vào được bộ sinh luật.
T2_MODE = os.getenv("TIER2_MODE", "observe").lower()
# Độ tin cậy gửi cho responder. Ngưỡng của model (TIER2_THRESHOLD) được chọn trên tập valid để tầng 2 chỉ thêm ≤ 0,1 %
# báo nhầm; nó KHÔNG cùng thang với θ = 0,90 của responder (model 14/11 dùng ngưỡng 0,67). Điểm model trong [ngưỡng, 1]
# được đổi tuyến tính sang [0,90; 1,00] — không thì mọi nhãn tầng 2 có điểm dưới 0,90 bị responder bỏ ở bước "độ tin
# cậy ≥ θ" dù đã vượt ngưỡng của chính model. Điểm gốc vẫn được lưu ở trường t2_conf.
T2_CONF_FLOOR = float(os.getenv("TIER2_CONF_FLOOR", "0.90"))

def t2_confidence(score):
    if T2_THRESHOLD >= 1.0: return max(score, T2_CONF_FLOOR)
    x = min(max((score - T2_THRESHOLD) / (1.0 - T2_THRESHOLD), 0.0), 1.0)
    return round(T2_CONF_FLOOR + (1.0 - T2_CONF_FLOOR) * x, 4)
T2_STRUCTURED = os.getenv("TIER2_STRUCTURED_BODY", "0") == "1"
ANOMALY_CONF = float(os.getenv("ANOMALY_CONFIDENCE", "0.5"))
# Trần quét. Trước đây chỉ đọc 100 tham số đầu, 2048 ký tự mỗi giá trị, 4096 ký tự thân JSON — đặt payload
# sau phần đệm là qua mặt được. Nay quét hết trong trần; vượt trần thì gắn nhãn 'uninspected' (không coi là lành tính).
MAX_PARAMS = int(os.getenv("SCAN_MAX_PARAMS", "1000"))           # = SecArgumentsLimit của ModSecurity
SCAN_MAX_BYTES = int(os.getenv("SCAN_MAX_BYTES", str(512 * 1024)))   # > SecRequestBodyNoFilesLimit (128 KB) của ModSecurity
UNINSPECTED_CONF = float(os.getenv("UNINSPECTED_CONFIDENCE", "0.5"))   # < θ: ghi kiểm toán, không tự chặn
REFERER_CONF = float(os.getenv("REFERER_CONFIDENCE", "0.6"))

# Dấu nối lệnh shell trong MỘT GIÁ TRỊ (đã tách tham số nên '&' ở đây đến từ %26).
# Siết 13/11 (đo trên website openappsec chưa thấy: luật cũ báo nhầm 2,9 % request lành tính — 1,6 % trên ĐƯỜNG DẪN,
# 0,5 % trên tham số url kiểu '...&id=5'): (1) không áp lên đường dẫn; (2) tên lệnh phải KẾT THÚC đúng chỗ (hết chuỗi,
# khoảng trắng hoặc ký tự shell) — '&id=5', '$(document)' không còn khớp; (3) '$(' phải theo sau là tên lệnh.
_CMD = (r"(?:/(?:usr/)?s?bin/)?(?:cat|ls|id|whoami|uname|wget|curl|nc|ncat|bash|sh|python[23]?|perl|php|chmod|pwd"
        r"|hostname|base64|powershell|ifconfig|nslookup)")
_CMD_END = r"(?=$|[\s;|&<>`)'\"])"
RECON_FOUND_CONF = float(os.getenv("RECON_FOUND_CONFIDENCE", "0.6"))  # đường dẫn 'nhạy cảm' nhưng trang CÓ THẬT: chỉ ghi nhận
REDIRECT_CONF = float(os.getenv("REDIRECT_CONFIDENCE", "0.6"))      # open redirect: chỉ ghi nhận (cần biết tên miền của ứng dụng)
BODY_LOW_CONF = float(os.getenv("STRUCTURED_BODY_LOW_CONFIDENCE", "0.6"))   # NoSQLi/LDAP chỉ thấy trong cả thân JSON/XML
REDIRECT_PARAMS = re.compile(r"^(?:next|url|redirect|redirect_uri|redirect_url|return|returnto|return_url|goto|continue"
                             r"|dest|destination|target|r|u)$")
INCLUDE_PARAMS = re.compile(r"^(?:page|file|filename|include|inc|path|template|tpl|doc|document|module|load|view|lang"
                            r"|language|folder|dir|pg|content|layout|conf|config)$")
# Mỗi luật: (lớp, mẫu, phạm vi). Phạm vi (xem _in_scope):
#   any      mọi đơn vị (đường dẫn, tham số, tên tham số lạ, User-Agent, Referer, cookie)
#   nopath   như any nhưng bỏ đường dẫn
#   raw      như nopath, thêm cả giá trị CHƯA gộp khoảng trắng (cần cho dấu xuống dòng: nối lệnh bằng \n)
#   rawonly  chỉ giá trị chưa gộp khoảng trắng (CRLF)
#   named    tham số có tên / cookie / header; thấy trong CẢ thân JSON/XML thì chỉ ghi nhận (BODY_LOW_CONF)
#   redirect tham số có tên kiểu chuyển hướng (next, url, return...) — độ tin cậy REDIRECT_CONF
#   include  tham số có tên kiểu include (page, file, template...)
# Thứ tự = thứ tự ưu tiên khi nhiều luật khớp. 9 họ mới (xxe...redirect) thêm 13/11: báo nhầm đo trên 751 939
# request thật của openappsec Legitimate là 10 (0,0013 %) khi open redirect chỉ ghi nhận — xem
# Huong-cai-tien-kich-ban-01-02-05-NSM.md, mục 4.3. Dữ liệu độc lập để đo lại: eval/data/payloads_independent/.
_RULES = [
    ("sqli", r"\bunion\b.{0,40}\bselect\b", "any"),
    ("sqli", r"['\"\d)]\s*\b(?:or|and)\b\s*['\"(]?\d+['\")]?\s*=\s*['\"(]?\d+", "any"),   # 1 or 1=1 / ' and 2=2
    ("sqli", r"'\s*(?:or|and)\s+'", "any"),
    ("sqli", r"\b(?:sleep|benchmark|pg_sleep)\s*\(", "any"),
    ("sqli", r"\binformation_schema\b", "any"),
    ("sqli", r";\s*(?:drop|insert|update|delete)\s", "any"),
    ("sqli", r"'\s*--", "any"),
    ("sqli", r"(?:extractvalue|updatexml|load_file|group_concat)\s*\(", "any"),           # SQLi dạng lỗi / đọc tệp
    ("sqli", r"'\s*(?:or|and)\s+\w+\s*\(", "any"),
    ("xss", r"<\s*script", "any"),
    # bỏ qua đúng dạng "liên kết không làm gì" javascript:void(0) / javascript:; khi nó đứng một mình (hết giá trị hoặc
    # tới dấu phân cách) — rất phổ biến trong tham số cấu hình của website thật. 'javascript:void(0);alert(1)' vẫn khớp.
    ("xss", r"javascript\s*:(?!\s*(?:void\s*\(\s*0\s*\)\s*;?|;)?\s*(?:$|[\"',}\]&]))", "any"),
    ("xss", r"\bon(?:error|load|mouseover|focus|click)\s*=", "any"),
    ("xss", r"<\s*(?:img|svg|iframe|body)\b[^<>]{0,512}\bon\w+", "any"),
    ("xss", r"document\.(?:cookie|domain)", "any"),
    # rce xét TRƯỚC lfi: '127.0.0.1;cat /etc/shadow' là chèn lệnh, không phải đọc tệp
    ("rce", r"(?:;|\||`|&&?|\$\()\s*" + _CMD + _CMD_END, "raw"),
    # nối lệnh bằng XUỐNG DÒNG (%0a): chỉ khi trước dấu xuống dòng là MỘT cụm liền không khoảng trắng, ở đầu giá trị
    # hoặc sau ký tự shell (dạng "127.0.0.1\nid"). Ô văn bản nhiều dòng hợp lệ ("Thú cưng:\ncat and dog") không khớp.
    ("rce", r"(?:^|[;|&`])[^\s;|&`]{1,64}[\r\n]+\s*" + _CMD + _CMD_END, "rawonly"),
    ("rce", r"\b(?:system|exec|passthru|shell_exec|popen)\s*\(", "any"),
    ("rce", r"\$\{\s*jndi\s*:", "any"),                                            # Log4Shell
    ("rce", r"\$\{[^}]{0,40}\$\{", "any"),                                         # Log4Shell lồng ${${lower:j}ndi:...}
    ("rce", r"\(\s*\)\s*\{\s*:?\s*;\s*\}", "any"),                                 # Shellshock () { :; }
    ("rce", r"^\s*\(\s*\x00?\s*\)[\s.]*\{", "nopath"),                             # Shellshock: giá trị bắt đầu bằng () {
    ("lfi", r"(?:\.{2,}[\\/]+){2,}", "any"),                                        # ../../  ....//....//
    ("lfi", r"/etc/(?:passwd|shadow|hosts)", "any"),
    ("lfi", r"(?:boot|win)\.ini", "any"),
    ("lfi", r"php://(?:filter|input)", "any"),
    ("xxe", r"<!doctype[^>]{0,300}\[\s*<!entity", "nopath"),
    ("xxe", r"<!entity\s+%?\s*[\w.-]+\s+(?:system|public)\b", "nopath"),
    ("ssti", r"\{\{\s*\d+\s*[*+/-]\s*\d+\s*\}\}", "nopath"),
    ("ssti", r"\$\{\s*\d+\s*[*+/-]\s*\d+\s*\}", "nopath"),
    ("ssti", r"<%=?\s*\d+\s*[*+/-]\s*\d+\s*%>", "nopath"),
    ("ssti", r"#\{\s*\d+\s*[*+/-]\s*\d+\s*\}", "nopath"),
    ("ssti", r"__(?:class|mro|globals|builtins|subclasses|import)__", "nopath"),
    ("ssti", r"\$\{\s*t\s*\(\s*java\.", "nopath"),
    ("ssti", r"\{\{\s*(?:config|self|request|cycler|lipsum|joiner|namespace)\b", "nopath"),
    ("ssti", r"\{%\s*(?:import|include|set|for)\b", "nopath"),
    ("ssrf", r"\b(?:https?|gopher|dict|ftp|tftp|ldap)://(?:[^/@\s]*@)?(?:\[[0-9a-f:.]*\]|localhost|127(?:\.\d{1,3}){3}"
             r"|0\.0\.0\.0|0x[0-9a-f]{6,8}|\d{8,10}|169\.254\.169\.254|metadata\.google\.internal|10(?:\.\d{1,3}){3}"
             r"|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})(?=[:/?#]|$)", "nopath"),
    ("ssrf", r"\b(?:gopher|dict)://", "nopath"),
    ("deser", r"\b[oc]:\+?\d+:\"[\w\\]+\":\d+:\{", "nopath"),                    # PHP object
    ("deser", r"\ba:\d+:\{(?:[is]:\d+[;:])", "nopath"),                          # PHP array
    ("deser", r"\bro0ab|\baced0005|\baaeaaad/////", "nopath"),                   # Java / .NET
    ("deser", r"c__builtin__|cposix\nsystem", "nopath"),                         # Python pickle
    ("nosqli", r"[\[{\"',]\s*\$(?:ne|gt|gte|lt|lte|in|nin|regex|where|exists|expr|or|and|not)\b", "named"),
    ("nosqli", r"\$where\s*[\"':]", "named"),
    ("nosqli", r"['\"]\s*;\s*return\s+(?:true|1)\b", "named"),
    ("ldap", r"\*\s*\)\s*\(\s*[\w-]+\s*=", "named"),
    ("ldap", r"\)\s*\(\s*[|&!]\s*(?:\(|\))", "named"),
    ("ldap", r"\(\s*[|&]\s*\(\s*[\w-]+\s*=\s*\*", "named"),
    ("crlf", r"[\r\n]+\s*(?:set-cookie|location|content-(?:length|type)|refresh|x-[\w-]+|access-control-[\w-]+"
             r"|transfer-encoding)\s*:", "rawonly"),
    ("rfi", r"^\s*(?:https?|ftp)://[^?#\s]+\.(?:php\d?|phtml|txt|asp|aspx|jsp|inc)\??\s*$", "include"),
    ("rfi", r"^\s*(?:https?|ftp)://\S+\?\s*$", "include"),
    ("rfi", r"^\s*\\\\[\w.-]+\\", "include"),
    ("redirect", r"^\s*/\s*[/\\]+\s*[^/\\\s]", "redirect"),                       # //evil, /\evil
    ("redirect", r"^\s*\\\\[^\\\s]", "redirect"),
    ("redirect", r"^\s*https?:\s*\\", "redirect"),
    ("redirect", r"^\s*https?:(?!/)\S", "redirect"),                              # https:evil
    ("redirect", r"^\s*https?://[^/?#]*@", "redirect"),                          # https://trusted@evil
]
RULES_T1 = [(c, re.compile(p, re.I), sc) for c, p, sc in _RULES]
RULES = {}                                   # dạng cũ {lớp: [mẫu]} — giữ cho mã/kiểm thử đọc danh sách luật
for _c, _p, _sc in RULES_T1: RULES.setdefault(_c, []).append(_p)
WS = re.compile(r"\s+")     # gộp khoảng trắng trước khi so khớp: SQL/shell không phân biệt số khoảng trắng, và
                            # tránh chuỗi rất dài làm regex quay lui O(n²)
# Tên tham số / cookie chứa dữ liệu nhạy cảm: giá trị được CHE trước khi lưu (vẫn được quét đầy đủ).
SENSITIVE = re.compile(r"pass|pwd|secret|token|api[_-]?key|auth|sess|sid$|csrf|xsrf|card|ccnum|cc_num|cvv|cvc"
                       r"|ssn|otp|^pin$|private|credential", re.I)
REDACTED = "[redacted]"
RECON = re.compile(r"/(phpmyadmin|pma|wp-admin|wp-login\.php|xmlrpc\.php|\.env|\.git/|actuator|cgi-bin/"
                   r"|server-status|manager/html|vendor/phpunit)", re.I)
SCANNER_UA = re.compile(r"(sqlmap|nikto|nmap|masscan|acunetix|dirbuster|gobuster|wfuzz|nuclei|zgrab|hydra)", re.I)
# Cổng cú pháp cho tầng 2: payload tấn công luôn cần ít nhất một ký tự/cụm trong tập này.
META = re.compile(r"""['"<>()=;|`$*\\{}#&%!^~\[\]]|\.\.|--|/\*""")
PLAIN_NAME = re.compile(r"^[\w.\-\[\]]{0,64}$")
SEV_CONF = {1: 0.95, 2: 0.8, 3: 0.6}
ET_CONF = {"critical": 0.95, "major": 0.85, "minor": 0.6}

MODEL = None
if os.path.exists(MODEL_PATH):
    import joblib
    from scipy.sparse import hstack, csr_matrix
    from feats import make_text, make_feats, NUM
    MODEL = joblib.load(MODEL_PATH)
    _clf = MODEL["clf"]; _vec = MODEL["vectorizer"]; _cols = MODEL.get("num_cols", NUM)
    _classes = [str(c) for c in _clf.classes_]
    _benign_i = _classes.index("benign") if "benign" in _classes else -1
    try: _names = _vec.get_feature_names_out()
    except Exception: _names = None
    L.info("tier2 model loaded: %s | decision=%s θ=%.2f gate=%s", _classes, T2_DECISION, T2_THRESHOLD, T2_GATE)
else:
    L.info("no tier2 model — tier 1 only")

def _ngram_evidence(xt, cls_i, k=5):
    """Các n-gram ký tự đóng góp nhiều nhất cho lớp được chọn — bằng chứng của quyết định tầng 2."""
    if _names is None or xt.nnz == 0 or _clf.coef_.shape[0] <= cls_i: return []
    coo = xt.tocoo(); w = coo.data * _clf.coef_[cls_i, coo.col]
    top = sorted(range(len(w)), key=lambda i: -w[i])[:k]
    return [str(_names[coo.col[i]]).strip() for i in top if w[i] > 0 and str(_names[coo.col[i]]).strip()]

def tier2(ev, gate_text=None):
    """Tầng 2 run_4: _text (values_only+normalize) + 21 f_* từ ev thô, hstack rồi dự đoán.
    KHỚP train_tier2 — truyền query/body THÔ như lúc huấn luyện. Trả (lớp, điểm, [n-gram]) hoặc None."""
    if MODEL is None: return None
    if T2_GATE and gate_text is not None and not META.search(gate_text): return None
    text = make_text(ev.get("query"), ev.get("body"))
    row = make_feats(ev.get("uri") or "", ev.get("query"), ev.get("body"))
    xt = _vec.transform([text])
    X = hstack([xt, csr_matrix([[float(row[c]) for c in _cols]])]).tocsr()
    proba = _clf.predict_proba(X)[0]
    attack = [i for i in range(len(_classes)) if i != _benign_i]
    top = max(attack, key=lambda i: proba[i])
    if T2_DECISION == "mass":
        score = 1.0 - (float(proba[_benign_i]) if _benign_i >= 0 else 0.0)
    else:
        score = float(proba[top]) if int(proba.argmax()) == top else 0.0
    if score < T2_THRESHOLD: return None
    return _classes[top], score, _ngram_evidence(xt, top)

def decode_p(s, n=3):
    """Giải mã %xx của ĐƯỜNG DẪN (không đổi '+')."""
    for _ in range(n):
        d = unquote(s)
        if d == s: break
        s = d
    return s

def decode_q(s):
    """Giải mã giá trị form: lần đầu '+' -> dấu cách, các lần sau chỉ %xx (bắt mã hoá kép
    mà không biến dấu '+' thật — vd 'c++' — thành dấu cách ở lần hai)."""
    return decode_p(unquote_plus(s), 2)

def split_params(raw):
    """'a=1&b=%27x' -> [('a','1'), ('b',\"'x\")] (đã giải mã, chữ thường). Phần không có '=' coi là giá trị."""
    out = []
    for part in (raw or "").split("&"):
        if not part: continue
        n, sep, v = part.partition("=")
        if not sep: n, v = "", part
        out.append((decode_q(n).lower()[:256], decode_q(v).lower()))     # KHÔNG cắt giá trị (xem SCAN_MAX_BYTES)
    return out

def body_params(body):
    b = (body or "").strip()
    if not b or b == "-": return []
    if is_structured(b):                             # JSON / XML / multipart: cả thân là một giá trị
        return [("", b.lower())]
    return split_params(b)

def multipart_text_values(body):
    """Nội dung các trường VĂN BẢN của một thân multipart (bỏ phần đầu của từng phần và các phần tệp)."""
    b = (body or "").lstrip()
    boundary = b.split("\n", 1)[0].strip()
    if not boundary.startswith("--") or len(boundary) < 3:
        return [b]
    out = []
    for part in b.split(boundary)[1:]:
        part = part.lstrip("\r\n")
        if not part or part.startswith("--"):            # phần kết thúc "--boundary--"
            continue
        sep = min((i for i in (part.find("\r\n\r\n"), part.find("\n\n")) if i >= 0), default=-1)
        if sep < 0:
            continue
        head, content = part[:sep], part[sep:].strip("\r\n")
        if "filename=" in head:
            continue
        out.append(content)
    return out

def is_structured(b):
    b = (b or "").lstrip()
    return bool(b) and (b[0] in "{[<" or b.startswith("--"))

def cookie_params(raw):
    """'a=1; b=2' -> [('a','1'), ('b','2')] (giải mã %xx, chữ thường)."""
    out = []
    for part in (raw or "").split(";"):
        part = part.strip()
        if not part or part == "-": continue
        n, _, v = part.partition("=")
        out.append((decode_p(n, 1).lower()[:256], decode_p(v, 2).lower()))
    return out

def scan_units(path, qargs, bargs, headers=None, limits=None):
    """Danh sách (tên biến kiểu ModSecurity, văn bản) để tầng 1 so khớp.
    headers: {'User-Agent': ..., 'Referer': ..., 'cookies': [(tên, giá trị)]}.
    limits (dict, tuỳ chọn) nhận khoá 'over' = lý do khi vượt trần tham số ('params') hoặc byte ('bytes')."""
    units = [("REQUEST_FILENAME", WS.sub(" ", path))]
    st = {"budget": SCAN_MAX_BYTES, "over": None}
    def add(field, text):
        if not text: return
        if len(text) > st["budget"]:
            st["over"] = st["over"] or "bytes"
            text = text[:max(st["budget"], 0)]
        st["budget"] -= len(text)
        if text: units.append((field, WS.sub(" ", text)))
    # header + cookie TRƯỚC (ngắn): đệm tham số không đẩy được chúng ra khỏi vùng quét
    h = headers or {}
    for name in ("User-Agent", "Referer"):
        v = h.get(name)
        if v and v != "-":
            add(f"REQUEST_HEADERS:{name}", decode_q(v).lower() if name == "Referer" else decode_p(v, 2).lower())
    for n, v in h.get("cookies") or []:
        add(f"REQUEST_COOKIES:{n}", v)
        if n and not PLAIN_NAME.match(n): add("REQUEST_COOKIES_NAMES", n)
    nparams = 0
    for src, args in (("ARGS_GET", qargs), ("ARGS_POST", bargs)):
        for n, v in args:
            nparams += 1
            if nparams > MAX_PARAMS:
                st["over"] = st["over"] or "params"; break
            add(f"{src}:{n}" if n else src, v)
            if n and not PLAIN_NAME.match(n):         # tên tham số 'lạ' có thể chính là payload
                add(f"{src}_NAMES", n)
            # bản CHƯA gộp khoảng trắng cho luật cần dấu xuống dòng; cả thân JSON/XML (một giá trị không tên): không soi
            # bản thô — xuống dòng ở đó chỉ là định dạng
            if v and ("\r" in v or "\n" in v) and not (not n and v.lstrip()[:1] in ("{", "[", "<")):
                field = f"RAW:{src}:{n}" if n else f"RAW:{src}"
                # thân multipart: phần đầu của từng phần (Content-Disposition / Content-Type) LUÔN có xuống dòng
                # -> chỉ soi NỘI DUNG các trường văn bản; phần tệp (filename=) không phải ARGS (ModSecurity cũng
                # tách FILES riêng). Trước đây luật CRLF gắn nhãn 46 % lần tải tệp hợp lệ của website thật.
                for raw in (multipart_text_values(v) if not n and v.lstrip().startswith("--") else [v]):
                    if "\r" in raw or "\n" in raw:
                        units.append((field, raw[:max(st["budget"], 0) + len(raw)]))
    if limits is not None and st["over"]: limits["over"] = st["over"]
    return units

def entropy(s):
    if not s: return 0.0
    c = Counter(s); return -sum(v/len(s)*math.log2(v/len(s)) for v in c.values())

def is_internal(ip):
    try: a = ipaddress.ip_address(ip)
    except (ValueError, TypeError): return True
    return any(a in n for n in INTERNAL)

def classify(path, qargs, bargs, ua, ev, headers=None):
    """-> dict(label, conf, tier, rule, field, evidence[, t2_label, t2_conf, t2_evidence]).
    field/evidence = bằng chứng (trường + chuỗi khớp)."""
    hdr = dict(headers or {}); hdr.setdefault("User-Agent", ua)
    limits = {}
    units = scan_units(path, qargs, bargs, hdr, limits)
    if ev.get("body_truncated"): limits.setdefault("over", "body_truncated")
    r = _tier1(units, path, ua, int(ev.get("status") or 0))
    if r: return r
    # tầng 2 chỉ xét tham số (không xét header/cookie); thân JSON/XML/multipart chỉ khi bật TIER2_STRUCTURED_BODY
    structured = len(bargs) == 1 and not bargs[0][0] and is_structured(bargs[0][1])
    gate_units = [t for f, t in units if f.startswith(("ARGS_GET", "ARGS_POST"))
                  and (T2_STRUCTURED or not (structured and f == "ARGS_POST"))]
    t2 = tier2(ev, " ".join(gate_units)) if gate_units else None
    out = {"label": "benign", "conf": 0.0, "tier": None, "rule": None, "field": None, "evidence": None}
    if t2:
        corroborated = bool(ev.get("_waf_blocked"))
        if T2_MODE == "enforce" or (T2_MODE in ("corroborate", "weighted") and corroborated) or T2_MODE == "weighted":
            out = {"label": t2[0], "conf": t2_confidence(t2[1]), "tier": 2, "rule": "model", "field": "ARGS",
                   "evidence": " | ".join(t2[2])[:120], "t2_conf": round(t2[1], 4)}
            if T2_MODE == "weighted" and not corroborated:
                out["weighted"] = True
        else:
            out.update(t2_label=t2[0], t2_conf=round(t2[1], 4), t2_evidence=" | ".join(t2[2])[:120])
    if out["label"] == "benign" and limits.get("over"):
        out.update(label="uninspected", conf=UNINSPECTED_CONF, tier=1, rule="scan_limit",
                   field=limits["over"], evidence=None)
    return out

def _arg_name(field):
    """'ARGS_GET:next' -> 'next'; '' nếu không phải tham số có tên."""
    if field.startswith(("ARGS_GET:", "ARGS_POST:")): return field.split(":", 1)[1]
    return ""

def _in_scope(scope, field):
    """-> None (không áp), hoặc độ tin cậy tối đa cho đơn vị này."""
    raw = field.startswith("RAW:")
    if scope == "rawonly": return 0.9 if raw else None
    if raw: return 0.9 if scope == "raw" else None
    if scope == "any": return 0.9
    if field == "REQUEST_FILENAME": return None
    if scope in ("nopath", "raw"): return 0.9
    if scope == "named":
        return BODY_LOW_CONF if field == "ARGS_POST" else 0.9     # cả thân JSON/XML: chỉ ghi nhận
    name = _arg_name(field)
    if scope == "redirect": return REDIRECT_CONF if REDIRECT_PARAMS.match(name) else None
    if scope == "include": return 0.9 if INCLUDE_PARAMS.match(name) else None
    return None

def _tier1(units, path, ua, status=0):
    """Luật đầu tiên khớp với độ tin cậy 0,9 thắng ngay; luật chỉ-ghi-nhận (Referer, open redirect, NoSQLi/LDAP trong cả
    thân JSON) không chặn đường của một luật mạnh hơn khớp ở chỗ khác trong cùng request."""
    weak = None
    for cls, p, scope in RULES_T1:
        for field, text in units:
            cap = _in_scope(scope, field)
            if cap is None: continue
            m = p.search(text)
            if not m: continue
            # Referer: nạn nhân bấm một liên kết XSS phản xạ sẽ mang payload trong Referer ở MỌI request sau
            # đó (kể cả css/js/ảnh) -> chỉ ghi nhận (độ tin cậy dưới θ), không để nạn nhân bị chặn.
            conf = min(cap, REFERER_CONF) if field == "REQUEST_HEADERS:Referer" else cap
            r = {"label": cls, "conf": conf, "tier": 1, "rule": p.pattern[:200], "field": field.replace("RAW:", ""),
                 "evidence": m.group(0)[:120]}
            if conf >= 0.9: return r
            if weak is None: weak = r
            break
    m = RECON.search(path)
    if m:
        # công cụ quét dò tài nguyên KHÔNG tồn tại (404/403...). Trang có thật (2xx/3xx: /wp-admin/admin-ajax.php của
        # site WordPress, ảnh theo dõi trong /cgi-bin/) chỉ được ghi nhận, không tính vào ngưỡng chặn. Chưa biết mã -> 0,9.
        conf = RECON_FOUND_CONF if 200 <= status < 400 else 0.9
        r = {"label": "recon", "conf": conf, "tier": 1, "rule": RECON.pattern[:80], "field": "REQUEST_FILENAME",
             "evidence": m.group(0)[:120]}
        if conf >= 0.9: return r
        if weak is None: weak = r                     # vẫn xét User-Agent công cụ quét phía dưới
    if SCANNER_UA.search(ua or ""):
        return {"label": "scanner", "conf": 0.9, "tier": 1, "rule": "scanner_ua",
                "field": "REQUEST_HEADERS:User-Agent", "evidence": (ua or "")[:120]}
    return weak

_SENS = r"[^=&;\s\"]*(?:pass|pwd|secret|token|api[_-]?key|auth|sess|csrf|xsrf|card|ccnum|cc_num|cvv|cvc|ssn|otp|private|credential)[^=&;\s\"]*"
_RED_FORM = re.compile(r"(?i)((?:^|[&?])" + _SENS + r"=)[^&]*")
_RED_JSON = re.compile(r'(?i)("' + _SENS + r'"\s*:\s*)("(?:[^"\\]|\\.)*"|[^,}\]\s]+)')
_RED_XML = re.compile(r"(?i)<(" + _SENS + r")(\s[^>]*)?>[^<]*</\1\s*>")
_RED_MULTI = re.compile(r'(?is)(name="' + _SENS + r'"[^\r\n]*\r?\n(?:[^\r\n]+\r?\n)*\r?\n).*?(?=\r?\n--)')

def redact_text(t):
    """Che giá trị của tham số nhạy cảm trong chuỗi query / thân form / JSON / XML / multipart (C1)."""
    if not t: return t
    t = _RED_FORM.sub(lambda m: m.group(1) + REDACTED, t)
    t = _RED_JSON.sub(lambda m: m.group(1) + '"' + REDACTED + '"', t)
    t = _RED_XML.sub(lambda m: f"<{m.group(1)}{m.group(2) or ''}>{REDACTED}</{m.group(1)}>", t)
    t = _RED_MULTI.sub(lambda m: m.group(1) + REDACTED, t)
    return t

def redact_pairs(pairs):
    return [(n, REDACTED if n and SENSITIVE.search(n) else v) for n, v in pairs]

# Thời gian lưu (quyết định 15/11/2026): sự kiện request giữ 30 ngày, sự kiện TẤN CÔNG giữ 1 năm. Chính sách vòng đời của
# Elasticsearch đặt theo chỉ mục, nên sự kiện có nhãn tấn công được ghi THÊM một bản vào attack-events-* (lưu dài).
# web-events-* vẫn có đủ mọi sự kiện như trước -> Grafana, rulegen và các công cụ đo không phải đổi gì.
ATTACK_ARCHIVE = os.getenv("ATTACK_ARCHIVE", "1") != "0"
NOT_ATTACK = {"benign", "info", None}

def store_event(buf, ts, doc):
    buf.add(day_index("web-events", ts), doc)
    if ATTACK_ARCHIVE and doc.get("label") not in NOT_ATTACK:
        buf.add(day_index("attack-events", ts), doc)

def emit_alert(p, a):
    p.produce("alerts", key=a["src_ip"].encode(), value=json.dumps(a).encode())

# ---- ghép body từ ModSec audit (web.audit) theo req_id ----
# Nhật ký truy cập apache KHÔNG có body; ModSec audit JSON có (Apache được cấu hình ghi audit
# cho mọi request có thân — xem web/apache/zz-autogen.conf). Cache body theo unique_id; request
# có thân đến trước audit thì tạm GIỮ (pending) tối đa PENDING_WAIT giây rồi mới phân loại.
ES_BUF = None; PROD = None
BODY_CACHE = {}      # req_id -> (ts, body, intercepted, truncated)
PENDING = {}         # req_id -> (ts, ev)
BODY_CACHE_MAX = int(os.getenv("BODY_CACHE_MAX", "20000"))
PENDING_MAX = int(os.getenv("PENDING_MAX", "20000"))
DROPPED = {"pending": 0, "body_cache": 0}
BODY_TTL = float(os.getenv("BODY_TTL_S", "180"))
PENDING_WAIT = float(os.getenv("PENDING_WAIT_S", "15"))   # trước là 3 s: khi nhật ký xoay, thân đến muộn hơn thế
# (đã đo). Chờ lâu hơn KHÔNG làm chậm trường hợp thường: có thân là phân loại ngay (xem handle_audit).
BODY_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

def _classify_web(ev, body, intercepted=None, truncated=False):
    ev["body"] = body or ""
    if truncated: ev["body_truncated"] = True
    ts = (ev.get("ts_ms") or time.time()*1000)/1000.0
    path = decode_p(ev.get("uri") or "").lower()
    rawq = (ev.get("query") or "").lstrip("?")
    qargs, bargs = split_params(rawq), body_params(body)
    ua = ev.get("ua", "")
    cookies = cookie_params(ev.get("cookie"))
    headers = {"User-Agent": ua, "Referer": ev.get("referer"), "cookies": cookies}
    status = int(ev.get("status") or 0)
    waf_blocked = bool(intercepted) if intercepted is not None else status == 403
    ev["_waf_blocked"] = waf_blocked
    c = classify(path, qargs, bargs, ua, ev, headers)
    label, conf = c["label"], c["conf"]
    # bản đã CHE dữ liệu nhạy cảm — dùng cho mọi thứ được lưu hoặc gửi đi
    query = decode_q(redact_text(rawq)).lower()
    target = (path + ("?"+query if query else ""))[:2048]
    # 1) PHÁT CẢNH BÁO TRƯỚC — không phụ thuộc Elasticsearch (spec E3)
    if label != "benign" and ev.get("src_ip") and not is_internal(ev["src_ip"]):
        emit_alert(PROD, {"alert_id": str(uuid.uuid4()), "ts": ts, "src_ip": ev["src_ip"], "class": label,
                          "confidence": conf, "tier": c["tier"], "source": "web", "target": target[:512],
                          "status": status, "waf_blocked": waf_blocked, "ua": (ua or "")[:256],
                          "evidence_field": c["field"], "evidence": c["evidence"],
                          **({"weighted": True} if c.get("weighted") else {})})
    # 2) rồi mới đưa bản ghi vào bộ đệm ES (ghi ở luồng nền)
    args = redact_pairs(qargs + bargs)[:50]
    # ARGS đúng như ModSecurity nhìn thấy (giải mã MỘT lần, giữ hoa thường): luật tự sinh được áp lên
    # góc nhìn này, nên bộ sinh luật phải học token từ đây chứ không từ arg_v (đã giải mã nhiều lần, chữ thường)
    ct = ev.get("ct") or ""
    margs, mbody = secrule.modsec_args(rawq, body or "", "" if ct == "-" else ct)
    margs = redact_pairs(margs)
    # KHÔNG cắt còn 50 như arg_*: ModSecurity soi tới SecArgumentsLimit (1000) tham số
    doc = {"@timestamp": iso(ts), "source": "web", "src_ip": ev.get("src_ip"), "method": ev.get("method"),
           "target": target, "status": status, "ua": ua, "label": label, "confidence": conf,
           "tier": c["tier"], "matched": c["rule"], "evidence_field": c["field"], "evidence": c["evidence"],
           "waf_blocked": waf_blocked, "req_id": ev.get("req_id"),
           "has_body": bool(body), "body": decode_q(redact_text(body or "")).lower()[:2048],
           "arg_n": [n for n, _ in args], "arg_v": [v[:512] for _, v in args],   # rulegen trích bất biến từ GIÁ TRỊ
           "marg_n": [n[:64] for n, _ in margs], "marg_v": [v[:2048] for _, v in margs],
           "marg_body": redact_text(mbody) if isinstance(mbody, str) else mbody,
           "cookie_n": [n for n, _ in cookies][:50],                             # chỉ TÊN cookie, không lưu giá trị
           "f_len": len(target), "f_special": sum(not ch.isalnum() for ch in target),
           "f_entropy": round(entropy(target), 3)}
    for k in ("t2_label", "t2_conf", "t2_evidence", "weighted"):
        if k in c: doc[k] = c[k]
    if truncated: doc["body_truncated"] = True
    store_event(ES_BUF, ts, doc)

def handle_web(ev):
    rid = ev.get("req_id"); method = (ev.get("method") or "").upper()
    cached = BODY_CACHE.pop(rid, None) if rid else None
    # Content-Length 0/không có (và không chunked) = chắc chắn không có thân -> phân loại ngay, không chờ
    # nhật ký kiểm toán tới 15 giây (T13). Không dựa vào Content-Type: kẻ tấn công bỏ được header đó.
    cl, te = str(ev.get("cl", "?")), str(ev.get("te") or "-").lower()
    expects_body = not (cl in ("-", "", "0") and "chunked" not in te)
    if method in BODY_METHODS and rid and not cached and not ev.get("body") and expects_body:
        _bounded_put(PENDING, rid, (time.time(), ev), PENDING_MAX, "pending")
        return                                        # chờ body từ audit
    if cached: _classify_web(ev, cached[1], cached[2], cached[3])
    else: _classify_web(ev, ev.get("body") or "")

def _bounded_put(d, k, v, cap, name):
    """Thêm vào dict có trần: đầy thì xử lý/bỏ mục cũ nhất (dict giữ thứ tự chèn) — không phình bộ nhớ vô hạn."""
    d[k] = v
    while len(d) > cap:
        old_k = next(iter(d))
        old = d.pop(old_k)
        DROPPED[name] += 1
        if name == "pending": _classify_web(old[1], "")      # không bỏ request: phân loại không thân

def handle_audit(ev):
    # ModSec JSON audit: id ở transaction.transaction_id/unique_id; body ở request.body
    tx = ev.get("transaction") or {}
    rid = tx.get("unique_id") or tx.get("transaction_id") or tx.get("id")
    if not rid: return
    req = ev.get("request") or tx.get("request") or {}
    body = req.get("body") or ""
    if isinstance(body, (list, tuple)): body = "".join(str(x) for x in body)   # ModSec gói body thành mảng
    action = (ev.get("audit_data") or {}).get("action") or {}
    intercepted = action.get("intercepted") if isinstance(action, dict) else None
    truncated = body_truncated(req.get("headers") or {}, body)
    pend = PENDING.pop(rid, None)
    if pend: _classify_web(pend[1], body, intercepted, truncated)   # có web event đang chờ -> xử ngay
    else: _bounded_put(BODY_CACHE, rid, (time.time(), body, intercepted, truncated), BODY_CACHE_MAX, "body_cache")

def body_truncated(headers, body):
    """ModSecurity 2.9 ghi thân vào nhật ký kiểm toán JSON như chuỗi C: gặp byte 0 là dừng (đã thấy thân gzip
    chỉ còn 3 byte). So với Content-Length để biết thân KHÔNG được soi hết (C7)."""
    cl = next((v for k, v in headers.items() if str(k).lower() == "content-length"), None)
    try: cl = int(cl)
    except (TypeError, ValueError): return False
    if cl <= 0: return False
    try: n = len(body.encode("latin-1"))
    except UnicodeEncodeError: n = len(body.encode("utf-8"))
    ctype = next((str(v).lower() for k, v in headers.items() if str(k).lower() == "content-type"), "")
    if "multipart/" in ctype: return False             # ModSecurity tách phần tệp ra khỏi thân được ghi
    return n * 2 < cl and cl - n > 64

def sweep_join():
    now = time.time()
    for rid in [k for k, (t, _) in list(PENDING.items()) if now - t >= PENDING_WAIT]:
        _, ev = PENDING.pop(rid); _classify_web(ev, "")   # hết hạn chờ -> phân loại không body
    for rid in [k for k, v in list(BODY_CACHE.items()) if now - v[0] >= BODY_TTL]:
        BODY_CACHE.pop(rid, None)

def suricata_class(alert):
    s = f"{alert.get('category','')} {alert.get('signature','')}".lower()
    for key, cls in (("sql", "sqli"), ("xss", "xss"), ("cross site", "xss"), ("traversal", "lfi"),
                     ("file inclusion", "lfi"), ("remote file", "lfi"),
                     ("command injection", "rce"), ("command execution", "rce"), ("code execution", "rce"),
                     ("log4j", "rce"), ("jndi", "rce"), ("shellshock", "rce"), (" rce", "rce"),
                     ("ssrf", "ssrf"), ("server-side request forgery", "ssrf"), ("xxe", "xxe"),
                     ("xml external entit", "xxe"), ("template injection", "ssti"), ("ssti", "ssti"),
                     ("ldap injection", "ldap"), ("nosql", "nosqli"), ("crlf", "crlf"), ("open redirect", "redirect"),
                     ("deserializ", "deser"),
                     ("scan", "scanner"), ("recon", "recon")):
        if key in s: return cls
    return "suricata"

def redact_url(u):
    """'/a/b?token=x&q=1' -> '/a/b?token=[redacted]&q=1' (che query; đường dẫn giữ nguyên)."""
    path, sep, q = (u or "").partition("?")
    return path + (sep + redact_text(q) if sep else "")

def handle_net(ev, es_buf, p):
    et = ev.get("event_type")
    if et not in ("alert", "http", "anomaly"): return
    src, dst = ev.get("src_ip"), ev.get("dest_ip")
    ext = [ip for ip in (src, dst) if ip and not is_internal(ip)]
    if not ext: return
    attacker = ext[0]
    ts = parse_ts(ev.get("timestamp")) or time.time()     # THỜI ĐIỂM SỰ KIỆN (để responder lọc cảnh báo cũ)
    doc = {"@timestamp": iso(ts), "sensor_ts": ev.get("timestamp"), "source": "net", "event_type": et,
           "src_ip": attacker, "label": "benign", "confidence": 0.0}
    if et == "http":
        h = ev.get("http", {})
        # C1: Suricata thấy nguyên URL (HTTP rõ) -> che tham số nhạy cảm trong query như nhánh nhật ký web
        # (kịch bản 29, 13/11: token trong query còn nguyên văn ở các bản ghi source=net)
        doc.update(target=redact_url(h.get("url") or "").lower()[:2048], method=h.get("http_method"),
                   status=h.get("status"), ua=h.get("http_user_agent"))
    elif et == "anomaly":
        an = ev.get("anomaly") or {}
        doc["anomaly"] = an
        # C2: yêu cầu HTTP dị dạng chỉ nhánh bắt gói thấy -> gắn nhãn + phát cảnh báo (độ tin cậy thấp:
        # responder chỉ ghi kiểm toán, không chặn chỉ vì một bất thường giao thức).
        if ev.get("app_proto") == "http" and not is_internal(src):
            doc.update(label="anomaly", confidence=ANOMALY_CONF, tier=0, matched=str(an.get("event") or an.get("type")))
            emit_alert(p, {"alert_id": str(uuid.uuid4()), "ts": ts, "src_ip": attacker, "class": "anomaly",
                           "confidence": ANOMALY_CONF, "tier": 0, "source": "net",
                           "signature": f"anomaly:{an.get('event') or an.get('type')}", "target": ""})
    else:
        a = ev.get("alert", {})
        et_sev = [s.lower() for s in (a.get("metadata") or {}).get("signature_severity", [])]
        informational = "informational" in et_sev or (a.get("signature") or "").startswith("ET INFO")
        response_side = is_internal(src)
        quiet = informational or response_side
        conf = next((ET_CONF[s] for s in et_sev if s in ET_CONF), SEV_CONF.get(a.get("severity"), 0.6))
        cls = "info" if quiet else suricata_class(a)
        doc.update(label=cls, confidence=0.0 if quiet else conf, tier=0, matched=a.get("signature"),
                   signature_id=a.get("signature_id"), direction="to_client" if response_side else "to_server")
        if not quiet:
            emit_alert(p, {"alert_id": str(uuid.uuid4()), "ts": ts, "src_ip": attacker, "class": cls,
                           "confidence": conf, "tier": 0, "source": "net", "signature": a.get("signature"),
                           "target": redact_url((ev.get("http") or {}).get("url") or "")[:512]})
    store_event(es_buf, ts, doc)

def main():
    global ES_BUF, PROD
    install_stop()
    ES_BUF = EsBuffer(es_client(required=False)); PROD = producer()
    c = consumer("classifier", ["web.logs", "net.events", "web.audit"])
    hb = Heartbeat("classifier", ES_BUF)
    t_start = time.time()
    last_seen = {}                      # topic -> lúc nhận sự kiện gần nhất (nguồn nào im lặng = cảm biến/Filebeat hỏng)
    L.info("classifier started (tầng 1 theo giá trị tham số + header; body-join qua web.audit; tầng 2: %s)", T2_MODE)
    last = time.time()
    while running():
        msg = c.poll(0.5)
        if msg is not None and msg.error():
            L.warning("kafka: %s", msg.error())
        elif msg is not None:
            ev = parse_json_line(msg.value()); hb.inc()
            last_seen[msg.topic()] = time.time()
            if isinstance(ev, dict):
                t = msg.topic()
                try:
                    if t == "web.logs": handle_web(ev)
                    elif t == "web.audit": handle_audit(ev)
                    else: handle_net(ev, ES_BUF, PROD)
                except Exception: L.exception("failed on event")
        if time.time() - last >= 1:
            sweep_join(); last = time.time()
            now = time.time()
            ages = {f"age_{k.replace('.', '_')}_s": int(now - last_seen.get(k, t_start))
                    for k in ("web.logs", "net.events", "web.audit")}
            hb.tick(c, pending_body=len(PENDING), body_cache=len(BODY_CACHE), tier2_mode=T2_MODE, **ages,
                    pending_forced=DROPPED["pending"], body_cache_evicted=DROPPED["body_cache"])
        ES_BUF.maybe_flush(); PROD.poll(0)
    L.info("classifier dừng — flush bộ đệm")
    ES_BUF.maybe_flush(force=True); PROD.flush(5); c.close()

if __name__ == "__main__":
    main()
